import crypto from 'node:crypto';

const JSON_HEADERS = { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' };
const POST_FIELDS = 'id,type,event_date,purpose,gender,my_seat,want_seat,body,chat_link,is_done,created_at,updated_at';

function send(res, status, data, extra = {}) {
  res.statusCode = status;
  Object.entries({ ...JSON_HEADERS, ...extra }).forEach(([k, v]) => res.setHeader(k, v));
  res.end(JSON.stringify(data));
}
function fail(res, status, message) { return send(res, status, { error: message }); }
function env(name) {
  const value = process.env[name];
  if (!value) throw new Error(`Missing environment variable: ${name}`);
  return value;
}
function parseBody(req) {
  if (!req.body) return {};
  if (typeof req.body === 'object') return req.body;
  try { return JSON.parse(req.body); } catch { return {}; }
}
function routeParts(req) {
  const requestUrl = new URL(req.url || '/', 'http://localhost');
  const raw =
    req.query?.apiPath ??
    req.query?.route ??
    requestUrl.searchParams.get('apiPath');

  if (raw) {
    return (Array.isArray(raw) ? raw : String(raw).split('/')).filter(Boolean);
  }

  return requestUrl.pathname
    .replace(/^\/api\/?/, '')
    .split('/')
    .filter(Boolean);
}
function method(req, expected) { return req.method === expected; }
function clean(value, max = 1000) { return String(value ?? '').trim().slice(0, max); }
function safeEqual(a, b) {
  const aa = crypto.createHash('sha256').update(String(a)).digest();
  const bb = crypto.createHash('sha256').update(String(b)).digest();
  return crypto.timingSafeEqual(aa, bb);
}
function b64url(data) { return Buffer.from(data).toString('base64url'); }
function sign(payload, secret = env('SESSION_SECRET')) {
  const body = b64url(JSON.stringify(payload));
  const sig = crypto.createHmac('sha256', secret).update(body).digest('base64url');
  return `${body}.${sig}`;
}
function verifySigned(token, secret = env('SESSION_SECRET')) {
  if (!token || !token.includes('.')) return null;
  const [body, sig] = token.split('.');
  const expected = crypto.createHmac('sha256', secret).update(body).digest('base64url');
  if (!safeEqual(sig, expected)) return null;
  try {
    const payload = JSON.parse(Buffer.from(body, 'base64url').toString());
    return payload.exp > Date.now() ? payload : null;
  } catch { return null; }
}
function cookies(req) {
  return Object.fromEntries(String(req.headers.cookie || '').split(';').map(v => v.trim().split('=').map(decodeURIComponent)).filter(v => v[0]));
}
function bearer(req) {
  const value = String(req.headers.authorization || '');
  return value.startsWith('Bearer ') ? value.slice(7) : '';
}
function clientIp(req) {
  return String(req.headers['x-forwarded-for'] || req.socket?.remoteAddress || '').split(',')[0].trim();
}
function ipHash(req) {
  return crypto.createHmac('sha256', env('RATE_LIMIT_SECRET')).update(clientIp(req)).digest('hex');
}
function normalizedPostFingerprint(post) {
  const normalized = [
    post.type, post.event_date, post.purpose, post.gender, post.my_seat, post.want_seat,
    post.body, post.chat_link
  ].map(value => String(value ?? '').normalize('NFKC').toLowerCase().replace(/\s+/g, ' ').trim()).join('|');
  return crypto.createHmac('sha256', env('RATE_LIMIT_SECRET')).update(normalized).digest('hex');
}
function seoulDayBucket() {
  return new Intl.DateTimeFormat('en-CA', { timeZone: 'Asia/Seoul', year: 'numeric', month: '2-digit', day: '2-digit' }).format(new Date());
}
function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
  return `${salt}:${crypto.scryptSync(password, salt, 64).toString('hex')}`;
}
function passwordMatches(password, stored) {
  const [salt, key] = String(stored || '').split(':');
  if (!salt || !key) return false;
  return safeEqual(crypto.scryptSync(password, salt, 64).toString('hex'), key);
}
function isUuid(v) { return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(v); }
function isChatLink(v) {
  try { const u = new URL(v); return u.protocol === 'https:' && u.hostname === 'open.kakao.com'; } catch { return false; }
}

async function db(path, { method: m = 'GET', body, prefer } = {}) {
  const response = await fetch(`${env('SUPABASE_URL')}/rest/v1/${path}`, {
    method: m,
    headers: {
      apikey: env('SUPABASE_SERVICE_ROLE_KEY'),
      Authorization: `Bearer ${env('SUPABASE_SERVICE_ROLE_KEY')}`,
      'Content-Type': 'application/json',
      ...(prefer ? { Prefer: prefer } : {})
    },
    body: body === undefined ? undefined : JSON.stringify(body)
  });
  const text = await response.text();
  const data = text ? JSON.parse(text) : null;
  if (!response.ok) throw new Error(data?.message || data?.hint || `Database error ${response.status}`);
  return data;
}
async function verifyTurnstile(token, req) {
  if (!token) return false;
  const form = new URLSearchParams({ secret: env('TURNSTILE_SECRET_KEY'), response: token, remoteip: clientIp(req) });
  const response = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', { method: 'POST', body: form });
  const result = await response.json();
  return result.success === true;
}
async function rateLimit(req, action, max, windowSeconds) {
  const result = await db('rpc/consume_rate_limit', {
    method: 'POST',
    body: { p_key: `${action}:${ipHash(req)}`, p_limit: max, p_window_seconds: windowSeconds }
  });
  return result === true;
}
async function requireHuman(req, res, action, max, windowSeconds) {
  const body = parseBody(req);

  if (!(await verifyTurnstile(body.turnstileToken, req))) {
    fail(res, 400, '보안 인증에 실패했습니다. 새로고침 후 다시 시도해주세요.');
    return null;
  }

  if (!(await rateLimit(req, action, max, windowSeconds))) {
    fail(res, 429, '요청이 너무 많습니다. 잠시 후 다시 시도해주세요.');
    return null;
  }

  return body;
}
function publicPost(row) {
  return {
    id: row.id, type: row.type, date: row.event_date, purpose: row.purpose, gender: row.gender,
    mySeat: row.my_seat, wantSeat: row.want_seat, text: row.body, link: row.chat_link,
    done: row.is_done, created: row.created_at, updated: row.updated_at
  };
}
function validatePost(body, partial = false) {
  const type = clean(body.type, 20);
  const result = {};
  if (!partial || body.type !== undefined) {
    if (!['swap', 'companion'].includes(type)) throw new Error('올바른 게시글 종류를 선택해주세요.');
    result.type = type;
  }
  const effectiveType = type || body.currentType;
  const date = clean(body.date, 20);
  const text = clean(body.text, 1500);
  const link = clean(body.link, 300);
  if (!partial || body.date !== undefined) { if (!date) throw new Error('공연 날짜를 입력해주세요.'); result.event_date = date; }
  if (!partial || body.text !== undefined) { if (text.length < 5) throw new Error('내용을 5자 이상 입력해주세요.'); result.body = text; }
  if (!partial || body.link !== undefined) { if (!isChatLink(link)) throw new Error('올바른 카카오 오픈채팅 링크를 입력해주세요.'); result.chat_link = link; }
  if (effectiveType === 'swap') {
    const my = clean(body.mySeat, 80), want = clean(body.wantSeat, 80);
    if (!partial || body.mySeat !== undefined) { if (!my) throw new Error('본인 자리를 입력해주세요.'); result.my_seat = my; }
    if (!partial || body.wantSeat !== undefined) { if (!want) throw new Error('원하는 자리를 입력해주세요.'); result.want_seat = want; }
    result.purpose = null; result.gender = null;
  } else if (effectiveType === 'companion') {
    const purpose = clean(body.purpose, 30), gender = clean(body.gender, 20);
    if (!['공연 동행', '택시팟', '기타'].includes(purpose)) throw new Error('동행 목적을 선택해주세요.');
    if (!['여성', '남성', '선택 안 함'].includes(gender)) throw new Error('성별 항목을 확인해주세요.');
    result.purpose = purpose; result.gender = gender; result.my_seat = null; result.want_seat = null;
  }
  return result;
}
function admin(req) { return verifySigned(cookies(req).admin_session)?.role === 'admin'; }
async function owner(req, postId) {
  const payload = verifySigned(bearer(req));
  return payload?.kind === 'owner' && payload.postId === postId;
}

async function listPosts(res, isAdmin = false) {
  const filter = isAdmin ? '' : '&is_deleted=eq.false&is_hidden=eq.false';
  const rows = await db(`posts?select=${POST_FIELDS},is_hidden,is_deleted&order=created_at.desc${filter}`);
  send(res, 200, { posts: rows.map(r => ({ ...publicPost(r), hidden: r.is_hidden, deleted: r.is_deleted })) });
}
async function createPost(req, res) {
  const body = await requireHuman(req, res, 'create-post', 3, 900); if (!body) return;
  const password = clean(body.password, 100);
  if (password.length < 4) return fail(res, 400, '비밀번호를 4자 이상 입력해주세요.');
  const post = validatePost(body);
  let rows;
  try {
    rows = await db('posts?select=' + POST_FIELDS, {
      method: 'POST', prefer: 'return=representation',
      body: {
        ...post,
        password_hash: hashPassword(password),
        author_ip_hash: ipHash(req),
        content_hash: normalizedPostFingerprint(post),
        duplicate_bucket: seoulDayBucket()
      }
    });
  } catch (error) {
    if (/duplicate|unique|posts_daily_duplicate/i.test(error.message)) {
      return fail(res, 409, '오늘 이미 같은 내용으로 등록한 게시글이 있습니다. 기존 글을 확인해주세요.');
    }
    throw error;
  }
  send(res, 201, { post: publicPost(rows[0]) });
}
async function unlockPost(req, res, id) {
  const body = await requireHuman(req, res, 'unlock-post', 10, 900); if (!body) return;
  const rows = await db(`posts?id=eq.${id}&is_deleted=eq.false&select=id,password_hash`);
  if (!rows[0] || !passwordMatches(clean(body.password, 100), rows[0].password_hash)) return fail(res, 403, '비밀번호가 일치하지 않습니다.');
  send(res, 200, { ownerToken: sign({ kind: 'owner', postId: id, exp: Date.now() + 15 * 60 * 1000 }) });
}
async function updatePost(req, res, id) {
  if (!(await owner(req, id)) && !admin(req)) return fail(res, 403, '수정 권한이 없습니다.');
  const body = parseBody(req);
  const current = await db(`posts?id=eq.${id}&is_deleted=eq.false&select=type`);
  if (!current[0]) return fail(res, 404, '게시글을 찾을 수 없습니다.');
  let patch = {};
  if (body.done !== undefined) patch.is_done = Boolean(body.done);
  if (body.post) patch = { ...patch, ...validatePost({ ...body.post, currentType: current[0].type }, true) };
  if (!Object.keys(patch).length) return fail(res, 400, '변경할 내용이 없습니다.');
  const rows = await db(`posts?id=eq.${id}&select=${POST_FIELDS}`, { method: 'PATCH', prefer: 'return=representation', body: patch });
  send(res, 200, { post: publicPost(rows[0]) });
}
async function deletePost(req, res, id) {
  if (!(await owner(req, id)) && !admin(req)) return fail(res, 403, '삭제 권한이 없습니다.');
  await db(`posts?id=eq.${id}`, { method: 'PATCH', body: { is_deleted: true, deleted_at: new Date().toISOString() } });
  send(res, 200, { ok: true });
}
async function createReport(req, res) {
  const body = await requireHuman(req, res, 'report-post', 5, 3600); if (!body) return;
  const postId = clean(body.postId, 50), reason = clean(body.reason, 40), detail = clean(body.detail, 500);
  if (!isUuid(postId)) return fail(res, 400, '게시글 정보가 올바르지 않습니다.');
  if (!['거래 금지 위반', '도배/광고', '욕설/부적절한 내용', '오픈채팅 링크 문제', '기타'].includes(reason)) return fail(res, 400, '신고 사유를 선택해주세요.');
  const target = await db(`posts?id=eq.${postId}&is_deleted=eq.false&select=id`);
  if (!target[0]) return fail(res, 404, '신고할 게시글을 찾을 수 없습니다.');
  try {
    await db('reports', { method: 'POST', body: { post_id: postId, reason, detail, reporter_ip_hash: ipHash(req) } });
  } catch (e) {
    if (/duplicate|unique/i.test(e.message)) return fail(res, 409, '이미 신고가 접수된 게시글입니다.');
    throw e;
  }
  send(res, 201, { ok: true });
}
async function adminLogin(req, res) {
  const body = await requireHuman(req, res, 'admin-login', 5, 900); if (!body) return;
  if (!safeEqual(clean(body.password, 200), env('ADMIN_CODE'))) return fail(res, 403, '관리자 코드가 일치하지 않습니다.');
  const token = sign({ role: 'admin', exp: Date.now() + 8 * 60 * 60 * 1000 });
  send(res, 200, { ok: true }, { 'Set-Cookie': `admin_session=${encodeURIComponent(token)}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=28800` });
}
async function adminReports(res) {
  const rows = await db('reports?select=id,post_id,reason,detail,status,admin_note,created_at,resolved_at,posts(id,type,event_date,body,is_hidden,is_deleted)&order=created_at.desc');
  send(res, 200, { reports: rows });
}
async function moderatePost(req, res, id) {
  const body = parseBody(req), action = clean(body.action, 20);
  const patch = action === 'hide' ? { is_hidden: true } : action === 'show' ? { is_hidden: false } : action === 'delete' ? { is_deleted: true, deleted_at: new Date().toISOString() } : action === 'restore' ? { is_deleted: false, deleted_at: null } : null;
  if (!patch) return fail(res, 400, '올바른 관리 작업이 아닙니다.');
  await db(`posts?id=eq.${id}`, { method: 'PATCH', body: patch });
  send(res, 200, { ok: true });
}
async function resolveReport(req, res, id) {
  const body = parseBody(req), status = clean(body.status, 20);
  if (!['resolved', 'dismissed'].includes(status)) return fail(res, 400, '처리 상태가 올바르지 않습니다.');
  await db(`reports?id=eq.${id}`, { method: 'PATCH', body: { status, admin_note: clean(body.note, 500), resolved_at: new Date().toISOString() } });
  send(res, 200, { ok: true });
}

export default async function handler(req, res) {
  try {
    const p = routeParts(req);
    if (p[0] === 'config' && method(req, 'GET')) return send(res, 200, { turnstileSiteKey: env('TURNSTILE_SITE_KEY') });
    if (p[0] === 'posts' && p.length === 1 && method(req, 'GET')) return listPosts(res);
    if (p[0] === 'posts' && p.length === 1 && method(req, 'POST')) return createPost(req, res);
    if (p[0] === 'posts' && isUuid(p[1]) && p[2] === 'unlock' && method(req, 'POST')) return unlockPost(req, res, p[1]);
    if (p[0] === 'posts' && isUuid(p[1]) && method(req, 'PATCH')) return updatePost(req, res, p[1]);
    if (p[0] === 'posts' && isUuid(p[1]) && method(req, 'DELETE')) return deletePost(req, res, p[1]);
    if (p[0] === 'reports' && p.length === 1 && method(req, 'POST')) return createReport(req, res);
    if (p[0] === 'admin' && p[1] === 'login' && method(req, 'POST')) return adminLogin(req, res);
    if (p[0] === 'admin' && p[1] === 'logout' && method(req, 'POST')) return send(res, 200, { ok: true }, { 'Set-Cookie': 'admin_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0' });
    if (p[0] === 'admin' && p[1] === 'me' && method(req, 'GET')) return send(res, admin(req) ? 200 : 401, { authenticated: admin(req) });
    if (p[0] === 'admin') {
      if (!admin(req)) return fail(res, 401, '관리자 로그인이 필요합니다.');
      if (p[1] === 'posts' && p.length === 2 && method(req, 'GET')) return listPosts(res, true);
      if (p[1] === 'posts' && isUuid(p[2]) && method(req, 'PATCH')) return moderatePost(req, res, p[2]);
      if (p[1] === 'reports' && p.length === 2 && method(req, 'GET')) return adminReports(res);
      if (p[1] === 'reports' && isUuid(p[2]) && method(req, 'PATCH')) return resolveReport(req, res, p[2]);
    }
    return fail(res, 404, '요청한 기능을 찾을 수 없습니다.');
  } catch (error) {
    console.error(error);
    return fail(res, 500, '서버 처리 중 오류가 발생했습니다.');
  }
}
