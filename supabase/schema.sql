begin;

create extension if not exists pgcrypto;

create table if not exists public.posts (
  id uuid primary key default gen_random_uuid(),
  type text not null check (type in ('swap', 'companion')),
  event_date text not null check (char_length(event_date) between 1 and 20),
  purpose text check (purpose in ('공연 동행', '택시팟', '기타')),
  gender text check (gender in ('여성', '남성', '선택 안 함')),
  my_seat text check (char_length(my_seat) <= 80),
  want_seat text check (char_length(want_seat) <= 80),
  body text not null check (char_length(body) between 5 and 1500),
  chat_link text not null check (chat_link ~ '^https://open\\.kakao\\.com/'),
  password_hash text not null,
  author_ip_hash text not null,
  content_hash text not null,
  duplicate_bucket date not null default ((now() at time zone 'Asia/Seoul')::date),
  is_done boolean not null default false,
  is_hidden boolean not null default false,
  is_deleted boolean not null default false,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  deleted_at timestamptz,
  constraint post_fields_by_type check (
    (type = 'swap' and my_seat is not null and want_seat is not null and purpose is null and gender is null)
    or
    (type = 'companion' and purpose is not null and gender is not null and my_seat is null and want_seat is null)
  )
);

-- 이전 버전 스키마에 재실행해도 중복글 차단 컬럼을 안전하게 추가합니다.
alter table public.posts add column if not exists content_hash text;
alter table public.posts add column if not exists duplicate_bucket date;
update public.posts
set content_hash = coalesce(content_hash, id::text),
    duplicate_bucket = coalesce(duplicate_bucket, (created_at at time zone 'Asia/Seoul')::date)
where content_hash is null or duplicate_bucket is null;
alter table public.posts alter column content_hash set not null;
alter table public.posts alter column duplicate_bucket set default ((now() at time zone 'Asia/Seoul')::date);
alter table public.posts alter column duplicate_bucket set not null;

create table if not exists public.reports (
  id uuid primary key default gen_random_uuid(),
  post_id uuid not null references public.posts(id) on delete cascade,
  reason text not null,
  detail text not null default '',
  reporter_ip_hash text not null,
  status text not null default 'open' check (status in ('open', 'resolved', 'dismissed')),
  admin_note text not null default '',
  created_at timestamptz not null default now(),
  resolved_at timestamptz
);

create unique index if not exists one_open_report_per_ip_post
  on public.reports(post_id, reporter_ip_hash) where status = 'open';
create unique index if not exists posts_daily_duplicate
  on public.posts(author_ip_hash, content_hash, duplicate_bucket) where not is_deleted;
create index if not exists posts_public_feed on public.posts(created_at desc) where not is_deleted and not is_hidden;
create index if not exists reports_status_created on public.reports(status, created_at desc);

create table if not exists public.rate_limits (
  key text primary key,
  window_started_at timestamptz not null,
  request_count integer not null check (request_count > 0),
  expires_at timestamptz not null
);
create index if not exists rate_limits_expiry on public.rate_limits(expires_at);

create or replace function public.set_updated_at()
returns trigger language plpgsql as $$
begin new.updated_at = now(); return new; end;
$$;
drop trigger if exists posts_set_updated_at on public.posts;
create trigger posts_set_updated_at before update on public.posts
for each row execute function public.set_updated_at();

create or replace function public.consume_rate_limit(p_key text, p_limit integer, p_window_seconds integer)
returns boolean
language plpgsql
security definer
set search_path = public
as $$
declare v_now timestamptz := clock_timestamp(); v_count integer;
begin
  if p_limit < 1 or p_window_seconds < 1 then return false; end if;
  delete from public.rate_limits where expires_at < v_now - interval '1 day';
  insert into public.rate_limits(key, window_started_at, request_count, expires_at)
  values (p_key, v_now, 1, v_now + make_interval(secs => p_window_seconds))
  on conflict (key) do update set
    window_started_at = case when public.rate_limits.expires_at <= v_now then v_now else public.rate_limits.window_started_at end,
    request_count = case when public.rate_limits.expires_at <= v_now then 1 else public.rate_limits.request_count + 1 end,
    expires_at = case when public.rate_limits.expires_at <= v_now then v_now + make_interval(secs => p_window_seconds) else public.rate_limits.expires_at end
  returning request_count into v_count;
  return v_count <= p_limit;
end;
$$;

alter table public.posts enable row level security;
alter table public.reports enable row level security;
alter table public.rate_limits enable row level security;
revoke all on public.posts, public.reports, public.rate_limits from anon, authenticated;
revoke all on function public.consume_rate_limit(text, integer, integer) from public, anon, authenticated;
grant execute on function public.consume_rate_limit(text, integer, integer) to service_role;

commit;
