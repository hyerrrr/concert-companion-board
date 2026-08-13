# 공연 구인 게시판

기존 단일 HTML UI를 Vercel Functions + Supabase + Cloudflare Turnstile 운영 구조로 전환한 프로젝트입니다.

## 구현 기능

- 자리 교환 / 동행·택시팟 게시글 등록, 조회, 수정, 완료 처리, 삭제
- 작성 비밀번호는 `scrypt` 해시로만 저장
- 신고 접수 및 관리자 신고 처리
- 관리자 게시글 숨김, 복구, 삭제
- Turnstile 서버 검증
- Supabase 원자적 IP 기반 요청 제한
- 같은 작성자가 같은 날 동일 내용으로 등록하는 중복글 차단
- 관리자 HttpOnly 서명 세션과 작성자 단기 권한 토큰
- Supabase RLS 활성화 및 브라우저의 DB 직접 접근 차단

## 1. Supabase 설정

Supabase 프로젝트의 SQL Editor에서 `supabase/schema.sql` 전체를 한 번 실행합니다.

Project Settings → API에서 아래 두 값을 확인합니다.

- Project URL → `SUPABASE_URL`
- `service_role` key → `SUPABASE_SERVICE_ROLE_KEY`

`service_role` 키는 절대 브라우저 코드나 공개 저장소에 넣지 마세요.

## 2. Turnstile 설정

Cloudflare Turnstile에서 사이트를 추가하고 실제 Vercel 도메인과 배포 전 테스트용 도메인을 허용합니다.

- Site key → `TURNSTILE_SITE_KEY`
- Secret key → `TURNSTILE_SECRET_KEY`

## 3. Vercel 환경변수

`.env.example`에 있는 7개 변수를 Vercel Project Settings → Environment Variables에 등록합니다. Production과 Preview에 각각 적용하세요.

- `ADMIN_CODE`: 관리자 로그인 코드. 브라우저 코드에는 포함되지 않고 서버 환경변수에만 저장됩니다.
- `SESSION_SECRET`: 32자 이상의 무작위 문자열
- `RATE_LIMIT_SECRET`: 위 값과 다른 32자 이상의 무작위 문자열

## 4. 배포

이 폴더를 Git 저장소에 올린 뒤 Vercel에서 Import하거나, Vercel CLI를 사용합니다.

```bash
npx vercel
npx vercel --prod
```

배포 후 Turnstile 허용 도메인에 최종 Vercel 도메인이 등록되어 있는지 확인합니다.

## 요청 제한 기본값

| 기능 | 제한 |
|---|---:|
| 게시글 등록 | IP당 15분에 3회 |
| 작성자 비밀번호 확인 | IP당 15분에 10회 |
| 신고 | IP당 1시간에 5회 |
| 관리자 로그인 | IP당 15분에 5회 |

제한값은 `api/[...route].js`의 각 `requireHuman` 호출에서 조정할 수 있습니다.

동일 작성자의 중복글은 한국시간 날짜 기준으로 하루에 한 번만 등록됩니다. 기존 글을 삭제하면 같은 내용을 다시 등록할 수 있습니다.
