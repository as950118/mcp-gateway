# satc-idp

satc-mcp-gateway 용 최소 OAuth 2.1 인가 서버. 게이트웨이가 검증할 JWT access token 을 발급한다.

| 용도 | grant | 클라이언트 |
|---|---|---|
| 서비스·CI 가 게이트웨이 호출 | `client_credentials` | 기밀 (client_secret) |
| 사람이 MCP 클라이언트(Claude Code 등)로 로그인 | `authorization_code` + PKCE(S256) | 공개 (secret 없음, loopback redirect) |
| 로그인 유지 | `refresh_token` (회전) | 위와 같음 |

계정은 IdP 자체 DB 에 둔다. 외부 SSO 연동, MFA, 동의 화면은 없다 (아래 "한계").

```
MCP 클라이언트 ──(1) /authorize → 로그인 폼 → code (PKCE)──┐
               ──(2) /token  code + verifier → JWT + refresh ┘
               ──(3) Authorization: Bearer JWT ──> satc-mcp-gateway ──(JWKS 로 서명·aud·exp 검증)
CI / 서비스    ──── /token client_credentials → JWT ──────────────^
```

## 실행

이 디렉터리(`idp/`)에서 실행한다. 게이트웨이와 함께 띄우는 순서는 저장소 루트 README 의 "gateway + idp 로컬 실행" 참고.

```bash
uv sync
cp config/idp.example.yaml config/idp.yaml        # issuer, allowed_audiences 수정

.venv/bin/satc-idp keys rotate                    # 서명 키 생성 (serve 가 없으면 자동 생성도 함)
.venv/bin/satc-idp users add alice                # 비밀번호는 프롬프트로 (12자 이상)
.venv/bin/satc-idp clients add ci-bot --type confidential           # secret 은 이때 한 번만 출력
.venv/bin/satc-idp clients add claude-code --type public \
    --redirect-uri http://127.0.0.1:33418/callback                  # loopback 은 포트 무관 (RFC 8252)
.venv/bin/satc-idp serve --port 5700
```

설정 파일은 `-c` 또는 `SATC_IDP_CONFIG`. `config/idp.yaml`, `data/`(DB·키·감사 로그)는 커밋하지 않는다.

### CLI

| 명령 | 설명 |
|---|---|
| `users add <name> [--password-stdin]` | 비밀번호는 프롬프트 또는 stdin 으로만 받는다 (argv·셸 기록에 남지 않게) |
| `users list` / `disable <name>` / `enable <name>` | disable 하면 그 사용자의 refresh token 을 모두 폐기 |
| `users set-password <name>` | 변경 시 기존 refresh token 모두 폐기 |
| `clients add <id> --type confidential\|public [--redirect-uri] [--scope] [--grant] [--name]` | 기밀: secret 생성 후 1회 출력, 해시만 저장. 공개: client_credentials 불가 |
| `clients list` / `remove <id>` | remove 하면 그 클라이언트의 refresh token 폐기 |
| `keys rotate` / `keys list` | 새 키를 active 로. 실행 중인 서버는 다음 요청에서 바로 반영 |

## 엔드포인트

| 경로 | 내용 |
|---|---|
| `GET /.well-known/oauth-authorization-server` | RFC 8414 메타데이터 |
| `GET /.well-known/jwks.json` | 공개키 (active + 직전 키) |
| `GET /authorize` | 요청 검증 → 로그인 폼 |
| `POST /authorize` | 로그인 → `redirect_uri?code=..&state=..&iss=..` (303) |
| `POST /token` | `authorization_code` / `refresh_token` / `client_credentials` |
| `POST /revoke` | refresh token 폐기 (RFC 7009, family 단위) |
| `POST /register` | 동적 클라이언트 등록 (RFC 7591, 기본 꺼짐) |
| `GET /userinfo` | `sub`, `preferred_username` |
| `GET /health` | |

### Access token (JWT, RFC 9068)

헤더 `alg=RS256, kid, typ=at+jwt`. 클레임 `iss, sub, aud, exp, iat, nbf, jti, client_id, scope`.
`sub` 는 사용자 id (client_credentials 는 client_id). `aud` 는 요청의 `resource`(RFC 8707) — `allowed_audiences` 안의 값만 허용, 없으면 첫 번째 값.
기본 수명 15분.

## 설정 (`config/idp.example.yaml`)

주요 키 (전체와 기본값은 예시 파일 주석 참고):

- `issuer`: https 여야 한다 (loopback 만 http 허용). 아니면 기동 거부 (`allow_insecure_issuer: true` 는 테스트 전용)
- `allowed_audiences`(게이트웨이 MCP URL), `scopes`, 토큰·코드 수명, `published_previous_keys`
- `refresh_family_max_lifetime_s`: refresh family 절대 수명 (기본 30일). 회전해도 늘지 않는다
- `cookie_secure`: 기본 true (`__Host-` 쿠키). false 는 loopback issuer 에서만 허용
- `forwarded_allow_ips`: 리버스 프록시 IP/CIDR. 비어 있으면 X-Forwarded-For 무시. `*`·`/0` 은 기동 거부. https issuer 인데 비어 있으면 경고 (프록시 뒤라면 모든 사용자가 프록시 IP 하나로 보여 IP 잠금을 함께 받는다). 이전 `trust_proxy` 는 없어졌고, 지정하면 기동 거부
- `argon2_max_concurrency`, `unknown_client_delay_s`, `max_pending_login_requests`, `max_pending_login_requests_per_ip`
- `max_form_bytes`(기본 16KB), `max_form_fields`(기본 30): `/token`·`/revoke`·`POST /authorize` 본문 제한
- `lockout`: `pair_max_failures`, `ip_max_failures`, `backoff_after`(서로 다른 IP 수)·`backoff_base_s`·`backoff_max_s`, `user_max_failures`, `trusted_ttl_s`
- `rate_limits`: `authorize_per_minute`, `token_per_minute`, `revoke_per_minute` (IP 당)
- `dcr`: `enabled`, `allow_localhost`(기본 true), `allowed_redirect_uris`, `default_scopes`(생략하면 전체 `scopes`), `rate_limit_per_hour`, `max_clients`, `unused_client_ttl_s`, `max_body_bytes`, `audiences`

## 보안 설계

**직접 구현하지 않은 것**: JWT 서명·검증과 JWK 는 `joserfc`, 비밀번호·client secret 해시는 `argon2-cffi`(argon2id), 난수는 `secrets`, 비교는 `hmac.compare_digest`.

| 항목 | 결정 |
|---|---|
| 비밀 저장 | 비밀번호·client secret 은 argon2id. 코드·refresh token·로그인 쿠키는 256비트 난수의 SHA-256 만 저장 (엔트로피가 충분해 느린 해시가 필요 없음) |
| argon2 비용 | 동시 검증 수 제한(`argon2_max_concurrency`, 기본 4). **없는 client_id 는 argon2 를 돌리지 않고 고정 지연**만 둔다 (인증 없는 CPU·메모리 증폭 방지. client_id 는 비밀이 아니라 존재 여부 노출은 수용) |
| 파일 권한 | CLI 가 umask 077 로 실행. 키 디렉터리 700, 개인키·DB·WAL·감사 로그 600. 개인키는 처음부터 600 으로 생성 (O_EXCL) |
| PKCE | 모든 클라이언트 필수, S256 만. verifier 형식(43~128자) 검사 |
| 인가 코드 | 60초, 1회용. client_id·redirect_uri·code_challenge 에 묶임. **redirect_uri·PKCE 를 확인한 뒤에만 사용 처리**한다 (확인과 사용 처리가 같은 락 안). verifier 가 틀리면 코드를 소모하지 않는다 (코드만 가로챈 쪽이 코드를 태울 수 없다). **정상 교환된 코드를 verifier 까지 맞게 다시 내면 그 코드로 발급한 refresh token family 전체 폐기**. verifier 없이 다시 낸 경우는 폐기하지 않는다 (DoS 방지). 다른 클라이언트가 낸 코드는 없는 코드처럼 처리 |
| refresh token | 불투명 난수, 회전. **이미 쓴 토큰이 다시 오면 family 전체 폐기** (탈취 감지). 클라이언트에 묶임. family 절대 수명(기본 30일)을 넘지 않는다 |
| 사용자 비활성·비밀번호 변경 | refresh family 전체 폐기 + 아직 교환되지 않은 인가 코드 삭제 |
| redirect_uri | 등록값과 정확히 일치. 공개 클라이언트의 loopback 만 포트 무관 (RFC 8252). 등록 시 https 또는 loopback http 만 허용. fragment 금지 |
| 오류 redirect | client_id·redirect_uri 를 확인하기 전 오류는 redirect 하지 않고 오류 화면만 보인다 (open redirect 방지) |
| 클라이언트 인증 | `client_secret_basic` / `client_secret_post` / 공개는 `none`. 두 방식 동시 사용 거부. 실패 시 401 + `WWW-Authenticate`. 없는 client_id 도 같은 시간 소요 |
| 로그인 CSRF | 서버에 저장한 로그인 요청(request_id) + 폼 CSRF 토큰 + 브라우저 쿠키(HttpOnly, SameSite=Lax, Secure) 세 가지가 모두 맞아야 한다. 로그인 요청은 1회용. **쿠키는 로그인 요청마다 새 이름·새 값**(`satc_idp_login_<request_id>`, https 면 `__Host-` 접두사·path=/)으로 발급하고, 받은 쿠키 값을 다시 쓰지 않는다 (세션 고정 방지). 로그인 성공 시 삭제 |
| 무차별 대입 | 검증 **전에** 실패를 먼저 예약한다 (한도 확인과 기록이 한 트랜잭션 → 동시 요청으로 한도를 넘을 수 없음). 같은 사용자 동시 검증은 1건만. 잠긴 동안은 비밀번호를 검증하지 않음. 없는 사용자도 더미 해시로 같은 시간 소요. 기준은 아래 |
| 잠금 기준 (15분 창) | **(사용자, IP) 쌍 5회** = 주 방어선. **IP 20회** = 여러 사용자 대입. **사용자 전체**: 실패가 **서로 다른 IP 10곳** 이상에서 나오면 지수 백오프(1초부터 최대 60초 대기), 실패 100회면 하드 잠금. **전에 로그인에 성공한 (사용자, IP) 와 신뢰 기기 쿠키**(로그인 성공 시마다 새 값 발급, `trusted_ttl_s` 기본 30일, 비밀번호 변경·비활성화 시 폐기)는 사용자 전체 백오프·하드 잠금에서 뺀다. 쌍·IP 잠금은 그대로 받는다 |
| 잠금 트레이드오프 | 사용자 전체 잠금은 사용자명만 아는 사람이 남의 계정을 잠그는 DoS 가 된다. 그래서 (1) 소수 IP 로 실패를 쌓아도 백오프가 걸리지 않게 IP 수 기준으로 세고 (그 IP 들은 쌍 잠금이 막는다), (2) 익숙한 IP·기기의 정상 사용자는 면제한다. 대신 **처음 쓰는 IP·기기의 정상 사용자**는 분산 공격(서로 다른 IP 10곳 이상) 중에 백오프 대기를 겪을 수 있다. 같은 IP(NAT 공유 등)에서의 공격과 피해자는 구분할 수 없다 |
| 클라이언트 IP | `request.client.host` 만 쓴다. X-Forwarded-For 는 `forwarded_allow_ips` 의 프록시에서 온 요청만, uvicorn `ProxyHeadersMiddleware` 가 **신뢰하지 않는 가장 오른쪽 값**을 고른다 (맨 왼쪽 값 위조로 IP 잠금·속도 제한 우회 방지) |
| 속도 제한 | IP 당 분당 `/authorize`·`/token`·`/revoke` 요청 수 (메모리, 단일 인스턴스, LRU 로 key 수 상한·O(1) 정리 — 상한을 넘으면 가장 오래 안 쓴 key 의 기록이 사라진다). 처리 전 로그인 요청은 IP 당 20건·전체 1만 건 상한. `state` 512자 이하 (넘으면 돌려주지 않고 오류) |
| 요청 본문 | `/token`·`/revoke`·`POST /authorize` 는 `application/x-www-form-urlencoded` 만, 16KB·필드 30개 이하 (Starlette 기본은 필드당 1MB × 1000). `/register` JSON 은 16KB, 깊게 중첩된 JSON 은 400 |
| HTML | CSP(`default-src 'none'`, `frame-ancestors 'none'`), X-Frame-Options DENY, no-store, nosniff, no-referrer. 출력 값 전부 escape. `form-action` 은 넣지 않음 (로그인 후 redirect 를 브라우저가 막음) |
| 토큰 응답 | `Cache-Control: no-store`, `Pragma: no-cache` |
| scope / aud | 클라이언트 허용 범위 안에서만. refresh 는 줄이기만 가능. 코드·refresh 에 묶인 aud 는 바꿀 수 없음. **교환·refresh 때마다 지금 정책으로 다시 확인**: 묶인 aud 가 설정·클라이언트 허용 목록에서 빠졌으면 `invalid_target`, scope 는 (처음 받은 scope ∩ 클라이언트 scope ∩ 서버 scopes), 남는 것이 없으면 `invalid_scope` |
| DCR | 기본 꺼짐. 켜도 공개 클라이언트(`none`)만, redirect 는 loopback(127.0.0.1, [::1], `allow_localhost` 면 `localhost`) 또는 허용 목록, grant 는 authorization_code/refresh_token. 필드 타입 검사(잘못되면 400), 본문 16KB·URI 2048자·redirect 10개·client_name 100자 제한, IP 당 시간당 횟수·전체 클라이언트 수 상한. 정리: 토큰을 한 번도 받지 않은 클라이언트는 `unused_client_ttl_s` 뒤, 받은 적 있는 클라이언트는 마지막 사용이 refresh family 절대 수명보다 오래됐을 때만 삭제. 로그인 화면에 **"(미검증 클라이언트)"** 표시 (이름을 스스로 정하므로) |
| DCR `localhost` | Claude Code 는 MCP OAuth 콜백으로 `http://localhost:<임의 포트>/callback` 을 쓴다. 그래서 `dcr.allow_localhost: true` 가 기본이다. RFC 8252 8.3 은 `localhost` 대신 IP 리터럴을 권한다 (hosts 파일·DNS 조작으로 다른 곳을 가리킬 수 있음). 이 위험은 사용자 PC 가 이미 조작된 경우에 해당하고, PKCE 가 코드 가로채기를 막는다. `localhost` 를 쓰는 클라이언트가 없으면 `allow_localhost: false` 로 끈다 |
| 클라이언트별 aud | `clients add --audience` 로 좁힐 수 있다 (`allowed_audiences` 와 교집합). 지정하지 않으면 전체. DCR 클라이언트는 `dcr.audiences` (비어 있으면 전체) |
| 키 교체 | active + 직전 `published_previous_keys` 개를 JWKS 에 게시. 더 오래된 키는 retired (게시 안 함) 되고 **개인키 파일도 삭제** |
| /userinfo | 이 서버가 발급한 access token(`typ=at+jwt`)이고 aud 가 지금 `allowed_audiences` 에 있어야 한다 |
| 감사 로그 | JSONL. 로그인 성공·실패(사유), 토큰 발급(jti)·오류, 코드·refresh 재사용, 폐기, 등록. 비밀 값 필드가 들어오면 예외. 신뢰할 수 없는 client_id 는 형식이 맞지 않으면 `invalid` 로, 사용자명은 64자로 잘라 기록 |
| 설정 안전장치 | https 도 loopback 도 아닌 issuer, loopback 이 아닌데 `cookie_secure: false`, `forwarded_allow_ips` 의 `*`·`/0` 은 기동 거부. 예시 설정은 https + `cookie_secure: true` |

## 검증 현황 (2026-10-14)

**2차 보안 리뷰 반영 (2026-10-14)**: 1차 수정 뒤 다른 리뷰어가 다시 본 결과(N1~N9)를 모두 반영했다. 회귀 테스트는 `tests/test_review2_fixes.py` (이름 앞 = N 번호).
- 리뷰어 PoC 재실행 결과

  | # | 내용 | 수정 전 | 수정 후 |
  |---|---|---|---|
  | N1 | 1시간 동안 공격 IP 6곳이 사용자 전체 백오프 유지 | 피해자 성공 11, 429 거부 503 | **성공 514, 거부 0** (공격 실패 기록 120건) |
  | N2 | `forwarded_allow_ips: ["*"]` 로 XFF 위조 스프레이 | 100/100 검증 | 기동 거부 |
  | N3 | aud·scope 를 허용 목록에서 뺀 뒤 refresh | 200, 예전 aud | 400 `invalid_target` |
  | N4 | 깊게 중첩된 DCR JSON | 500 | 400 `invalid_client_metadata` |
  | N5 | 틀린 verifier 로 먼저 제출 | 정상 교환 400 + `code_reuse` | 공격자 400, **정상 교환 200**, `code_reuse` 없음 |
  | N7 | `/token` 299MB form 본문 | Python 할당 최대 601MB | **413**, 최대 1MB |
  | N8 | key 10만 개에서 `allow()` 1회 | 14.3ms | 0.0ms |
  | 마이그레이션 | 새 열·테이블 없는 이전 DB | — | 열 추가, 새 테이블 생성, 기존 행 유지 |
- 변이 검사 (되돌림 → 실패 확인 → 복원 후 원본과 동일 확인)
  - N1 신뢰 면제 제거 → `test_n1_known_ip_and_trusted_device_exempt_from_user_backoff`, `test_n1_hard_lock_exempts_trusted` 실패. 서로 다른 IP 대신 실패 수로 세기 → `test_n1_backoff_counts_distinct_ips` 실패
  - N3 묶인 aud 재확인 제거 → `test_n3_*` 2개 실패
  - N5 확인 전에 사용 처리 → `test_n5_*` 2개 포함 8개 실패
- 함께 바꾼 것: DCR `localhost` redirect 허용(`dcr.allow_localhost`, 기본 true — Claude Code 호환), `dcr.default_scopes` 생략 시 전체 scopes (전에는 `[]` 라 `dcr: {enabled: true}` 만 쓰면 로그인 단계에서 `invalid_scope`)

**보안 리뷰 반영 (2026-10-14)**: 독립 리뷰의 17개 발견 사항 중 16개를 수정했다 (#16 공개 client 와 미등록 client 의 응답 시간 차이는 client_id 가 비밀이 아니라서 수용). 항목마다 회귀 테스트를 `tests/test_review_fixes.py` 에 두었다 (이름 앞 번호 = 리뷰 번호).
- 리뷰어 PoC 재실행 결과
  - 동시 로그인 40건: 비밀번호 검증 40회에서 **1회**로 줄었다 (39건은 429)
  - 신뢰 프록시 뒤 X-Forwarded-For 맨 왼쪽 위조: IP 잠금이 3회 뒤 걸리고, DCR 제한 2회가 지켜지며, 감사 로그 ip 는 실제 주소
  - 없는 client 의 /token: argon2 를 돌리지 않는다 (고정 지연 50ms). 기본 분당 120회 뒤 429
  - 다른 클라이언트가 낸 코드: 정상 교환과 피해자 refresh 모두 영향 없음
  - 비밀번호 변경 뒤 대기 중인 코드 교환: 400
  - 1MB client_id 실패: 감사 로그 149바이트. DCR 대용량 요청: 413
  - DCR 잘못된 타입: 500 대신 400. `localhost` redirect: 400. 공격자가 심은 쿠키 값: 재사용하지 않음
- 변이 검사 (수정 → 되돌림 → 테스트 실패 확인 → 복원 후 원본과 동일 확인)
  - #1 잠금 예약·동시 검증 제한 제거 → `test_01_concurrent_guesses_cannot_exceed_lockout` 실패
  - #2 X-Forwarded-For 맨 왼쪽 값 사용 → `test_02_*` 2개 실패
  - #5 client_id 와 무관하게 코드 소모 → `test_05_other_client_cannot_burn_or_replay_code` 실패

**실증**
- 단위·통합 테스트 121개 (`uv run pytest`): 정상 흐름 10개, 보안 부정 테스트 44개, 1차 리뷰 회귀 38개, 2차 리뷰 회귀 29개 (파라미터화 포함).
  - 정상: discovery·JWKS(공개키만), 개인키 권한, client_credentials (basic/post, 다른 aud), 인가 코드 + PKCE + refresh 회전, loopback 임의 포트, scope 축소, revoke, userinfo, DCR 후 로그인, 감사 로그에 비밀 값 없음
  - 부정: PKCE 없음·plain·불일치·verifier 없음, 코드 재사용 → family 폐기, 코드 만료, redirect_uri 불일치, 다른 클라이언트의 코드, 등록 안 된 redirect 4종(외부·경로 조작·fragment·유사 호스트)은 redirect 하지 않음, 없는 클라이언트, 기밀 클라이언트 loopback 포트 변경, 잘못된 secret·secret 없음, 공개 클라이언트의 client_credentials, 인증 방식 중복, 미지원 grant, refresh 재사용 → family 폐기, 다른 클라이언트의 refresh, 비활성 사용자 refresh·로그인, scope 상승 3경로, 허용 안 된 resource, 교환 시 resource 변경, 사용자·IP 잠금, CSRF 토큰 없음·위조, 쿠키 없는 브라우저(login CSRF), 로그인 요청 재사용, 보안 헤더·쿠키 속성, client_name XSS escape, DCR 꺼짐·위험 메타데이터 5종·속도 제한, 키 교체 후 기존 토큰 검증 / 두 번 교체 후 내려간 키 거부, 다른 키로 위조한 토큰 거부
- 변이 검사: PKCE 검증, 코드 재사용 family 폐기, redirect_uri 검증, 로그인 쿠키 바인딩을 각각 끄면 해당 테스트(2·1·5·1개)가 실패하고, 되돌리면 모두 통과.
- 실제 서버 E2E (uvicorn 127.0.0.1:5700, CLI 로 사용자·클라이언트 생성, httpx)
  - client_credentials 200 (`no-store`), 실제 JWKS 로 서명·iss·aud·exp 검증, `typ=at+jwt`, 수명 900초. 잘못된 secret 401 + `Basic realm="satc-idp"`
  - 인가 코드: 로그인 폼(CSP·쿠키) → 잘못된 비밀번호 401 → 로그인 303 (`state`, `iss` 포함) → 교환 200 → 같은 코드 재사용 400 → 그 코드의 refresh 도 400
  - refresh 회전 200 → 이전 refresh 재사용 400 → 최신 refresh 도 400 (family 폐기)
  - 서버 실행 중 `keys rotate` → JWKS 에 두 키, 교체 전·후 토큰 모두 검증
  - DCR 꺼짐 404. 감사 로그·서버 로그에 secret·비밀번호 문자열 0건
  - CLI 거부: 외부 http redirect_uri, 12자 미만 비밀번호
  - 데이터 파일 권한: DB·WAL·SHM·감사 로그·개인키 600, 키 디렉터리 700

- 보안 리뷰 반영 뒤 실제 서버 smoke (2026-10-14): client_credentials 200 (`typ=at+jwt`, aud·scope 유지), 잘못된 secret 401, 로그인 폼 → 잘못된 비밀번호 401 → 로그인 303 (로그인 쿠키 삭제) → 교환 200 → refresh 회전 200 → 이전 refresh 재사용 400. CLI 가 설정에 없는 `--audience` 를 거부. 감사·서버 로그에 secret·비밀번호 0건

- satc-mcp-gateway 연동 E2E (2차 리뷰 반영 뒤, upstream 5599 + IdP 5700 + 게이트웨이 5600 `auth.mode=jwt`)
  - IdP 설정은 `dcr: {enabled: true}` 만 (redirect 허용 목록·default_scopes 없이)
  - client_credentials → 게이트웨이 도구 31개, 호출 성공, 게이트웨이 감사 로그 `client: ci-bot`
  - 디스커버리 전 과정: 401 + `resource_metadata` → PRM → AS 메타데이터 → **DCR `http://localhost:53682/callback` 201 (scope `mcp`)** → 로그인 폼(미검증 라벨) → 303 콜백 → 토큰(aud·scope 정상) → 게이트웨이 호출 성공 → 같은 코드 재사용 400
  - mcp SDK `OAuthClientProvider` (127.0.0.1 콜백) → 도구 31개, 호출 성공
  - 서버 로그·두 감사 로그에 secret·비밀번호·JWT 문자열 0건, 감사 로그 권한 600

**부분 실증**
- Claude Code 2.1.299 headless: 게이트웨이 401 을 `needs-auth` 로 인식한다. headless 에서는 DCR·브라우저 로그인을 시작하지 않아 그 뒤는 확인하지 못했다.

**미검증**
- 실제 MCP 클라이언트(Claude Code)의 대화형 OAuth 흐름 (DCR + 브라우저 로그인). Claude Code 가 쓰는 redirect 형식(`http://localhost:<포트>/callback`)으로 DCR·로그인·교환이 되는 것은 스크립트로 확인했다.
- 실제 브라우저에서의 로그인 화면·쿠키 동작 (테스트는 HTTP 클라이언트로만).
- 부하·동시성 (sqlite 단일 연결 + 락).
- 외부 보안 점검·침투 테스트.

## 한계

- MFA, 동의(consent) 화면, 비밀번호 재설정 메일, 외부 SSO 연동 없음.
- id_token 을 발급하지 않는다 (OIDC 로그인 용도가 아니라 access token 발급 서버).
- **access token 은 폐기할 수 없다.** 게이트웨이가 JWKS 로 로컬 검증하므로 refresh token 을 폐기해도 이미 발급된 access token 은 만료(기본 15분)까지 유효하다. 수명을 짧게 유지한다.
- 로그인 세션을 유지하지 않는다 (인가 요청마다 로그인).
- sqlite 단일 인스턴스 전제. 속도 제한·동시 검증 제한도 프로세스 메모리에 있다 (uvicorn worker 를 여러 개 띄우면 worker 마다 따로 센다). 여러 인스턴스로 늘리려면 저장소와 제한을 공유 저장소로 옮겨야 한다.
- TLS 는 앞단(리버스 프록시)에서 처리한다. 운영에서는 `issuer` 를 https 로, `cookie_secure: true`, 프록시 뒤면 `forwarded_allow_ips` 에 프록시 주소.
- 같은 IP 를 공유하는 사용자(NAT 등) 사이에서는 (사용자, IP) 잠금이 공격자와 피해자를 구분하지 못한다.
- 분산 공격(서로 다른 IP 10곳 이상) 중에는 처음 쓰는 IP·기기의 정상 사용자가 백오프 대기를 겪을 수 있다.
- 버려진 로그인 쿠키(`satc_idp_login_<id>`)는 만료(10분)까지 브라우저에 남는다. 로그인 화면을 짧은 시간에 아주 많이 열면 쿠키 헤더가 프록시 헤더 한도를 넘을 수 있다 (사용자 스스로 일으키는 경우만 해당, 고치지 않음).
- refresh token 개별 만료는 회전할 때마다 `refresh_token_ttl_s` 만큼 다시 잡힌다 (family 절대 수명 안에서만).
- 키 교체는 수동(`keys rotate`). 자동 교체 주기는 없다.
