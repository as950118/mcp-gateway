# satc-mcp-gateway

satc-mcp-server 같은 MCP 서버 앞에 두는 게이트웨이. upstream 코드를 고치지 않고 세 가지를 더한다.

| 구성 | 하는 일 | 위치 |
|---|---|---|
| **Tool Registry** | upstream 도구 정의 + 게이트웨이가 관리하는 메타데이터(도메인·부작용·태그·예시·core) | `registry.py`, `config/registry/*.yaml` |
| **도구 검색** | 자연어 질의로 도구 찾기 (`search_tools`). 기본은 메모리 BM25, 인터페이스 교체 가능 | `search.py` |
| **실행 Gateway** | 감사 로그, 부작용·도구별 차단·확인, 타임아웃, 노출 모드(all/dynamic) | `middleware.py` |
| **인증** | HTTP 접속 인증 (정적 토큰 / JWT). stdio 는 로컬 실행이라 인증하지 않는다 | `auth.py` |

```
클라이언트(Cursor, Claude Code)
   │  MCP (stdio / streamable-http)
   ▼
satc-mcp-gateway ── Audit ─> Exposure ─> Policy ─> mount(proxy) ──> satc-mcp-server (http)
                                │                                └─> (다른 MCP 서버, prefix 로 구분)
                     Registry + ToolSearcher
                     search_tools / activate_tools
```

## 실행

```bash
uv sync
cp config/gateway.example.yaml config/gateway.yaml
# config/registry/<upstream>.yaml 작성 (config/registry/example.yaml 참고) 후 gateway.yaml 의 registry 경로 수정

# 1) upstream 을 HTTP 로 띄운다 (satc-mcp-server 디렉터리에서)
MCP_TRANSPORT=http MCP_SERVER_PORT=5555 .venv/bin/python main.py

# 2) 레지스트리 대조 — upstream 도구와 config/registry 가 어긋나면 경고와 함께 exit 1
.venv/bin/satc-mcp-gateway check

# 3) 게이트웨이 실행
.venv/bin/satc-mcp-gateway serve                                  # stdio (Cursor 등록용)
.venv/bin/satc-mcp-gateway serve --transport http --port 5600     # http (기본 127.0.0.1)

# 검색 결과 확인 (디버깅)
.venv/bin/satc-mcp-gateway search "argo 파드 로그에서 에러 원인"
```

upstream 주소는 `SATC_MCP_SERVER_URL` (기본 `http://localhost:5555/mcp`), 설정 파일은 `-c` 또는 `SATC_GATEWAY_CONFIG`.
HTTP 를 외부 주소(`--host 0.0.0.0` 등)로 열려면 인증을 설정해야 한다 (아래 "인증").

Cursor `mcp.json` 예시:

```json
{
  "mcpServers": {
    "satc": {
      "command": "/path/to/satc-mcp-gateway/.venv/bin/satc-mcp-gateway",
      "args": ["serve", "-c", "/path/to/satc-mcp-gateway/config/gateway.yaml"],
      "env": { "SATC_MCP_SERVER_URL": "http://localhost:5555/mcp" }
    }
  }
}
```

## 설정 (`config/gateway.yaml`)

- `upstreams[]`: `name`, `url`, `prefix`(있으면 도구 이름이 `{prefix}_{name}`), `registry`(메타데이터 YAML)
- `exposure.mode`
  - `all` (기본): 모든 도구를 그대로 노출하고 `search_tools`·`activate_tools` 를 더한다. 기존 동작과 같다.
  - `dynamic`: `core: true` 도구와 메타 도구만 노출한다. `activate_tools` 로 켠 도구는 **그 세션에만** 노출되고 `notifications/tools/list_changed` 를 보낸다. 클라이언트가 이 알림을 지원해야 한다.
- `policy`
  - `side_effects`: 분류별 `allow` / `deny` / `confirm`
  - `deny_tools`, `confirm_tools`: 도구별 지정 (`deny` 가 우선)
  - `confirm_fallback`: confirm 대상인데 클라이언트가 elicitation 을 지원하지 않을 때 `deny`(기본) / `allow`
  - `timeouts`(분류별 초), `tool_timeouts`. 사용자 확인을 기다리는 시간은 타임아웃에 넣지 않는다

### 실행 전 확인 (`confirm`)

`confirm` 대상 도구를 호출하면 게이트웨이가 MCP elicitation 으로 "실행할까요?" 를 묻는다 (도구 이름, 부작용 분류, 비밀값을 가린 인자 포함).
승인하면 실행하고, 거절·취소하면 차단한다. 감사 로그 `confirm` 필드에 `accept` / `decline` / `cancel` / `fallback_allow` / `fallback_deny` 가 남는다.

```yaml
policy:
  side_effects: {external: confirm}     # 예: PR 생성처럼 외부 상태를 바꾸는 도구는 확인받기
  confirm_tools: [some_exec_tool]       # 도구 단위로도 지정 가능
```
- `audit.path`: JSON Lines 감사 로그. `password`·`token`·`secret` 등이 들어간 인자 키는 `***` 로 가린다
- `registry_ttl_s`: upstream 도구 목록을 다시 읽는 주기

### 인증 (`auth`, HTTP 전용)

| `mode` | 동작 | 필요한 값 |
|---|---|---|
| `none` (기본) | 인증 없음. loopback(127.0.0.1, localhost, ::1) 이 아닌 주소로 HTTP 를 열면 기동을 거부한다 (`allow_unauthenticated: true` 로 해제) | - |
| `static_tokens` | `Authorization: Bearer <token>` 을 정적 토큰 목록과 대조 (fastmcp `StaticTokenVerifier`) | 환경변수 `GATEWAY_TOKENS="alice:<token>,ci-bot:<token>"` (`tokens_env` 로 이름 변경) |
| `jwt` | 외부 IdP 가 발급한 JWT 를 검증 (fastmcp `JWTVerifier`) | `jwks_uri` 또는 `public_key_env`(PEM 공개키 환경변수 이름), `issuer`, `audience`(없으면 `resource_url`), `algorithm`(기본 RS256) |

```yaml
auth:
  mode: static_tokens
  tokens_env: GATEWAY_TOKENS
  # mode: jwt
  # jwks_uri: ${GATEWAY_JWKS_URI}
  # issuer: https://idp.example.com
  # audience: mcp-gateway
```

- 토큰 값은 설정 파일에 쓰지 않는다. 정적 토큰은 16자 미만이면 경고한다 (`openssl rand -hex 24` 권장).
- 감사 로그 `client` 필드에 호출자가 남는다 (정적 토큰은 client_id, JWT 는 `client_id` 또는 `sub`). 토큰 값은 남기지 않는다.
- `GET /health` 는 인증 없이 열려 있고 `{"status":"ok"}` 만 돌려준다 (컨테이너 헬스체크용).
- fastmcp 문서는 `StaticTokenVerifier` 를 개발·테스트용으로 안내한다. 팀 공용 운영에는 `jwt` 를 권장한다.
- 클라이언트 설정 형식 예 (Claude Code `.mcp.json`, 고정 bearer 토큰. 2026-10-14 Claude Code 2.1.296 에서 확인):

  ```json
  { "mcpServers": { "satc": { "type": "http", "url": "https://gateway.example.com/mcp",
      "headers": { "Authorization": "Bearer ${SATC_GATEWAY_TOKEN}" } } } }
  ```

### OAuth 연동 (satc-idp) 과 MCP 인가 디스커버리

satc-idp(별도 프로젝트) 같은 OAuth 2.1 인가 서버가 발급한 JWT 로 게이트웨이를 보호한다. `resource_url` 을 주면 MCP 클라이언트가 스스로 인가 서버를 찾아 로그인할 수 있다 (MCP 인가 스펙, RFC 9728).

```yaml
auth:
  mode: jwt
  jwks_uri: https://idp.example.com/.well-known/jwks.json
  issuer: https://idp.example.com
  # 게이트웨이 MCP 엔드포인트의 외부 URL. 토큰 aud 도 이 값으로 검증한다 (audience 를 따로 주지 않으면)
  resource_url: https://gateway.example.com/mcp
  # authorization_servers: [https://idp.example.com]   # 없으면 [issuer]
  required_scopes: [mcp]
```

```
MCP 클라이언트 ── POST /mcp (토큰 없음) ──> 401  WWW-Authenticate: Bearer resource_metadata=".../.well-known/oauth-protected-resource/mcp"
               ── GET  PRM ──> {"resource": ".../mcp", "authorization_servers": ["https://idp.example.com/"], "scopes_supported": ["mcp"]}
               ── GET  IdP /.well-known/oauth-authorization-server
               ── POST IdP /register (동적 등록, IdP 에서 켰을 때) → /authorize (PKCE, 로그인) → /token (resource=.../mcp)
               ── POST /mcp  Authorization: Bearer <JWT aud=.../mcp>
```

- **스코프**: 게이트웨이 접근은 `mcp` 하나로 둔다 (`required_scopes`). 도구 단위 권한은 스코프가 아니라 게이트웨이 정책(`policy`)이 맡는다. IdP 는 `mcp` 를 기본 스코프로 발급한다.
- **audience**: IdP 는 RFC 8707 `resource` 값을 `aud` 로 넣는다. IdP 의 `allowed_audiences` 에 `resource_url` 과 같은 값을 넣는다.
- 감사 로그 `client`: client_credentials 는 `ci-bot`, 사용자 로그인은 `<client_id> (<사용자 id>)`.
- PRM 문서는 `/.well-known/oauth-protected-resource/mcp`(RFC 9728 경로)와 `/.well-known/oauth-protected-resource` 두 곳에서 같은 내용을 준다.
- **fastmcp 2.11.3 보정**: 401 의 `resource_metadata` 를 fastmcp 는 `{resource}/.well-known/oauth-protected-resource` 로 알리지만 문서는 RFC 9728 경로에 등록돼 404 가 된다. 게이트웨이는 알리는 주소를 등록 경로에 맞춘다 (`auth.py` `ProtectedResourceAuth`).
- mcp SDK 가 `authorization_servers` 를 직렬화하며 끝에 `/` 를 붙인다 (`https://idp.example.com/`). mcp SDK 클라이언트는 문제없이 처리했다. 다른 클라이언트에서 issuer 비교가 실패하면 이 점을 먼저 본다.
- **클라이언트 호환**: mcp SDK `OAuthClientProvider` 에 MCP URL(`.../mcp`) 을 주면 전 과정이 동작한다. fastmcp 2.11.3 의 `fastmcp.client.auth.OAuth` helper 는 서버 URL 을 origin 으로 잘라 넘겨서, PRM resource(`.../mcp`) 검증에서 `Protected resource ... does not match expected ...` 로 실패한다 (클라이언트 쪽 한계).

### 부작용 분류 (`side_effect`)

| 값 | 뜻 | 클라이언트에 붙는 annotation |
|---|---|---|
| `read` | 조회만 (프롬프트·문서 문자열 생성 포함) | `readOnlyHint: true` |
| `write` | 로컬 파일 생성 | `readOnlyHint: false` |
| `exec` | SSH·subprocess 실행 | `readOnlyHint: false`, `openWorldHint: true` |
| `external` | 외부 시스템 상태 변경 (커밋·PR) | `readOnlyHint: false`, `openWorldHint: true` |
| `unknown` | 레지스트리에 없음 | 붙이지 않음 |

분류는 upstream 코드를 읽고 정하고, 근거를 레지스트리 YAML 주석으로 남긴다.

## Docker

```bash
cp config/gateway.example.yaml config/gateway.yaml      # auth.mode 를 static_tokens 또는 jwt 로
docker build -t satc-mcp-gateway .
docker run -d -p 5600:5600 \
  -e SATC_MCP_SERVER_URL=http://<upstream>:5555/mcp \
  -e GATEWAY_TOKENS="alice:$(openssl rand -hex 24)" \
  -v "$PWD/config:/app/config:ro" -v gateway-logs:/app/logs \
  satc-mcp-gateway
```

- 이미지에는 설정을 넣지 않는다. `config/` 를 `/app/config` 에 마운트한다 (`gateway.yaml` 의 `audit.path: ../logs/audit.jsonl` → `/app/logs`).
- non-root 사용자(`gateway`, uid 10001)로 `serve --transport http --host 0.0.0.0 --port 5600` 을 실행한다. `auth.mode: none` 이면 기동을 거부한다.
- `HEALTHCHECK` 는 `/health` 를 본다.
- upstream 과 함께 띄우는 예시: `docker-compose.example.yml`.
- `OPENSSL_armcap=0` 이 기본으로 들어 있다. Apple M4 의 Docker(arm64)에서 OpenSSL 이 CPU 기능을 잘못 감지해 `cryptography` import 때 SIGILL(exit 132)로 죽는 문제를 피한다. x86 에서는 무시되고, ARM 서버에서 OpenSSL 가속이 필요하면 `-e OPENSSL_armcap=` 로 끈다.
- Docker Desktop(macOS)은 공유되지 않은 경로(예: `/private/tmp`)를 빈 디렉터리로 마운트한다. 설정은 공유된 경로(`/Users/...`)에 둔다.

## 커밋하지 않는 파일

사내 upstream 의 도구 목록·이름이 드러나는 파일은 `.gitignore` 로 빼고, 같은 형식의 예시만 커밋한다.

| 실제 파일 (로컬 전용) | 커밋되는 예시 |
|---|---|
| `config/gateway.yaml` | `config/gateway.example.yaml` |
| `config/registry/<upstream>.yaml` | `config/registry/example.yaml` |
| `eval/upstream_tools.snapshot.json` | `eval/upstream_tools.snapshot.example.json` |
| `eval/tool_queries.yaml` | `eval/tool_queries.example.yaml` |

## 레지스트리 메타데이터 작성 규칙

- upstream 에 도구가 추가되면 `check` 가 경고한다 → YAML 에 항목을 추가한다.
- `side_effect` 는 반드시 코드를 읽고 정하고, 근거를 주석으로 남긴다.
- `tags` 에는 설명에 없는 동의어(한/영, 약어)를 넣는다. 검색 품질은 주로 여기서 오른다.
- `examples` 에 `eval/tool_queries.yaml` 질의를 옮기지 않는다 (평가 오염).

## 평가

```bash
.venv/bin/python scripts/eval_search.py --misses
```

- `eval/tool_queries.yaml`: 평가 질의. **레지스트리를 보지 않은 별도 작성자가 도구 설명만 보고 작성**한다.
- `eval/upstream_tools.snapshot.json`: 평가에 쓰는 upstream 도구 목록 스냅샷.
- 실제 파일이 없으면 `*.example.*` 로 돌아간다.

내부 upstream (도구 28개, 질의 56개 = 도구당 2개) 결과 (2026-10-12, 메모리 BM25):

| 구성 | hit@1 | hit@3 | hit@5 | MRR |
|---|---|---|---|---|
| upstream 설명만 | 0.70 | 0.89 | 0.95 | 0.80 |
| + 레지스트리 메타데이터 | **0.82** | **0.98** | **1.00** | **0.90** |

2026-10-14 upstream 에 도구 1개가 추가돼 다시 측정했다 (도구 29개, 질의 58개. 새 도구 질의 2개는 레지스트리를 보지 않은 작성자가 추가).

| 구성 | hit@1 | hit@3 | hit@5 | MRR |
|---|---|---|---|---|
| upstream 설명만 | 0.71 | 0.90 | 0.97 | 0.81 |
| + 레지스트리 메타데이터 | **0.83** | **0.97** | **1.00** | **0.90** |

새 도구 질의 2개는 모두 1위였다. 대신 기존 질의 2개가 한 칸씩 밀렸다 (하나는 3위 → 4위). 도구가 늘면 비슷한 도구끼리 경쟁해 순위가 흔들릴 수 있으므로, 도구를 추가할 때마다 평가를 다시 돌린다.

1위를 놓친 10건은 거의 기능이 겹치는 형제 도구 간 혼동이다 (테이블 목록/컬럼/상세, PR 템플릿/PR 생성 등).
`search_tools` 는 상위 5개를 돌려주므로 정답은 모두 결과 안에 있다. 평가셋에 맞춰 레지스트리를 고치지 않았다 (과적합 방지).

## 검증 현황 (2026-10-12, 2026-10-14 갱신)

**실증**
- 레지스트리 대조: 실제 upstream(HTTP) 도구 28개와 레지스트리 28개가 일치하고 경고는 없었다.
- all 모드 E2E (HTTP·stdio 모두): 도구 30개(28개 + 메타 도구 2개)가 노출되고, annotation 주입, 도구 호출 통과, `search_tools`, 감사 로그가 동작했다.
- dynamic 모드 E2E (HTTP, fastmcp Client)
  - 처음에는 4개(core 2개 + 메타 2개)만 노출된다.
  - `activate_tools` 를 호출하면 `tools/list_changed` 가 수신되고 6개로 늘어난다.
  - 활성화하지 않은 도구를 호출하면 `hidden` 으로 거부된다.
- 정책 E2E: `deny_tools` 에 넣은 도구 호출이 차단되고 감사 로그에 `denied` 로 남는다.
- 타임아웃 E2E (2026-10-14): 실제 upstream 호출이 제한 시간을 넘기면 중단되고(`timeout`), 이어진 다른 호출도 정상 처리된다. upstream 로그에 에러 없음.
- **Claude Code (2.1.296) dynamic 모드 (2026-10-14)**: `claude -p --strict-mcp-config` 로 stdio 연결.
  - 시작 시 도구 4개가 노출되고 활성화 대상 도구는 목록에 없다.
  - `search_tools` → `activate_tools` 후 Claude Code 가 목록을 다시 받아 새 도구를 로드하고 호출에 성공한다 (감사 로그 `ok`, `hidden` 아님).
- 감사 로그 `tool_error`: satc-mcp-server 는 실패를 MCP 에러가 아니라 `{"status":"error"}` 정상 응답으로 돌려준다. 게이트웨이는 응답을 그대로 전달하고, 감사 로그에만 `tool_error` 로 기록한다 (DB 미연결 상태에서 확인).
- 도구 목록 크기 (JSON 문자 수)

  | 경로 | 도구 수 | 크기 |
  |---|---|---|
  | upstream 직접 | 28 | 18,447 |
  | gateway all | 30 | 21,299 |
  | gateway dynamic | 4 | 2,824 (upstream 대비 약 85% 감소) |
- **인증 E2E (2026-10-14, 로컬 프로세스)**: 실제 upstream 앞에 `static_tokens` 로 HTTP 기동.
  - 올바른 토큰: 도구 목록 조회와 호출 성공, 감사 로그 `client: alice`, 토큰 값은 감사 로그에 없음.
  - 토큰 없음·틀린 토큰: `HTTP 401 {"error": "invalid_token", "error_description": "Authentication required"}`.
  - `/health`: 200 `{"status":"ok"}`.
  - `auth.mode: none` + `--host 0.0.0.0`: 에러 로그와 함께 exit 2 로 기동 거부.
- **Docker E2E (2026-10-14, Docker 27.4 / Apple M4 Pro)**: 이미지 빌드 → 컨테이너가 호스트의 실제 upstream(`host.docker.internal`)에 연결.
  - 컨테이너 사용자 `gateway`, 헬스체크 `healthy`.
  - 위 인증 E2E 와 같은 결과 (올바른 토큰 성공·감사 로그 `client: ci-bot`, 토큰 없음·틀린 토큰 401).
  - `auth.mode: none` 설정 컨테이너는 exit 2, 설정 파일이 없으면 "설정 파일이 없습니다" 로그와 함께 종료.
  - 처음 빌드한 이미지는 M4 에서 SIGILL(exit 132)로 죽었고 `OPENSSL_armcap=0` 으로 해결했다.
- **satc-idp 연동 E2E (2026-10-14, 로컬 프로세스: upstream 5599, IdP 5700(DCR 켬), 게이트웨이 5600 `auth.mode: jwt` + `resource_url`)**
  - client_credentials: IdP `/token` 200 (`expires_in` 900, `scope` mcp) → 도구 31개 조회, `get_style_tag_config` 호출 성공, 감사 로그 `client: ci-bot`.
  - 디스커버리 전 과정 (httpx 스크립트): 토큰 없이 `POST /mcp` → 401 + `resource_metadata=".../.well-known/oauth-protected-resource/mcp"` → PRM 200 → IdP 메타데이터 200 → DCR 201 → `/authorize` 로그인 폼 → 303 (state·`iss` 일치) → `/token` 200 (`aud=.../mcp`, refresh 발급) → 게이트웨이 도구 31개·호출 성공. 감사 로그 `client: <dcr client_id> (<사용자 id>)`.
  - mcp SDK `OAuthClientProvider` (브라우저 단계만 스크립트로 대체): PRM·AS 메타데이터·DCR·PKCE·토큰 교환을 SDK 가 직접 수행해 도구 31개·호출 성공. `resource=http://127.0.0.1:5600/mcp`.
  - Claude Code 2.1.296 (`--strict-mcp-config`, HTTP): bearer 헤더(client_credentials 토큰)로 도구 호출 성공. 토큰 없이 연결하면 서버 상태 `needs-auth` (401 인가 요구를 인식).
  - 로그(게이트웨이·IdP·감사)에서 client secret·비밀번호·JWT 문자열 0건.
- 단위 테스트 42개 (`uv run pytest`): 메모리 upstream 으로 노출·정책·확인(승인/거절/취소/미지원 fallback)·타임아웃·감사·세션 분리·prefix 를 검증한다. 인증은 게이트웨이를 uvicorn 으로 띄워 정적 토큰(성공/없음/틀림 → 401)·JWT(fastmcp `RSAKeyPair` 로 발급, 잘못된 audience·다른 키 → 401)·감사 `client`·노출 가드를 검증한다. `test_oauth.py` 는 IdP 와 같은 모양의 토큰(`typ=at+jwt`, kid, RS256)과 HTTP 로 내려주는 JWKS 로 성공·잘못된 aud/iss·만료·다른 키·스코프 없음·`alg=none` → 401, 401 의 `resource_metadata` 와 PRM 문서를 검증한다 (RFC 9728 경로 보정을 끄면 실패). 정책 차단·노출 필터·확인 절차·인증 provider 를 일부러 끄면 해당 테스트가 실패하는 것도 확인했다.

**부분 실증**
- Claude Code `confirm` (2026-10-14): Claude Code 는 elicitation 지원을 광고하고, 게이트웨이의 확인 요청을 받는다. headless(`-p`) 에서는 응답할 사람이 없어 `cancel` 로 돌아오고 도구는 실행되지 않는다 (안전하게 실패). 대화형 세션에서 사용자가 승인하는 흐름은 아직 확인하지 않았다.
- 여러 upstream + prefix: 단위 테스트로만 확인했다. 실제 upstream 은 하나뿐이다.

**미검증**
- Cursor 의 `tools/list_changed`·elicitation 지원. Cursor 를 쓰는 환경이면 dynamic·confirm 을 켜기 전에 확인한다.
- `exec`·`external`·`write` 도구를 게이트웨이를 거쳐 실제로 실행하는 것. 부작용이 있어 E2E 대상에서 뺐다.
- Claude Code·Cursor 대화형 OAuth 로그인 (브라우저로 IdP 로그인 → 토큰 저장). headless 에서는 `needs-auth` 까지만 확인했다.
- 운영 IdP·게이트웨이를 https 로 띄운 구성 (로컬 http 로만 확인).
- TLS. 게이트웨이는 평문 HTTP 를 연다. 외부에 열 때는 앞단(리버스 프록시·인그레스)에서 TLS 를 종료해야 한다.
- docker-compose 예시 전체 기동 (upstream 이미지가 placeholder 라 실행해 보지 않았다). 게이트웨이 컨테이너 단독 실행은 실증.
- x86 서버에서의 이미지 동작 (arm64 에서만 빌드·실행).
- Cursor 를 HTTP + 토큰으로 게이트웨이에 연결하는 것.

**주의**: 게이트웨이는 MCP 도구 호출만 중계한다. upstream 이 MCP 와 별개로 HTTP 엔드포인트(웹훅 등)를 직접 열면, 그 경로는 게이트웨이의 인증·정책·감사를 거치지 않는다. 그런 엔드포인트는 upstream 쪽에서 따로 보호해야 한다.

## 다음 단계 후보

- Cursor 에서 dynamic 모드·confirm 확인. Claude Code 대화형 세션에서 confirm 승인 흐름 확인.
- 운영 배포 위치 결정 후 IdP·게이트웨이 https 구성, 대화형 Claude Code OAuth 로그인 확인.
- 감사 로그로 도구 사용 빈도와 실패율을 본다. `core` 선정과 레지스트리 보강의 근거로 쓴다.
- 도구가 50개를 넘거나 여러 서버를 묶으면, 별도 문서 검색 서비스의 하이브리드 색인(BM25 + 임베딩, RRF)을 쓰는 `ToolSearcher` 구현을 추가한다.
