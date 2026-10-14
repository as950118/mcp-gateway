# satc-mcp-gateway

satc-mcp-server 같은 MCP 서버 앞에 두는 게이트웨이. upstream 코드를 고치지 않고 세 가지를 더한다.

| 구성 | 하는 일 | 위치 |
|---|---|---|
| **Tool Registry** | upstream 도구 정의 + 게이트웨이가 관리하는 메타데이터(도메인·부작용·태그·예시·core) | `registry.py`, `config/registry/*.yaml` |
| **도구 검색** | 자연어 질의로 도구 찾기 (`search_tools`). 기본은 메모리 BM25, 인터페이스 교체 가능 | `search.py` |
| **실행 Gateway** | 감사 로그, 부작용·도구별 차단, 타임아웃, 노출 모드(all/dynamic) | `middleware.py` |

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
.venv/bin/satc-mcp-gateway serve --transport http --port 5600     # http

# 검색 결과 확인 (디버깅)
.venv/bin/satc-mcp-gateway search "argo 파드 로그에서 에러 원인"
```

upstream 주소는 `SATC_MCP_SERVER_URL` (기본 `http://localhost:5555/mcp`), 설정 파일은 `-c` 또는 `SATC_GATEWAY_CONFIG`.

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

### 부작용 분류 (`side_effect`)

| 값 | 뜻 | 클라이언트에 붙는 annotation |
|---|---|---|
| `read` | 조회만 (프롬프트·문서 문자열 생성 포함) | `readOnlyHint: true` |
| `write` | 로컬 파일 생성 | `readOnlyHint: false` |
| `exec` | SSH·subprocess 실행 | `readOnlyHint: false`, `openWorldHint: true` |
| `external` | 외부 시스템 상태 변경 (커밋·PR) | `readOnlyHint: false`, `openWorldHint: true` |
| `unknown` | 레지스트리에 없음 | 붙이지 않음 |

분류는 upstream 코드를 읽고 정하고, 근거를 레지스트리 YAML 주석으로 남긴다.

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

1위를 놓친 10건은 거의 기능이 겹치는 형제 도구 간 혼동이다 (테이블 목록/컬럼/상세, PR 템플릿/PR 생성 등).
`search_tools` 는 상위 5개를 돌려주므로 정답은 모두 결과 안에 있다. 평가셋에 맞춰 레지스트리를 고치지 않았다 (과적합 방지).

## 검증 현황 (2026-10-12)

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
- 단위 테스트 23개 (`uv run pytest`): 메모리 upstream 으로 노출·정책·확인(승인/거절/취소/미지원 fallback)·타임아웃·감사·세션 분리·prefix 를 검증한다. 정책 차단·노출 필터·확인 절차를 일부러 끄면 해당 테스트가 실패하는 것도 확인했다.

**부분 실증**
- Claude Code `confirm` (2026-10-14): Claude Code 는 elicitation 지원을 광고하고, 게이트웨이의 확인 요청을 받는다. headless(`-p`) 에서는 응답할 사람이 없어 `cancel` 로 돌아오고 도구는 실행되지 않는다 (안전하게 실패). 대화형 세션에서 사용자가 승인하는 흐름은 아직 확인하지 않았다.
- 여러 upstream + prefix: 단위 테스트로만 확인했다. 실제 upstream 은 하나뿐이다.

**미검증**
- Cursor 의 `tools/list_changed`·elicitation 지원. Cursor 를 쓰는 환경이면 dynamic·confirm 을 켜기 전에 확인한다.
- `exec`·`external`·`write` 도구를 게이트웨이를 거쳐 실제로 실행하는 것. 부작용이 있어 E2E 대상에서 뺐다.
- 운영 배포 (Docker, 인증). 게이트웨이 자체에는 아직 인증이 없다.

## 다음 단계 후보

- Cursor 에서 dynamic 모드·confirm 확인. Claude Code 대화형 세션에서 confirm 승인 흐름 확인.
- 감사 로그로 도구 사용 빈도와 실패율을 본다. `core` 선정과 레지스트리 보강의 근거로 쓴다.
- 도구가 50개를 넘거나 여러 서버를 묶으면, 별도 문서 검색 서비스의 하이브리드 색인(BM25 + 임베딩, RRF)을 쓰는 `ToolSearcher` 구현을 추가한다.
