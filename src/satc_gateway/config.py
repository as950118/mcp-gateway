"""
게이트웨이 설정 (gateway.yaml) 로딩
"""

import os
import re
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional

import yaml
from pydantic import BaseModel, Field

# 도구의 부작용 분류
#   read     : 조회만 한다 (DB/검색/외부 API 조회, 프롬프트 생성 포함)
#   write    : 로컬 파일을 만든다 (코드 생성, 이미지 다운로드)
#   exec     : 명령을 실행한다 (SSH, 빌드·프로파일링 subprocess)
#   external : 외부 시스템 상태를 바꾼다 (커밋·PR 생성)
#   unknown  : 레지스트리에 등록되지 않은 도구
SideEffect = Literal["read", "write", "exec", "external", "unknown"]
# confirm: 실행 전에 사용자에게 묻는다 (MCP elicitation). 클라이언트가 지원하지 않으면 confirm_fallback
PolicyAction = Literal["allow", "deny", "confirm"]


class UpstreamConfig(BaseModel):
    """게이트웨이 뒤에 붙는 MCP 서버"""

    name: str
    # streamable-http URL (예: http://localhost:5555/mcp). ${ENV} 치환 지원
    url: str
    # 지정하면 도구 이름이 "{prefix}_{name}" 으로 노출된다 (여러 upstream 간 이름 충돌 방지)
    prefix: Optional[str] = None
    # 이 upstream 의 레지스트리 메타데이터 파일 (gateway.yaml 기준 상대 경로)
    registry: Optional[str] = None


class ExposureConfig(BaseModel):
    """클라이언트에 도구를 어떻게 노출할지"""

    # all     : 모든 도구를 그대로 노출 (+ search_tools/activate_tools)
    # dynamic : core 도구 + 세션에서 activate_tools 로 켠 도구만 노출 (tools/list_changed 알림)
    mode: Literal["all", "dynamic"] = "all"
    search_top_k: int = 5


class PolicyConfig(BaseModel):
    """실행 정책"""

    side_effects: Dict[str, PolicyAction] = Field(
        default_factory=lambda: {
            "read": "allow",
            "write": "allow",
            "exec": "allow",
            "external": "allow",
            "unknown": "allow",
        }
    )
    # 부작용 분류와 무관하게 막을 도구 / 확인받을 도구 (노출 이름 기준). deny 가 우선
    deny_tools: List[str] = Field(default_factory=list)
    confirm_tools: List[str] = Field(default_factory=list)
    # confirm 대상인데 클라이언트가 elicitation 을 지원하지 않을 때
    confirm_fallback: Literal["allow", "deny"] = "deny"
    # 부작용 분류별 기본 타임아웃(초)
    timeouts: Dict[str, float] = Field(
        default_factory=lambda: {
            "read": 60,
            "write": 120,
            "exec": 300,
            "external": 120,
            "unknown": 120,
        }
    )
    # 도구별 타임아웃(초), 노출 이름 기준
    tool_timeouts: Dict[str, float] = Field(default_factory=dict)

    def action_for(self, tool_name: str, side_effect: str) -> PolicyAction:
        if tool_name in self.deny_tools:
            return "deny"
        if tool_name in self.confirm_tools:
            return "confirm"
        return self.side_effects.get(side_effect, "allow")

    def timeout_for(self, tool_name: str, side_effect: str) -> Optional[float]:
        if tool_name in self.tool_timeouts:
            return self.tool_timeouts[tool_name]
        return self.timeouts.get(side_effect)


class AuditConfig(BaseModel):
    """감사 로그 (JSON Lines)"""

    # None 이면 감사 로그를 남기지 않는다. gateway.yaml 기준 상대 경로
    path: Optional[str] = "logs/audit.jsonl"
    max_arg_chars: int = 500
    redact_keys: List[str] = Field(
        default_factory=lambda: ["password", "token", "secret", "api_key", "authorization"]
    )


class AuthConfig(BaseModel):
    """HTTP 인증 (stdio 에는 적용하지 않는다). 토큰 값은 설정 파일에 쓰지 않는다"""

    mode: Literal["none", "static_tokens", "jwt"] = "none"
    # none 인데 loopback 이 아닌 주소로 HTTP 를 열려면 명시적으로 true
    allow_unauthenticated: bool = False
    # static_tokens: "client_id:token,client_id:token" 를 담은 환경변수 이름
    tokens_env: str = "GATEWAY_TOKENS"
    # jwt: jwks_uri 또는 public_key_env(PEM 공개키를 담은 환경변수 이름) 중 하나. ${ENV} 치환 지원
    jwks_uri: Optional[str] = None
    public_key_env: Optional[str] = None
    issuer: Optional[str] = None
    audience: Optional[str] = None
    algorithm: str = "RS256"
    required_scopes: List[str] = Field(default_factory=list)


class GatewayConfig(BaseModel):
    name: str = "satc-mcp-gateway"
    upstreams: List[UpstreamConfig]
    exposure: ExposureConfig = Field(default_factory=ExposureConfig)
    policy: PolicyConfig = Field(default_factory=PolicyConfig)
    audit: AuditConfig = Field(default_factory=AuditConfig)
    auth: AuthConfig = Field(default_factory=AuthConfig)
    # upstream 도구 목록을 다시 읽어 레지스트리·검색 인덱스를 갱신하는 주기(초)
    registry_ttl_s: float = 300
    # 설정 파일이 있는 디렉터리 (상대 경로 해석용, 로딩 시 채움)
    base_dir: Path = Field(default_factory=Path.cwd, exclude=True)

    def resolve(self, path: str) -> Path:
        p = Path(path)
        return p if p.is_absolute() else self.base_dir / p


_ENV_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}")


def expand_env(value: str) -> str:
    """${VAR} 또는 ${VAR:-기본값} 치환"""
    return _ENV_RE.sub(lambda m: os.environ.get(m.group(1)) or (m.group(2) or ""), value)


def load_config(path: str | os.PathLike) -> GatewayConfig:
    config_path = Path(path).resolve()
    raw: Dict[str, Any] = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
    for upstream in raw.get("upstreams", []):
        if "url" in upstream:
            upstream["url"] = expand_env(upstream["url"])
    auth = raw.get("auth") or {}
    for key in ("jwks_uri", "issuer", "audience"):
        if isinstance(auth.get(key), str):
            auth[key] = expand_env(auth[key]) or None
    config = GatewayConfig.model_validate(raw)
    config.base_dir = config_path.parent
    return config
