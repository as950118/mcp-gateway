"""
IdP 설정 (idp.yaml) 로딩
"""

from pathlib import Path
from typing import List, Optional

import ipaddress
from urllib.parse import urlsplit

import yaml
from pydantic import BaseModel, Field, model_validator


class LockoutConfig(BaseModel):
    """로그인 무차별 대입 방어 (window_s 안의 실패 수 기준)

    - (사용자, IP) 쌍: pair_max_failures 회 실패하면 그 IP 에서 그 사용자로는 잠근다 (주 방어선)
    - 사용자 전체: 실패한 **서로 다른 IP 수**가 backoff_after 이상이면 지수 백오프(실패 사이 최소 대기),
      실패 수가 user_max_failures 회면 잠근다. 남이 계정을 잠그는 DoS 가 되지 않도록
      전에 로그인에 성공한 (사용자, IP) 와 신뢰 기기 쿠키는 사용자 전체 백오프·잠금에서 뺀다
    - IP 전체: ip_max_failures 회면 그 IP 를 잠근다 (여러 사용자를 돌려 대입하는 공격)
    """

    window_s: int = 900
    pair_max_failures: int = 5
    user_max_failures: int = 100
    ip_max_failures: int = 20
    # 사용자 전체 백오프를 시작하는 실패 IP 수 (서로 다른 IP)
    backoff_after: int = 10
    backoff_base_s: float = 1.0
    backoff_max_s: float = 60.0
    # 로그인 성공한 (사용자, IP)·기기를 기억하는 기간 (사용자 전체 백오프·잠금 면제)
    trusted_ttl_s: int = 60 * 60 * 24 * 30


class RateLimitConfig(BaseModel):
    """IP 당 분당 요청 수 (인증 없이 부를 수 있는 엔드포인트)"""

    authorize_per_minute: int = 60
    token_per_minute: int = 120
    revoke_per_minute: int = 60


class DcrConfig(BaseModel):
    """동적 클라이언트 등록 (RFC 7591). 공개 클라이언트(token_endpoint_auth_method=none)만 받는다"""

    enabled: bool = False
    # loopback(127.0.0.1/[::1], allow_localhost 면 localhost) 외에 허용할 redirect_uri (정확히 일치)
    allowed_redirect_uris: List[str] = Field(default_factory=list)
    # http://localhost:<포트>/... redirect 허용. Claude Code 등 MCP 클라이언트가 이 형식을 쓴다.
    # RFC 8252 8.3 은 localhost 대신 IP 리터럴을 권한다 (hosts·DNS 조작 여지). 쓰는 클라이언트가 없으면 false
    allow_localhost: bool = True
    # 등록된 클라이언트에 줄 scope (요청한 scope 는 이 안에서만 허용). 없으면 전체 scopes
    default_scopes: Optional[List[str]] = None
    # IP 당 시간당 등록 허용 횟수
    rate_limit_per_hour: int = 10
    # 전체 DCR 클라이언트 상한
    max_clients: int = 1000
    # 등록 뒤 이 시간 동안 토큰을 한 번도 받지 않은 DCR 클라이언트는 지운다.
    # 토큰을 받은 적 있는 클라이언트는 마지막 사용이 refresh_family_max_lifetime_s 보다 오래됐을 때만 지운다
    unused_client_ttl_s: int = 7 * 24 * 3600
    # 등록 요청 본문 최대 크기
    max_body_bytes: int = 16 * 1024
    # DCR 클라이언트가 받을 수 있는 aud. 비어 있으면 allowed_audiences 전체
    audiences: List[str] = Field(default_factory=list)


class IdpConfig(BaseModel):
    # 토큰 iss, discovery 기준 URL. 끝에 / 없이 (예: https://idp.example.com)
    issuer: str
    db_path: str = "../data/idp.sqlite3"
    keystore_dir: str = "../data/keys"
    audit_path: Optional[str] = "../data/audit.jsonl"

    access_token_ttl_s: int = 900
    refresh_token_ttl_s: int = 60 * 60 * 24 * 14
    # refresh family 절대 수명 (최초 로그인 기준). 회전해도 이 시점을 넘기지 않는다
    refresh_family_max_lifetime_s: int = 60 * 60 * 24 * 30
    code_ttl_s: int = 60
    # 로그인 폼 유효 시간
    login_request_ttl_s: int = 600
    # 아직 처리되지 않은 로그인 요청 전체 상한 (GET /authorize 로 DB 를 채우는 것 방지)
    max_pending_login_requests: int = 10000
    # IP 당 처리되지 않은 로그인 요청 상한 (소수 IP 가 전역 상한을 채우는 것 방지)
    max_pending_login_requests_per_ip: int = 20
    # /token, /revoke, POST /authorize 의 form 본문 최대 크기와 필드 수
    max_form_bytes: int = 16 * 1024
    max_form_fields: int = 30

    # 토큰 aud 로 허용할 값 (RFC 8707 resource). 첫 번째가 기본값
    allowed_audiences: List[str]
    # 서버가 아는 scope 전체
    scopes: List[str] = Field(default_factory=lambda: ["mcp"])
    # JWKS 에 함께 게시할 이전 키 수 (키 교체 직후 기존 토큰 검증용)
    published_previous_keys: int = 1

    cookie_secure: bool = True
    # 리버스 프록시 IP (또는 CIDR). 이 주소에서 온 요청만 X-Forwarded-For 를 보고,
    # 그 중 신뢰하지 않는 가장 오른쪽 값을 클라이언트 IP 로 쓴다 (uvicorn ProxyHeadersMiddleware)
    forwarded_allow_ips: List[str] = Field(default_factory=list)
    # issuer 가 https 도 loopback 도 아니어도 기동 (테스트 전용)
    allow_insecure_issuer: bool = False

    # 동시에 돌릴 argon2 검증 수 (메모리 64MiB/건)
    argon2_max_concurrency: int = 4
    # 없는 클라이언트 인증 실패 시 고정 지연 (argon2 를 돌리지 않는다)
    unknown_client_delay_s: float = 0.05

    lockout: LockoutConfig = Field(default_factory=LockoutConfig)
    rate_limits: RateLimitConfig = Field(default_factory=RateLimitConfig)
    dcr: DcrConfig = Field(default_factory=DcrConfig)

    # 설정 파일이 있는 디렉터리 (상대 경로 해석용, 로딩 시 채움)
    base_dir: Path = Field(default_factory=Path.cwd, exclude=True)

    @model_validator(mode="before")
    @classmethod
    def _reject_removed(cls, data):
        if isinstance(data, dict) and data.get("trust_proxy"):
            raise ValueError("trust_proxy 는 없어졌습니다. 리버스 프록시 주소를 forwarded_allow_ips 에 지정하세요")
        if isinstance(data, dict):
            data.pop("trust_proxy", None)
        return data

    @model_validator(mode="after")
    def _check(self):
        self.issuer = self.issuer.rstrip("/")
        if not self.allowed_audiences:
            raise ValueError("allowed_audiences 는 하나 이상 있어야 합니다")
        if self.dcr.default_scopes is None:
            self.dcr.default_scopes = list(self.scopes)
        unknown = set(self.dcr.default_scopes) - set(self.scopes)
        if unknown:
            raise ValueError(f"dcr.default_scopes 에 scopes 에 없는 값이 있습니다: {sorted(unknown)}")
        unknown_aud = set(self.dcr.audiences) - set(self.allowed_audiences)
        if unknown_aud:
            raise ValueError(f"dcr.audiences 에 allowed_audiences 에 없는 값이 있습니다: {sorted(unknown_aud)}")
        if not self.allow_insecure_issuer and not _is_secure_issuer(self.issuer):
            raise ValueError(
                f"issuer 는 https 여야 합니다 (loopback 만 http 허용): {self.issuer}. "
                "테스트 목적이면 allow_insecure_issuer: true"
            )
        if not self.cookie_secure and not _is_loopback_url(self.issuer) and not self.allow_insecure_issuer:
            raise ValueError("cookie_secure: false 는 loopback issuer 에서만 쓸 수 있습니다")
        for entry in self.forwarded_allow_ips:
            if _trusts_everyone(entry):
                raise ValueError(
                    f"forwarded_allow_ips 에 {entry!r} 는 쓸 수 없습니다 (모든 주소를 프록시로 믿으면 X-Forwarded-For 위조로 "
                    "IP 잠금·속도 제한이 무력화된다). 리버스 프록시 IP 나 좁은 CIDR 을 지정하세요"
                )
        return self

    @property
    def default_audience(self) -> str:
        return self.allowed_audiences[0]

    def resolve(self, path: str) -> Path:
        p = Path(path)
        return p if p.is_absolute() else self.base_dir / p


def _is_loopback_url(url: str) -> bool:
    host = urlsplit(url).hostname or ""
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _trusts_everyone(entry: str) -> bool:
    entry = entry.strip()
    if entry == "*":
        return True
    try:
        return ipaddress.ip_network(entry, strict=False).prefixlen == 0
    except ValueError:
        return False


def _is_secure_issuer(url: str) -> bool:
    scheme = urlsplit(url).scheme
    return scheme == "https" or (scheme == "http" and _is_loopback_url(url))


def load_config(path: str) -> IdpConfig:
    config_path = Path(path).resolve()
    raw = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
    config = IdpConfig.model_validate(raw)
    config.base_dir = config_path.parent
    return config
