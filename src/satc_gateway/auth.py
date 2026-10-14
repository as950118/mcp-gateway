"""
HTTP 인증 (stdio 는 로컬 프로세스라 인증하지 않는다)

    none           인증 없음. loopback 이 아닌 주소로 띄우려면 allow_unauthenticated: true 가 필요
    static_tokens  환경변수의 "client_id:token,client_id:token" 목록 (fastmcp StaticTokenVerifier)
    jwt            외부 IdP 가 발급한 JWT 를 JWKS 또는 공개키로 검증 (fastmcp JWTVerifier)

토큰 값은 설정 파일에 쓰지 않고 환경변수로만 받는다.
"""

import ipaddress
import logging
import os
from typing import Dict, Optional

from fastmcp.server.auth import AuthProvider, JWTVerifier, StaticTokenVerifier
from fastmcp.server.dependencies import get_access_token

from .config import AuthConfig

logger = logging.getLogger(__name__)

# 이보다 짧은 정적 토큰은 경고한다
MIN_TOKEN_LENGTH = 16


def parse_static_tokens(raw: str) -> Dict[str, Dict[str, object]]:
    """"client_id:token,client_id:token" -> StaticTokenVerifier 용 dict"""
    tokens: Dict[str, Dict[str, object]] = {}
    for item in (raw or "").split(","):
        item = item.strip()
        if not item:
            continue
        client_id, sep, token = item.partition(":")
        if not sep or not client_id.strip() or not token.strip():
            raise ValueError("정적 토큰 형식은 'client_id:token' 이어야 합니다 (쉼표로 여러 개)")
        client_id, token = client_id.strip(), token.strip()
        if token in tokens:
            raise ValueError(f"중복된 토큰이 있습니다 (client_id={client_id})")
        if len(token) < MIN_TOKEN_LENGTH:
            logger.warning("client '%s' 의 토큰이 %d자보다 짧습니다", client_id, MIN_TOKEN_LENGTH)
        tokens[token] = {"client_id": client_id, "scopes": []}
    return tokens


def build_auth_provider(auth: AuthConfig) -> Optional[AuthProvider]:
    if auth.mode == "none":
        return None
    if auth.mode == "static_tokens":
        tokens = parse_static_tokens(os.environ.get(auth.tokens_env, ""))
        if not tokens:
            raise ValueError(f"auth.mode=static_tokens 인데 환경변수 {auth.tokens_env} 에 토큰이 없습니다")
        logger.info("정적 토큰 인증: client %d개", len(tokens))
        return StaticTokenVerifier(tokens=tokens, required_scopes=auth.required_scopes or None)
    # jwt
    if not auth.jwks_uri and not auth.public_key_env:
        raise ValueError("auth.mode=jwt 에는 jwks_uri 또는 public_key_env 가 필요합니다")
    public_key = os.environ.get(auth.public_key_env) if auth.public_key_env else None
    return JWTVerifier(
        jwks_uri=auth.jwks_uri or None,
        public_key=public_key,
        issuer=auth.issuer or None,
        audience=auth.audience or None,
        algorithm=auth.algorithm,
        required_scopes=auth.required_scopes or None,
    )


def is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def ensure_http_exposure_allowed(auth: AuthConfig, host: str) -> None:
    """인증 없이 외부 주소로 여는 것을 막는다"""
    if auth.mode == "none" and not is_loopback(host) and not auth.allow_unauthenticated:
        raise ValueError(
            f"인증 없이(auth.mode=none) {host} 로 HTTP 를 열 수 없습니다. "
            "auth.mode 를 static_tokens/jwt 로 설정하거나, 의도한 것이면 auth.allow_unauthenticated: true 를 지정하세요."
        )


def current_client() -> Optional[str]:
    """현재 요청의 인증된 호출자 (토큰 값은 돌려주지 않는다)"""
    try:
        token = get_access_token()
    except Exception:
        return None
    if token is None:
        return None
    sub = (token.claims or {}).get("sub")
    if sub and sub != token.client_id:
        return f"{token.client_id} ({sub})"
    return token.client_id
