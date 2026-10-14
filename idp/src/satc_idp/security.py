"""
보안 유틸리티. 암호 기법은 직접 구현하지 않고 표준 라이브러리·argon2-cffi 를 쓴다.

- 비밀번호·client secret: argon2id (사람이 고르거나 오래 쓰는 비밀)
- 인가 코드·refresh token·로그인 요청 쿠키: secrets 로 만든 256비트 난수 → SHA-256 해시만 저장
  (엔트로피가 충분한 난수라 느린 해시가 필요 없고, 해시로 바로 조회할 수 있다)
"""

import base64
import hashlib
import hmac
import ipaddress
import re
import secrets
from typing import Iterable, Optional
from urllib.parse import urlsplit

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

_hasher = PasswordHasher()  # argon2id, 라이브러리 권장 기본값
# 없는 사용자로 로그인할 때도 검증 시간을 맞추기 위한 더미 해시
_DUMMY_HASH = _hasher.hash(secrets.token_urlsafe(16))

# RFC 7636: code_verifier = 43~128 자의 unreserved 문자
_VERIFIER_RE = re.compile(r"^[A-Za-z0-9\-._~]{43,128}$")
_CHALLENGE_RE = re.compile(r"^[A-Za-z0-9\-_]{43}$")


def new_token(nbytes: int = 32) -> str:
    return secrets.token_urlsafe(nbytes)


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def hash_secret(secret: str) -> str:
    return _hasher.hash(secret)


def verify_secret(secret_hash: Optional[str], secret: str) -> bool:
    """argon2 검증. 해시가 없으면(없는 사용자 등) 더미 해시로 같은 시간을 쓴 뒤 False"""
    try:
        return _hasher.verify(secret_hash or _DUMMY_HASH, secret) and secret_hash is not None
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def constant_time_equals(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


def is_valid_code_challenge(challenge: str) -> bool:
    return bool(_CHALLENGE_RE.match(challenge or ""))


def verify_pkce_s256(verifier: str, challenge: str) -> bool:
    if not verifier or not _VERIFIER_RE.match(verifier):
        return False
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    computed = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return constant_time_equals(computed, challenge)


def is_loopback_redirect(uri: str, allow_localhost: bool = True) -> bool:
    """http://127.0.0.1, http://[::1], http://localhost (RFC 8252 7.3)

    allow_localhost=False 면 IP 리터럴만 허용한다 (RFC 8252 8.3: localhost 는 DNS·hosts 조작 여지가 있다)"""
    try:
        parts = urlsplit(uri)
    except ValueError:
        return False
    if parts.scheme != "http" or not parts.hostname or parts.fragment or parts.username or parts.password:
        return False
    if parts.hostname == "localhost":
        return allow_localhost
    try:
        return ipaddress.ip_address(parts.hostname).is_loopback
    except ValueError:
        return False


def _without_port(uri: str):
    parts = urlsplit(uri)
    return (parts.scheme, parts.hostname, parts.path or "/", parts.query)


def redirect_uri_allowed(requested: str, registered: Iterable[str], public_client: bool) -> bool:
    """등록된 값과 정확히 일치해야 한다.
    공개 클라이언트의 loopback redirect 는 포트만 달라도 허용한다 (RFC 8252 7.3, 네이티브 앱은 임의 포트를 쓴다)."""
    if not requested or "#" in requested:
        return False
    for uri in registered:
        if constant_time_equals(requested, uri):
            return True
        if public_client and is_loopback_redirect(uri) and is_loopback_redirect(requested):
            try:
                if _without_port(requested) == _without_port(uri):
                    return True
            except ValueError:
                continue
    return False


_LOGGABLE_ID_RE = re.compile(r"^[A-Za-z0-9._:@-]{1,128}$")


def loggable(value: object, max_len: int = 128) -> str:
    """신뢰할 수 없는 식별자(client_id, username)를 감사 로그에 넣을 때. 형식이 이상하면 'invalid'"""
    text = str(value) if value is not None else ""
    if not text:
        return ""
    return text if _LOGGABLE_ID_RE.match(text) and len(text) <= max_len else "invalid"
