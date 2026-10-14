"""
OAuth 2.1 인가 서버

    GET  /.well-known/oauth-authorization-server   RFC 8414 메타데이터
    GET  /.well-known/jwks.json                    공개키
    GET  /authorize                                인가 요청 검증 → 로그인 폼
    POST /authorize                                로그인 → 인가 코드 발급 → redirect_uri 로 이동
    POST /token                                    authorization_code(+PKCE S256) / refresh_token(회전) / client_credentials
    POST /revoke                                   refresh token 폐기 (RFC 7009)
    POST /register                                 동적 클라이언트 등록 (RFC 7591, 기본 꺼짐)
    GET  /userinfo                                 sub, preferred_username
    GET  /health
"""

import asyncio
import base64
import json
import logging
import threading
import time
import uuid
from collections import OrderedDict, deque
from typing import Any, Deque, Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qsl, unquote_plus, urlencode, urlsplit, urlunsplit

from joserfc import jwt
from joserfc.errors import JoseError
from starlette.applications import Starlette
from starlette.concurrency import run_in_threadpool
from starlette.datastructures import FormData
from starlette.middleware import Middleware
from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse, Response
from starlette.routing import Route
from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware

from . import pages
from .audit import Audit
from .config import IdpConfig
from .db import Database
from .keys import ALGORITHM, KeyStore
from .security import (
    constant_time_equals,
    hash_secret,
    is_loopback_redirect,
    is_valid_code_challenge,
    loggable,
    new_token,
    redirect_uri_allowed,
    token_hash,
    verify_pkce_s256,
    verify_secret,
)

logger = logging.getLogger(__name__)

LOGIN_COOKIE_PREFIX = "satc_idp_login_"
DEVICE_COOKIE = "satc_idp_device"
NO_STORE = {"Cache-Control": "no-store", "Pragma": "no-cache"}
AUTH_CODE_GRANTS = {"authorization_code", "refresh_token"}
ALL_GRANTS = {"authorization_code", "refresh_token", "client_credentials"}
MAX_STATE_LENGTH = 512
MAX_URI_LENGTH = 2048
MAX_REDIRECT_URIS = 10
MAX_CLIENT_NAME_LENGTH = 100
MAX_USERNAME_LENGTH = 200


class OAuthError(Exception):
    def __init__(self, error: str, description: str, status: int = 400, headers: Optional[Dict[str, str]] = None):
        super().__init__(description)
        self.error = error
        self.description = description
        self.status = status
        self.headers = headers or {}


def _oauth_error_response(e: OAuthError) -> JSONResponse:
    return JSONResponse(
        {"error": e.error, "error_description": e.description},
        status_code=e.status,
        headers={**NO_STORE, **e.headers},
    )


def _invalid_client(description: str = "클라이언트 인증에 실패했습니다") -> OAuthError:
    return OAuthError("invalid_client", description, 401, {"WWW-Authenticate": 'Basic realm="satc-idp"'})


def _too_many() -> OAuthError:
    return OAuthError("invalid_request", "요청이 너무 많습니다. 잠시 후 다시 시도하세요.", 429, {"Retry-After": "60"})


def _parse_scope(raw: Optional[str]) -> List[str]:
    return list(dict.fromkeys((raw or "").split()))


class RateLimiter:
    """메모리 슬라이딩 윈도우 (단일 인스턴스 전제). key 당 window_s 안에 limit 회까지

    key 는 최근 사용 순서(LRU)로 두고, 앞쪽(가장 오래 안 쓴 key)부터 만료·상한 초과분을 지운다.
    요청마다 전체를 훑지 않으므로 key 가 많아도 O(1) 이다 (상한을 넘으면 가장 오래된 key 의 기록이 사라진다)."""

    MAX_KEYS = 100_000

    def __init__(self, max_keys: Optional[int] = None):
        self._hits: "OrderedDict[str, Deque[float]]" = OrderedDict()
        self._lock = threading.Lock()
        self._max_window = 0.0
        self.max_keys = max_keys or self.MAX_KEYS

    def __len__(self) -> int:
        return len(self._hits)

    def allow(self, key: str, limit: int, window_s: float = 60.0) -> bool:
        now = time.monotonic()
        with self._lock:
            self._max_window = max(self._max_window, window_s)
            hits = self._hits.get(key)
            if hits is None:
                hits = self._hits[key] = deque()
            else:
                self._hits.move_to_end(key)
            while hits and now - hits[0] > window_s:
                hits.popleft()
            allowed = len(hits) < limit
            if allowed:
                hits.append(now)
            while self._hits:
                oldest = next(iter(self._hits.values()))
                if len(self._hits) > self.max_keys or not oldest or now - oldest[-1] > self._max_window:
                    self._hits.popitem(last=False)
                else:
                    break
            return allowed


class IdpServer:
    def __init__(self, config: IdpConfig):
        self.config = config
        self.db = Database(config.resolve(config.db_path))
        self.keys = KeyStore(config.resolve(config.keystore_dir), config.published_previous_keys)
        self.audit = Audit(config.resolve(config.audit_path) if config.audit_path else None)
        self.limiter = RateLimiter()
        # argon2 (64MiB/건) 동시 실행 수 제한. 스레드풀 안에서 잡는다
        self._argon2 = threading.BoundedSemaphore(max(1, config.argon2_max_concurrency))
        # 지금 비밀번호를 검증 중인 사용자 (같은 사용자 동시 검증은 1건만)
        self.inflight_users: Set[str] = set()

    # ------------------------------------------------------------------ 공통
    def client_ip(self, request: Request) -> str:
        # X-Forwarded-For 는 직접 읽지 않는다. 신뢰 프록시 처리는 ProxyHeadersMiddleware 가 request.client 에 반영한다
        return request.client.host if request.client else "unknown"

    def rate_limited(self, name: str, request: Request, limit: int) -> bool:
        return not self.limiter.allow(f"{name}:{self.client_ip(request)}", limit)

    def _verify_sync(self, secret_hash: Optional[str], secret: str) -> bool:
        with self._argon2:
            return verify_secret(secret_hash, secret)

    async def verify(self, secret_hash: Optional[str], secret: str) -> bool:
        return await run_in_threadpool(self._verify_sync, secret_hash, secret)

    def login_cookie(self, request_id: str) -> Tuple[str, str]:
        """(쿠키 이름, path). 로그인 요청마다 다른 이름이라 여러 탭이 동시에 로그인해도 서로 덮지 않는다.
        https 면 __Host- 접두사 (Secure, path=/, Domain 없음 강제)"""
        if self.config.cookie_secure:
            return f"__Host-{LOGIN_COOKIE_PREFIX}{request_id}", "/"
        return f"{LOGIN_COOKIE_PREFIX}{request_id}", "/authorize"

    def device_cookie(self) -> Tuple[str, str]:
        """신뢰 기기 쿠키 (로그인 성공 시 발급). 사용자 전체 백오프·잠금 면제 확인에만 쓴다"""
        if self.config.cookie_secure:
            return f"__Host-{DEVICE_COOKIE}", "/"
        return DEVICE_COOKIE, "/authorize"

    def client_scopes(self, client: Dict[str, Any]) -> List[str]:
        """클라이언트 scope 중 지금 서버 설정에 있는 것만"""
        return [s for s in client["scopes"] if s in self.config.scopes]

    def metadata(self) -> Dict[str, Any]:
        issuer = self.config.issuer
        data = {
            "issuer": issuer,
            "authorization_endpoint": f"{issuer}/authorize",
            "token_endpoint": f"{issuer}/token",
            "jwks_uri": f"{issuer}/.well-known/jwks.json",
            "revocation_endpoint": f"{issuer}/revoke",
            "userinfo_endpoint": f"{issuer}/userinfo",
            "response_types_supported": ["code"],
            "response_modes_supported": ["query"],
            "grant_types_supported": sorted(ALL_GRANTS),
            "code_challenge_methods_supported": ["S256"],
            "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "none"],
            "revocation_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "none"],
            "scopes_supported": self.config.scopes,
            "authorization_response_iss_parameter_supported": True,
        }
        if self.config.dcr.enabled:
            data["registration_endpoint"] = f"{issuer}/register"
        return data

    def client_audiences(self, client: Dict[str, Any]) -> List[str]:
        """설정의 allowed_audiences 와 클라이언트별 허용 목록의 교집합 (설정 순서 유지)"""
        restricted = client.get("allowed_audiences")
        if restricted is None:
            return list(self.config.allowed_audiences)
        return [a for a in self.config.allowed_audiences if a in restricted]

    def resolve_audience(self, resources: List[str], client: Dict[str, Any], bound: Optional[str] = None) -> str:
        """RFC 8707 resource → aud. bound 가 있으면(코드·refresh 에 묶인 값) 같은 값만 허용"""
        if len(resources) > 1:
            raise OAuthError("invalid_target", "resource 는 하나만 지정할 수 있습니다")
        allowed = self.client_audiences(client)
        if bound is not None and bound not in allowed:
            # 코드·refresh 를 받은 뒤 설정이나 클라이언트 허용 목록에서 빠진 aud 는 더 발급하지 않는다
            raise OAuthError("invalid_target", "더 이상 허용되지 않는 resource 입니다")
        if not resources:
            if bound is not None:
                return bound
            if not allowed:
                raise OAuthError("invalid_target", "이 클라이언트가 받을 수 있는 resource 가 없습니다")
            return allowed[0]
        resource = resources[0]
        if resource not in allowed:
            raise OAuthError("invalid_target", "허용되지 않은 resource 입니다")
        if bound is not None and resource != bound:
            raise OAuthError("invalid_target", "처음 요청한 resource 와 다릅니다")
        return resource

    def resolve_scope(self, requested: List[str], allowed: List[str]) -> List[str]:
        if not requested:
            if not allowed:
                raise OAuthError("invalid_scope", "받을 수 있는 scope 가 없습니다")
            return list(allowed)
        extra = [s for s in requested if s not in allowed]
        if extra:
            raise OAuthError("invalid_scope", f"허용되지 않은 scope: {' '.join(extra)[:200]}")
        return requested

    def issue_access_token(self, sub: str, client_id: str, audience: str, scope: List[str]) -> Tuple[str, str]:
        now = int(time.time())
        jti = str(uuid.uuid4())
        claims = {
            "iss": self.config.issuer,
            "sub": sub,
            "aud": audience,
            "exp": now + self.config.access_token_ttl_s,
            "iat": now,
            "nbf": now,
            "jti": jti,
            "client_id": client_id,
            "scope": " ".join(scope),
        }
        key = self.keys.signing_key()
        # RFC 9068 JWT access token
        token = jwt.encode({"alg": ALGORITHM, "kid": key.kid, "typ": "at+jwt"}, claims, key)
        return token, jti

    def token_response(self, sub: str, client: Dict[str, Any], audience: str, scope: List[str], grant: str,
                       family_id: Optional[str] = None, user_id: Optional[str] = None, ip: str = "",
                       family_expires_at: Optional[float] = None) -> JSONResponse:
        access_token, jti = self.issue_access_token(sub, client["client_id"], audience, scope)
        body: Dict[str, Any] = {
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": self.config.access_token_ttl_s,
            "scope": " ".join(scope),
        }
        if family_id and user_id and "refresh_token" in client["grant_types"]:
            refresh = new_token()
            if family_expires_at is None:
                family_expires_at = time.time() + self.config.refresh_family_max_lifetime_s
            self.db.add_refresh_token(token_hash(refresh), family_id, client["client_id"], user_id, " ".join(scope),
                                      audience, self.config.refresh_token_ttl_s, family_expires_at)
            body["refresh_token"] = refresh
        self.db.touch_client(client["client_id"])
        self.audit.log("token_issued", grant=grant, client_id=client["client_id"], sub=sub, aud=audience,
                       scope=body["scope"], jti=jti, refresh_issued="refresh_token" in body, ip=ip)
        return JSONResponse(body, headers=NO_STORE)

    async def authenticate_client(self, request: Request, form: Dict[str, str]) -> Dict[str, Any]:
        """client_secret_basic / client_secret_post / none(공개 클라이언트)"""
        basic_id = basic_secret = None
        header = request.headers.get("authorization", "")
        if header.lower().startswith("basic "):
            try:
                decoded = base64.b64decode(header[6:].strip(), validate=True).decode("utf-8")
                raw_id, sep, raw_secret = decoded.partition(":")
                if not sep:
                    raise ValueError
            except ValueError:
                raise _invalid_client("Authorization 헤더 형식이 잘못되었습니다") from None
            # RFC 6749 2.3.1: id·secret 은 form-urlencoded 된 뒤 Basic 으로 묶인다
            basic_id, basic_secret = unquote_plus(raw_id), unquote_plus(raw_secret)

        form_id = form.get("client_id")
        form_secret = form.get("client_secret")
        if basic_id is not None and form_secret is not None:
            raise OAuthError("invalid_request", "클라이언트 인증 방식은 하나만 사용해야 합니다")
        if basic_id is not None and form_id is not None and form_id != basic_id:
            raise OAuthError("invalid_request", "client_id 가 일치하지 않습니다")

        client_id = basic_id if basic_id is not None else form_id
        secret = basic_secret if basic_id is not None else form_secret
        if not client_id:
            raise _invalid_client("client_id 가 없습니다")
        client = self.db.get_client(client_id)

        if client is None:
            # 없는 클라이언트: argon2 를 돌리지 않고 고정 지연만 둔다 (인증 없는 argon2 비용 증폭 방지).
            # client_id 는 비밀이 아니라 존재 여부가 드러나는 것은 받아들인다
            await asyncio.sleep(self.config.unknown_client_delay_s)
            raise _invalid_client()
        if client["client_type"] == "confidential":
            if not secret or not await self.verify(client["secret_hash"], secret):
                raise _invalid_client()
            return client
        # 공개 클라이언트는 secret 을 보내면 안 된다
        if secret:
            raise _invalid_client("공개 클라이언트는 secret 을 사용하지 않습니다")
        return client


def _redirect_with(uri: str, params: Dict[str, Optional[str]]) -> RedirectResponse:
    parts = urlsplit(uri)
    query = parts.query + ("&" if parts.query else "") + urlencode({k: v for k, v in params.items() if v is not None})
    return RedirectResponse(urlunsplit(parts._replace(query=query)), status_code=303, headers=NO_STORE)


class FormError(Exception):
    def __init__(self, status: int, description: str):
        super().__init__(description)
        self.status = status
        self.description = description


async def _read_form(request: Request, config: IdpConfig) -> FormData:
    """application/x-www-form-urlencoded 본문을 크기·필드 수 제한 안에서 읽는다 (Starlette 기본은 필드당 1MB × 1000)"""
    content_type = request.headers.get("content-type", "").split(";")[0].strip().lower()
    if content_type != "application/x-www-form-urlencoded":
        raise FormError(400, "application/x-www-form-urlencoded 본문이 필요합니다")
    raw = await _read_body_limited(request, config.max_form_bytes)
    if raw is None:
        raise FormError(413, f"요청 본문은 {config.max_form_bytes} 바이트 이하여야 합니다")
    try:
        pairs = parse_qsl(raw.decode("ascii"), keep_blank_values=True, max_num_fields=config.max_form_fields,
                          encoding="utf-8", errors="strict")
    except (UnicodeDecodeError, ValueError):
        raise FormError(400, "form 본문 형식이 잘못되었거나 필드가 너무 많습니다") from None
    return FormData(pairs)


async def _read_body_limited(request: Request, limit: int) -> Optional[bytes]:
    """본문을 limit 바이트까지만 읽는다. 넘으면 None"""
    declared = request.headers.get("content-length")
    if declared is not None:
        try:
            if int(declared) > limit:
                return None
        except ValueError:
            return None
    chunks = bytearray()
    async for chunk in request.stream():
        chunks.extend(chunk)
        if len(chunks) > limit:
            return None
    return bytes(chunks)


def create_app(config: IdpConfig) -> Starlette:
    server = IdpServer(config)
    server.keys.ensure_key()
    server.db.cleanup()
    if config.issuer.startswith("https://") and not config.forwarded_allow_ips:
        logger.warning(
            "issuer 가 https 인데 forwarded_allow_ips 가 비어 있습니다. TLS 리버스 프록시 뒤라면 모든 사용자가 프록시 IP 하나로 "
            "보여 IP 잠금·속도 제한을 함께 받습니다. 프록시 IP 를 forwarded_allow_ips 에 지정하세요"
        )

    async def discovery(request: Request) -> Response:
        return JSONResponse(server.metadata())

    async def jwks(request: Request) -> Response:
        return JSONResponse(server.keys.jwks(), headers={"Cache-Control": "max-age=300"})

    async def health(request: Request) -> Response:
        return JSONResponse({"status": "ok"})

    # ---------------------------------------------------------------- /authorize
    async def authorize_get(request: Request) -> Response:
        if server.rate_limited("authorize", request, config.rate_limits.authorize_per_minute):
            return pages.error_page("요청이 너무 많습니다. 잠시 후 다시 시도하세요.", status=429)
        q = request.query_params
        # client_id·redirect_uri 를 확인하기 전 오류는 redirect 하지 않고 화면으로만 알린다
        for key in ("client_id", "redirect_uri"):
            if len(q.getlist(key)) > 1:
                return pages.error_page(f"{key} 가 여러 번 지정되었습니다")
        client_id = q.get("client_id", "")
        redirect_uri = q.get("redirect_uri", "")
        client = server.db.get_client(client_id) if client_id else None
        if client is None:
            return pages.error_page("등록되지 않은 클라이언트입니다")
        if not redirect_uri_allowed(redirect_uri, client["redirect_uris"], client["client_type"] == "public"):
            return pages.error_page("등록되지 않은 redirect_uri 입니다")

        state = q.get("state")
        if state is not None and len(state) > MAX_STATE_LENGTH:
            # 너무 긴 state 는 돌려주지 않는다
            server.audit.log("authorize_rejected", client_id=client_id, error="invalid_request", reason="state_too_long",
                             ip=server.client_ip(request))
            return _redirect_with(redirect_uri, {"error": "invalid_request",
                                                 "error_description": f"state 는 {MAX_STATE_LENGTH}자 이하여야 합니다",
                                                 "iss": config.issuer})

        def fail(error: str, description: str) -> Response:
            server.audit.log("authorize_rejected", client_id=client_id, error=error, ip=server.client_ip(request))
            return _redirect_with(redirect_uri, {"error": error, "error_description": description, "state": state,
                                                 "iss": config.issuer})

        for key in ("response_type", "scope", "state", "code_challenge", "code_challenge_method"):
            if len(q.getlist(key)) > 1:
                return fail("invalid_request", f"{key} 가 여러 번 지정되었습니다")
        if q.get("response_type") != "code":
            return fail("unsupported_response_type", "response_type=code 만 지원합니다")
        if "authorization_code" not in client["grant_types"]:
            return fail("unauthorized_client", "이 클라이언트는 authorization_code 를 쓸 수 없습니다")
        code_challenge = q.get("code_challenge", "")
        if not code_challenge:
            return fail("invalid_request", "PKCE code_challenge 가 필요합니다")
        if q.get("code_challenge_method") != "S256":
            return fail("invalid_request", "code_challenge_method 는 S256 만 지원합니다")
        if not is_valid_code_challenge(code_challenge):
            return fail("invalid_request", "code_challenge 형식이 잘못되었습니다")
        try:
            scope = server.resolve_scope(_parse_scope(q.get("scope")), server.client_scopes(client))
            audience = server.resolve_audience(q.getlist("resource"), client)
        except OAuthError as e:
            return fail(e.error, e.description)

        server.db.cleanup()
        ip = server.client_ip(request)
        if server.db.count_login_requests(ip) >= config.max_pending_login_requests_per_ip:
            server.audit.log("authorize_rejected", client_id=client_id, error="temporarily_unavailable",
                             reason="too_many_pending_logins_ip", ip=ip)
            return pages.error_page("처리되지 않은 로그인 요청이 너무 많습니다. 잠시 후 다시 시도하세요.", status=429)
        if server.db.count_login_requests() >= config.max_pending_login_requests:
            server.audit.log("authorize_rejected", client_id=client_id, error="temporarily_unavailable",
                             reason="too_many_pending_logins", ip=ip)
            return pages.error_page("지금은 로그인 요청을 받을 수 없습니다. 잠시 후 다시 시도하세요.", status=503)
        request_id = new_token(16)
        csrf_token = new_token(16)
        # 쿠키 값은 매번 새로 만든다 (받은 쿠키 값을 다시 쓰면 공격자가 심은 값으로 바인딩될 수 있다)
        cookie = new_token()
        params = {"client_id": client_id, "redirect_uri": redirect_uri, "state": state, "scope": scope,
                  "audience": audience, "code_challenge": code_challenge}
        server.db.add_login_request(request_id, csrf_token, token_hash(cookie), params, config.login_request_ttl_s, ip=ip)
        response = pages.login_page(request_id, csrf_token, client["name"] or client_id, scope,
                                    unverified=client["registered_via"] == "dcr")
        name, path = server.login_cookie(request_id)
        response.set_cookie(name, cookie, max_age=config.login_request_ttl_s, path=path,
                            httponly=True, secure=config.cookie_secure, samesite="lax")
        return response

    async def authorize_post(request: Request) -> Response:
        if server.rate_limited("authorize", request, config.rate_limits.authorize_per_minute):
            return pages.error_page("요청이 너무 많습니다. 잠시 후 다시 시도하세요.", status=429)
        try:
            form = await _read_form(request, config)
        except FormError as e:
            return pages.error_page(e.description, status=e.status)
        ip = server.client_ip(request)
        request_id = str(form.get("request_id", ""))[:64]
        login = server.db.get_login_request(request_id) if request_id else None
        if login is None:
            return pages.error_page("로그인 요청이 만료되었습니다. 처음부터 다시 시도하세요.")
        cookie_name, cookie_path = server.login_cookie(request_id)
        cookie = request.cookies.get(cookie_name, "")
        csrf = str(form.get("csrf_token", ""))
        if not cookie or not constant_time_equals(token_hash(cookie), login["cookie_hash"]) \
                or not csrf or not constant_time_equals(csrf, login["csrf_token"]):
            server.audit.log("login_rejected", reason="csrf", ip=ip)
            return pages.error_page("잘못된 로그인 요청입니다 (CSRF).", status=403)

        params = login["params"]
        client = server.db.get_client(params["client_id"])
        if client is None:
            return pages.error_page("등록되지 않은 클라이언트입니다")
        username = str(form.get("username", ""))[:MAX_USERNAME_LENGTH]
        password = str(form.get("password", ""))
        log_name = username[:64]

        def again(message: str, status: int) -> Response:
            return pages.login_page(request_id, login["csrf_token"], client["name"] or client["client_id"],
                                    params["scope"], error=message, username=username, status=status,
                                    unverified=client["registered_via"] == "dcr")

        def locked() -> Response:
            server.audit.log("login_failure", username=log_name, reason="locked", client_id=client["client_id"], ip=ip)
            return again("로그인 시도가 너무 많습니다. 잠시 후 다시 시도하세요.", 429)

        # 같은 사용자에 대한 동시 검증은 1건만 (확인과 등록 사이에 await 가 없어 이벤트 루프 안에서 원자적)
        if username in server.inflight_users:
            return locked()
        server.inflight_users.add(username)
        try:
            lock = config.lockout
            pair_key, user_key, ip_key = f"pair:{username}|{ip}", f"user:{username}", f"ip:{ip}"
            user = server.db.get_user_by_name(username)
            # 전에 이 IP 나 이 기기에서 로그인에 성공했으면 사용자 전체 백오프·잠금에서 뺀다
            # (남이 사용자 전체 실패를 쌓아 피해자를 잠그는 것 방지. 쌍·IP 잠금은 그대로)
            device_name, _ = server.device_cookie()
            device = request.cookies.get(device_name, "")
            trusted = server.db.is_known_login(username, ip) or bool(
                user and device and server.db.trusted_device_user(token_hash(device)) == user["id"])
            limits = {pair_key: lock.pair_max_failures, ip_key: lock.ip_max_failures}
            if not trusted:
                limits[user_key] = lock.user_max_failures
            # 검증 전에 실패를 먼저 예약한다 (확인과 기록이 한 트랜잭션: 동시 요청이 한도를 넘지 못한다)
            attempt = server.db.reserve_login_attempt(
                limits, lock.window_s,
                backoff=None if trusted else (user_key, lock.backoff_after, lock.backoff_base_s, lock.backoff_max_s),
                ip=ip, record=[pair_key, user_key, ip_key],
            )
            if attempt is None:
                return locked()

            ok = await server.verify(user["password_hash"] if user else None, password)
            if not ok or user is None or user["disabled"]:
                # 예약한 실패 행이 그대로 실패 기록이 된다
                reason = "disabled" if (ok and user and user["disabled"]) else "bad_credentials"
                server.audit.log("login_failure", username=log_name, reason=reason, client_id=client["client_id"], ip=ip)
                return again("아이디 또는 비밀번호가 올바르지 않습니다.", 401)

            # 로그인 요청은 한 번만 쓴다 (동시 제출 방지)
            if not server.db.delete_login_request(request_id):
                server.db.release_login_attempt(attempt)
                return pages.error_page("로그인 요청이 이미 처리되었습니다.")
            server.db.release_login_attempt(attempt, clear_keys=[pair_key])
            server.db.remember_login(username, ip, lock.trusted_ttl_s)
        finally:
            server.inflight_users.discard(username)

        code = new_token()
        server.db.add_code(token_hash(code), client["client_id"], user["id"], params["redirect_uri"],
                           params["code_challenge"], " ".join(params["scope"]), params["audience"], config.code_ttl_s)
        server.audit.log("login_success", username=log_name, sub=user["id"], client_id=client["client_id"], ip=ip)
        response = _redirect_with(params["redirect_uri"], {"code": code, "state": params["state"], "iss": config.issuer})
        response.delete_cookie(cookie_name, path=cookie_path, secure=config.cookie_secure, httponly=True,
                               samesite="lax")
        # 신뢰 기기 쿠키는 성공할 때마다 새 값 (받은 값을 다시 쓰지 않는다)
        device_value = new_token()
        server.db.add_trusted_device(token_hash(device_value), user["id"], config.lockout.trusted_ttl_s)
        device_name, device_path = server.device_cookie()
        response.set_cookie(device_name, device_value, max_age=config.lockout.trusted_ttl_s, path=device_path,
                            httponly=True, secure=config.cookie_secure, samesite="lax")
        return response

    # ------------------------------------------------------------------- /token
    async def token(request: Request) -> Response:
        ip = server.client_ip(request)
        if server.rate_limited("token", request, config.rate_limits.token_per_minute):
            server.audit.log("token_error", grant="", error="rate_limited", client_id="", ip=ip)
            return _oauth_error_response(_too_many())
        try:
            form_data = await _read_form(request, config)
        except FormError as e:
            server.audit.log("token_error", grant="", error="invalid_request", reason="bad_form", client_id="", ip=ip)
            return _oauth_error_response(OAuthError("invalid_request", e.description, e.status))
        form = {k: str(v) for k, v in form_data.multi_items()}
        grant = form.get("grant_type", "")
        try:
            client = await server.authenticate_client(request, form)
            if grant not in ALL_GRANTS:
                raise OAuthError("unsupported_grant_type", "지원하지 않는 grant_type 입니다")
            if grant not in client["grant_types"]:
                raise OAuthError("unauthorized_client", f"이 클라이언트는 {grant} 를 쓸 수 없습니다")
            resources = form_data.getlist("resource")
            if grant == "client_credentials":
                return _client_credentials(client, form, resources, ip)
            if grant == "authorization_code":
                return _authorization_code(client, form, resources, ip)
            return _refresh_token(client, form, resources, ip)
        except OAuthError as e:
            server.audit.log("token_error", grant=loggable(grant, 32), error=e.error,
                             client_id=loggable(form.get("client_id")), ip=ip)
            return _oauth_error_response(e)

    def _client_credentials(client, form, resources, ip) -> Response:
        if client["client_type"] != "confidential":
            raise OAuthError("unauthorized_client", "client_credentials 는 기밀 클라이언트만 쓸 수 있습니다")
        scope = server.resolve_scope(_parse_scope(form.get("scope")), server.client_scopes(client))
        audience = server.resolve_audience(resources, client)
        return server.token_response(client["client_id"], client, audience, scope, "client_credentials", ip=ip)

    def _authorization_code(client, form, resources, ip) -> Response:
        code = form.get("code", "")
        if not code:
            raise OAuthError("invalid_request", "code 가 없습니다")
        def check(row: Dict[str, Any]) -> Optional[str]:
            if not constant_time_equals(form.get("redirect_uri", ""), row["redirect_uri"]):
                return "redirect_uri"
            if not verify_pkce_s256(form.get("code_verifier", ""), row["code_challenge"]):
                return "pkce"
            return None

        # 이 클라이언트에 발급된 코드만 찾고, redirect_uri·PKCE 를 확인한 뒤에만 사용 처리한다
        # (verifier 없이 코드를 태우거나, 다른 클라이언트로 내서 피해자 family 를 폐기시킬 수 없다)
        row, result = server.db.redeem_code(token_hash(code), client["client_id"], check)
        if result == "missing":
            raise OAuthError("invalid_grant", "유효하지 않은 코드입니다")
        if result == "reused":
            # 정상 교환된 코드를 verifier 까지 가진 쪽이 다시 냈다 = 탈취 가능성. 이 코드로 발급한 refresh token 폐기
            server.db.revoke_family(row["family_id"], "code_reuse")
            server.audit.log("code_reuse", client_id=client["client_id"], sub=row["user_id"], family=row["family_id"], ip=ip)
            raise OAuthError("invalid_grant", "이미 사용한 코드입니다")
        if result == "expired":
            raise OAuthError("invalid_grant", "만료된 코드입니다")
        if result == "redirect_uri":
            raise OAuthError("invalid_grant", "redirect_uri 가 일치하지 않습니다")
        if result == "pkce":
            raise OAuthError("invalid_grant", "PKCE 검증에 실패했습니다")
        user = server.db.get_user(row["user_id"])
        if user is None or user["disabled"]:
            raise OAuthError("invalid_grant", "사용할 수 없는 사용자입니다")
        audience = server.resolve_audience(resources, client, bound=row["audience"])
        # 코드를 받은 뒤 클라이언트·서버 설정에서 빠진 scope 는 주지 않는다
        scope = server.resolve_scope([], [s for s in row["scope"].split() if s in server.client_scopes(client)])
        return server.token_response(user["id"], client, audience, scope, "authorization_code",
                                     family_id=row["family_id"], user_id=user["id"], ip=ip,
                                     family_expires_at=time.time() + config.refresh_family_max_lifetime_s)

    def _refresh_token(client, form, resources, ip) -> Response:
        refresh = form.get("refresh_token", "")
        if not refresh:
            raise OAuthError("invalid_request", "refresh_token 이 없습니다")
        hashed = token_hash(refresh)
        row = server.db.get_refresh_token(hashed)
        if row is None or row["client_id"] != client["client_id"]:
            raise OAuthError("invalid_grant", "유효하지 않은 refresh token 입니다")
        if row["revoked"] or server.db.is_family_revoked(row["family_id"]):
            raise OAuthError("invalid_grant", "폐기된 refresh token 입니다")
        if row["used"] or not server.db.use_refresh_token(hashed):
            # 회전된 토큰이 다시 쓰였다 = 탈취 가능성. family 전체 폐기
            server.db.revoke_family(row["family_id"], "refresh_reuse")
            server.audit.log("refresh_reuse", client_id=client["client_id"], sub=row["user_id"], family=row["family_id"], ip=ip)
            raise OAuthError("invalid_grant", "이미 사용한 refresh token 입니다")
        if row["expires_at"] < time.time():
            raise OAuthError("invalid_grant", "만료된 refresh token 입니다")
        user = server.db.get_user(row["user_id"])
        if user is None or user["disabled"]:
            raise OAuthError("invalid_grant", "사용할 수 없는 사용자입니다")
        # 처음 받은 scope 중 지금도 클라이언트·서버 설정에 있는 것 안에서만
        allowed_scope = [s for s in row["scope"].split() if s in server.client_scopes(client)]
        scope = server.resolve_scope(_parse_scope(form.get("scope")), allowed_scope)
        audience = server.resolve_audience(resources, client, bound=row["audience"])
        # family 절대 만료는 그대로 물려준다 (이전 버전 행은 생성 시각 기준으로 계산)
        family_expires_at = row.get("family_expires_at") or (row["created_at"] + config.refresh_family_max_lifetime_s)
        return server.token_response(user["id"], client, audience, scope, "refresh_token",
                                     family_id=row["family_id"], user_id=user["id"], ip=ip,
                                     family_expires_at=family_expires_at)

    # ------------------------------------------------------------------ /revoke
    async def revoke(request: Request) -> Response:
        ip = server.client_ip(request)
        if server.rate_limited("revoke", request, config.rate_limits.revoke_per_minute):
            return _oauth_error_response(_too_many())
        try:
            form = {k: str(v) for k, v in (await _read_form(request, config)).multi_items()}
        except FormError as e:
            return _oauth_error_response(OAuthError("invalid_request", e.description, e.status))
        try:
            client = await server.authenticate_client(request, form)
        except OAuthError as e:
            return _oauth_error_response(e)
        token_value = form.get("token", "")
        if not token_value:
            return _oauth_error_response(OAuthError("invalid_request", "token 이 없습니다"))
        row = server.db.get_refresh_token(token_hash(token_value))
        # RFC 7009: 없는 토큰·다른 클라이언트의 토큰도 200 으로 응답한다 (존재 여부를 알려주지 않음)
        if row is not None and row["client_id"] == client["client_id"]:
            server.db.revoke_family(row["family_id"], "revoked_by_client")
            server.audit.log("revoke", client_id=client["client_id"], sub=row["user_id"], family=row["family_id"], ip=ip)
        return Response(status_code=200, headers=NO_STORE)

    # ---------------------------------------------------------------- /register
    async def register(request: Request) -> Response:
        dcr = config.dcr
        if not dcr.enabled:
            return JSONResponse({"error": "invalid_request", "error_description": "동적 클라이언트 등록이 꺼져 있습니다"},
                                status_code=404, headers=NO_STORE)
        ip = server.client_ip(request)
        if server.db.count_registrations(ip, 3600) >= dcr.rate_limit_per_hour:
            server.audit.log("register_rejected", reason="rate_limited", ip=ip)
            return JSONResponse({"error": "invalid_request", "error_description": "등록 요청이 너무 많습니다"},
                                status_code=429, headers=NO_STORE)
        server.db.add_registration_event(ip)

        def reject(error: str, description: str, status: int = 400) -> Response:
            server.audit.log("register_rejected", reason=error, ip=ip)
            return JSONResponse({"error": error, "error_description": description}, status_code=status, headers=NO_STORE)

        raw = await _read_body_limited(request, dcr.max_body_bytes)
        if raw is None:
            return reject("invalid_client_metadata", f"요청 본문은 {dcr.max_body_bytes} 바이트 이하여야 합니다", 413)
        try:
            body = json.loads(raw)
            if not isinstance(body, dict):
                raise ValueError
        except (ValueError, RecursionError):
            # 깊게 중첩된 JSON 은 RecursionError
            return reject("invalid_client_metadata", "JSON 객체가 필요합니다")

        method = body.get("token_endpoint_auth_method", "none")
        if method != "none":
            return reject("invalid_client_metadata", "공개 클라이언트(token_endpoint_auth_method=none)만 등록할 수 있습니다")
        redirect_uris = body.get("redirect_uris")
        if not isinstance(redirect_uris, list) or not redirect_uris or len(redirect_uris) > MAX_REDIRECT_URIS \
                or not all(isinstance(u, str) and 0 < len(u) <= MAX_URI_LENGTH for u in redirect_uris):
            return reject("invalid_redirect_uri",
                          f"redirect_uris 가 필요합니다 (최대 {MAX_REDIRECT_URIS}개, 각 {MAX_URI_LENGTH}자 이하)")
        for uri in redirect_uris:
            # loopback IP 리터럴은 항상, localhost 는 dcr.allow_localhost 일 때만 (RFC 8252 8.3 은 IP 리터럴을 권한다)
            if not (is_loopback_redirect(uri, allow_localhost=dcr.allow_localhost) or uri in dcr.allowed_redirect_uris):
                hosts = "127.0.0.1, [::1], localhost" if dcr.allow_localhost else "127.0.0.1, [::1]"
                return reject("invalid_redirect_uri",
                              f"loopback({hosts}) 이거나 허용 목록에 있는 redirect_uri 만 쓸 수 있습니다")
        grant_types = body.get("grant_types", ["authorization_code", "refresh_token"])
        if not isinstance(grant_types, list) or not grant_types or not all(isinstance(g, str) for g in grant_types) \
                or not set(grant_types) <= AUTH_CODE_GRANTS or "authorization_code" not in grant_types:
            return reject("invalid_client_metadata", "grant_types 는 authorization_code, refresh_token 만 쓸 수 있습니다")
        grant_types = list(dict.fromkeys(grant_types))
        response_types = body.get("response_types", ["code"])
        if response_types != ["code"]:
            return reject("invalid_client_metadata", "response_types 는 [\"code\"] 만 쓸 수 있습니다")
        raw_scope = body.get("scope")
        if raw_scope is not None and not isinstance(raw_scope, str):
            return reject("invalid_client_metadata", "scope 는 공백으로 구분한 문자열이어야 합니다")
        requested_scope = _parse_scope(raw_scope)
        if any(s not in dcr.default_scopes for s in requested_scope):
            return reject("invalid_client_metadata", "허용되지 않은 scope 입니다")
        scopes = requested_scope or list(dcr.default_scopes)
        name = body.get("client_name")
        if name is not None and (not isinstance(name, str) or len(name) > MAX_CLIENT_NAME_LENGTH):
            return reject("invalid_client_metadata", f"client_name 은 {MAX_CLIENT_NAME_LENGTH}자 이하 문자열이어야 합니다")

        server.db.cleanup_unused_dcr_clients(
            dcr.unused_client_ttl_s, max(dcr.unused_client_ttl_s, config.refresh_family_max_lifetime_s))
        if server.db.count_dcr_clients() >= dcr.max_clients:
            return reject("temporarily_unavailable", "등록된 클라이언트가 너무 많습니다", 503)

        client_id = f"dcr-{new_token(12)}"
        server.db.add_client(client_id, "public", None, redirect_uris, grant_types, scopes, "dcr",
                             name=name or None, allowed_audiences=list(dcr.audiences) or None)
        server.audit.log("register", client_id=client_id, client_name=name, redirect_uris=redirect_uris, ip=ip)
        return JSONResponse(
            {
                "client_id": client_id,
                "client_id_issued_at": int(time.time()),
                "client_name": name,
                "redirect_uris": redirect_uris,
                "grant_types": grant_types,
                "response_types": ["code"],
                "token_endpoint_auth_method": "none",
                "scope": " ".join(scopes),
            },
            status_code=201,
            headers=NO_STORE,
        )

    # ---------------------------------------------------------------- /userinfo
    async def userinfo(request: Request) -> Response:
        header = request.headers.get("authorization", "")
        challenge = {"WWW-Authenticate": 'Bearer error="invalid_token"'}
        if not header.lower().startswith("bearer "):
            return JSONResponse({"error": "invalid_token"}, status_code=401, headers={**NO_STORE, **challenge})
        try:
            decoded = jwt.decode(header[7:].strip(), server.keys.key_set(), algorithms=[ALGORITHM])
            jwt.JWTClaimsRegistry(iss={"essential": True, "value": config.issuer}, exp={"essential": True}) \
                .validate(decoded.claims)
            # 이 서버가 발급한 access token(RFC 9068) 이고 aud 가 지금 허용 목록에 있어야 한다
            if decoded.header.get("typ") != "at+jwt" or decoded.claims.get("aud") not in config.allowed_audiences:
                raise ValueError("not an access token for an allowed audience")
        except (JoseError, ValueError):
            return JSONResponse({"error": "invalid_token"}, status_code=401, headers={**NO_STORE, **challenge})
        user = server.db.get_user(decoded.claims.get("sub", ""))
        if user is None or user["disabled"]:
            return JSONResponse({"error": "invalid_token"}, status_code=401, headers={**NO_STORE, **challenge})
        return JSONResponse({"sub": user["id"], "preferred_username": user["username"]}, headers=NO_STORE)

    routes = [
        Route("/.well-known/oauth-authorization-server", discovery),
        Route("/.well-known/jwks.json", jwks),
        Route("/authorize", authorize_get, methods=["GET"]),
        Route("/authorize", authorize_post, methods=["POST"]),
        Route("/token", token, methods=["POST"]),
        Route("/revoke", revoke, methods=["POST"]),
        Route("/register", register, methods=["POST"]),
        Route("/userinfo", userinfo, methods=["GET"]),
        Route("/health", health),
    ]
    middleware = []
    if config.forwarded_allow_ips:
        # 신뢰 프록시에서 온 요청만 X-Forwarded-For 를 보고, 신뢰하지 않는 가장 오른쪽 값을 클라이언트로 쓴다
        middleware.append(Middleware(ProxyHeadersMiddleware, trusted_hosts=list(config.forwarded_allow_ips)))
    app = Starlette(routes=routes, middleware=middleware)
    app.state.idp = server
    return app


def new_client_secret() -> Tuple[str, str]:
    """(secret, 저장할 해시)"""
    secret = new_token()
    return secret, hash_secret(secret)
