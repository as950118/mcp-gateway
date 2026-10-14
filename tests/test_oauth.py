"""
auth.mode=jwt + MCP 인가 디스커버리 (RFC 9728)

토큰은 satc-idp 가 발급하는 것과 같은 모양으로 만든다:
헤더 alg=RS256, kid, typ=at+jwt / 클레임 iss, sub, aud, exp, iat, nbf, jti, client_id, scope
JWKS 는 실제 HTTP 로 내려준다 (JWTVerifier 가 httpx 로 받아 간다).
"""

import time
import uuid
from contextlib import asynccontextmanager

import httpx
import pytest
from authlib.jose import JsonWebKey, jwt
from fastmcp import Client
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route

from test_auth import _audit, serve_http

ISSUER = "http://idp.test"
RESOURCE = "http://gw.test/mcp"
ACCEPT = "application/json, text/event-stream"


def make_key(kid: str):
    return JsonWebKey.generate_key("RSA", 2048, is_private=True, options={"kid": kid})


def mint(key, **overrides) -> str:
    now = int(time.time())
    claims = {
        "iss": ISSUER,
        "sub": "user-alice",
        "aud": RESOURCE,
        "exp": now + 900,
        "iat": now,
        "nbf": now,
        "jti": uuid.uuid4().hex,
        "client_id": "claude-code",
        "scope": "mcp",
    }
    claims.update(overrides)
    claims = {k: v for k, v in claims.items() if v is not None}
    header = {"alg": "RS256", "kid": key.as_dict()["kid"], "typ": "at+jwt"}
    return jwt.encode(header, claims, key).decode()


@asynccontextmanager
async def serve_jwks(key):
    public = key.as_dict(is_private=False)
    app = Starlette(routes=[Route("/jwks.json", lambda request: JSONResponse({"keys": [public]}))])

    class _App:  # serve_http 은 gateway.http_app() 을 부르므로 같은 모양으로 감싼다
        def http_app(self):
            return app

    async with serve_http(_App()) as base:
        yield f"{base}/jwks.json"


@pytest.fixture
async def oauth_gateway(make_gateway):
    key = make_key("k1")
    async with serve_jwks(key) as jwks_uri:
        gateway, state = make_gateway(auth={
            "mode": "jwt",
            "jwks_uri": jwks_uri,
            "issuer": ISSUER,
            "resource_url": RESOURCE,
            "required_scopes": ["mcp"],
        })
        async with serve_http(gateway) as base:
            yield key, base, state


async def _ping(http: httpx.AsyncClient, base: str, token: str | None) -> httpx.Response:
    headers = {"Accept": ACCEPT}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return await http.post(f"{base}/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "ping"}, headers=headers)


async def test_idp_shaped_token_is_accepted(oauth_gateway):
    key, base, state = oauth_gateway
    async with Client(f"{base}/mcp", auth=mint(key)) as client:
        result = await client.call_tool("list_db_tables", {"schema_name": "shop"})
    assert result.data == ["shop.users", "shop.orders"]
    # 사용자 로그인 토큰은 client_id 와 sub 를 함께 남긴다
    assert _audit(state)[0]["client"] == "claude-code (user-alice)"


async def test_client_credentials_token_records_client_id(oauth_gateway):
    key, base, state = oauth_gateway
    token = mint(key, sub="ci-bot", client_id="ci-bot")
    async with Client(f"{base}/mcp", auth=token) as client:
        await client.call_tool("list_db_tables", {"schema_name": "shop"})
    assert _audit(state)[0]["client"] == "ci-bot"


@pytest.mark.parametrize(
    "case",
    ["wrong_aud", "wrong_iss", "expired", "other_key", "missing_scope", "alg_none"],
)
async def test_invalid_tokens_are_rejected(oauth_gateway, case):
    key, base, _ = oauth_gateway
    tokens = {
        "wrong_aud": lambda: mint(key, aud="http://other.test/mcp"),
        "wrong_iss": lambda: mint(key, iss="http://evil.test"),
        "expired": lambda: mint(key, exp=int(time.time()) - 10),
        "other_key": lambda: mint(make_key("k1")),  # 같은 kid, 다른 키
        "missing_scope": lambda: mint(key, scope="profile"),
        "alg_none": lambda: _alg_none_token(),
    }
    async with httpx.AsyncClient() as http:
        response = await _ping(http, base, tokens[case]())
    assert response.status_code == 401


def _alg_none_token() -> str:
    import base64
    import json

    def b64(data: dict) -> str:
        return base64.urlsafe_b64encode(json.dumps(data).encode()).rstrip(b"=").decode()

    now = int(time.time())
    return f"{b64({'alg': 'none', 'typ': 'at+jwt'})}.{b64({'iss': ISSUER, 'aud': RESOURCE, 'sub': 'x', 'exp': now + 60, 'scope': 'mcp'})}."


async def test_unauthenticated_request_points_to_resource_metadata(oauth_gateway):
    _, base, _ = oauth_gateway
    async with httpx.AsyncClient() as http:
        response = await _ping(http, base, None)
        assert response.status_code == 401
        challenge = response.headers["www-authenticate"]
        assert challenge.startswith("Bearer")
        # RFC 9728: 경로가 있는 resource 는 well-known 뒤에 경로를 붙인다
        assert 'resource_metadata="http://gw.test/.well-known/oauth-protected-resource/mcp"' in challenge

        # 알린 경로에 실제로 문서가 있어야 한다 (fastmcp 2.11.3 기본값은 여기가 어긋난다)
        for path in ("/.well-known/oauth-protected-resource/mcp", "/.well-known/oauth-protected-resource"):
            metadata = await http.get(f"{base}{path}")
            assert metadata.status_code == 200, path
            body = metadata.json()
            assert body["resource"] == RESOURCE
            # mcp SDK 의 AnyHttpUrl 이 경로 없는 URL 끝에 "/" 를 붙인다 (issuer 는 "/" 없음)
            assert body["authorization_servers"] == [f"{ISSUER}/"]
            assert body["scopes_supported"] == ["mcp"]
            assert body["bearer_methods_supported"] == ["header"]


async def test_resource_url_requires_authorization_server(make_gateway):
    with pytest.raises(ValueError, match="authorization_servers"):
        make_gateway(auth={"mode": "jwt", "jwks_uri": "http://idp.test/jwks.json", "resource_url": RESOURCE})
