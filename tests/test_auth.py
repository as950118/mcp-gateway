import asyncio
import json
from contextlib import asynccontextmanager

import httpx
import pytest
import uvicorn
from fastmcp import Client

from satc_gateway.auth import ensure_http_exposure_allowed, is_loopback, parse_static_tokens
from satc_gateway.config import AuthConfig

TOKEN = "alice-token-0123456789"
OTHER = "ci-bot-token-0123456789"


@asynccontextmanager
async def serve_http(gateway):
    """게이트웨이 HTTP 앱을 임의 포트로 띄운다"""
    server = uvicorn.Server(uvicorn.Config(gateway.http_app(), host="127.0.0.1", port=0, log_level="warning"))
    task = asyncio.create_task(server.serve())
    while not server.started:
        await asyncio.sleep(0.01)
    port = server.servers[0].sockets[0].getsockname()[1]
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        server.should_exit = True
        await task


@pytest.fixture
def token_env(monkeypatch):
    monkeypatch.setenv("GATEWAY_TOKENS", f"alice:{TOKEN}, ci-bot:{OTHER}")


def _audit(state):
    path = state.config.resolve(state.config.audit.path)
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def test_parse_static_tokens():
    tokens = parse_static_tokens(f"alice:{TOKEN},ci-bot:{OTHER}")
    assert tokens[TOKEN]["client_id"] == "alice"
    assert tokens[OTHER]["client_id"] == "ci-bot"
    with pytest.raises(ValueError, match="client_id:token"):
        parse_static_tokens("no-separator")
    with pytest.raises(ValueError, match="중복"):
        parse_static_tokens(f"a:{TOKEN},b:{TOKEN}")


def test_static_tokens_without_env_fails(make_gateway, monkeypatch):
    monkeypatch.delenv("GATEWAY_TOKENS", raising=False)
    with pytest.raises(ValueError, match="GATEWAY_TOKENS"):
        make_gateway(auth={"mode": "static_tokens"})


def test_jwt_requires_key_source(make_gateway):
    with pytest.raises(ValueError, match="jwks_uri"):
        make_gateway(auth={"mode": "jwt"})


def test_unauthenticated_exposure_guard():
    assert is_loopback("127.0.0.1") and is_loopback("localhost") and is_loopback("::1")
    assert not is_loopback("0.0.0.0")
    ensure_http_exposure_allowed(AuthConfig(), "127.0.0.1")
    with pytest.raises(ValueError, match="allow_unauthenticated"):
        ensure_http_exposure_allowed(AuthConfig(), "0.0.0.0")
    ensure_http_exposure_allowed(AuthConfig(allow_unauthenticated=True), "0.0.0.0")
    ensure_http_exposure_allowed(AuthConfig(mode="static_tokens"), "0.0.0.0")


async def test_valid_token_can_list_and_call(make_gateway, token_env):
    gateway, state = make_gateway(auth={"mode": "static_tokens"})
    async with serve_http(gateway) as base:
        async with Client(f"{base}/mcp", auth=TOKEN) as client:
            names = {t.name for t in await client.list_tools()}
            result = await client.call_tool("list_db_tables", {"schema_name": "shop"})
    assert "list_db_tables" in names
    assert result.data == ["shop.users", "shop.orders"]
    record = _audit(state)[0]
    assert record["client"] == "alice"
    # 토큰 값은 감사 로그 어디에도 남지 않는다
    assert TOKEN not in json.dumps(record)


@pytest.mark.parametrize("headers", [{}, {"Authorization": "Bearer wrong-token-0123456789"}])
async def test_missing_or_invalid_token_is_401(make_gateway, token_env, headers):
    gateway, state = make_gateway(auth={"mode": "static_tokens"})
    body = {"jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "t", "version": "0"}}}
    async with serve_http(gateway) as base:
        async with httpx.AsyncClient() as http:
            response = await http.post(
                f"{base}/mcp",
                json=body,
                headers={"Accept": "application/json, text/event-stream", **headers},
            )
            health = await http.get(f"{base}/health")
    assert response.status_code == 401
    # 헬스체크는 인증 없이 열려 있다
    assert health.status_code == 200 and health.json() == {"status": "ok"}
    assert not state.config.resolve(state.config.audit.path).exists()


async def test_no_auth_mode_records_no_client(make_gateway):
    gateway, state = make_gateway()
    async with serve_http(gateway) as base:
        async with Client(f"{base}/mcp") as client:
            await client.call_tool("list_db_tables", {"schema_name": "shop"})
    assert _audit(state)[0]["client"] is None


async def test_jwt_mode_with_public_key(make_gateway, monkeypatch):
    from fastmcp.server.auth.providers.jwt import RSAKeyPair

    keys = RSAKeyPair.generate()
    monkeypatch.setenv("GATEWAY_JWT_PUBLIC_KEY", keys.public_key)
    gateway, state = make_gateway(auth={
        "mode": "jwt",
        "public_key_env": "GATEWAY_JWT_PUBLIC_KEY",
        "issuer": "https://idp.example.com",
        "audience": "mcp-gateway",
    })
    good = keys.create_token(subject="user-1", issuer="https://idp.example.com", audience="mcp-gateway")
    wrong_aud = keys.create_token(subject="user-1", issuer="https://idp.example.com", audience="other")
    other_key = RSAKeyPair.generate().create_token(issuer="https://idp.example.com", audience="mcp-gateway")

    async with serve_http(gateway) as base:
        async with Client(f"{base}/mcp", auth=good) as client:
            await client.call_tool("list_db_tables", {"schema_name": "shop"})
        async with httpx.AsyncClient() as http:
            for bad in (wrong_aud, other_key):
                response = await http.post(
                    f"{base}/mcp",
                    json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
                    headers={"Accept": "application/json, text/event-stream", "Authorization": f"Bearer {bad}"},
                )
                assert response.status_code == 401
    assert _audit(state)[0]["client"] == "user-1"
