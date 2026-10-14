"""정상 흐름: discovery, JWKS, 세 가지 grant, revoke, userinfo, DCR"""

import base64
import os
import stat

from joserfc import jwt
from joserfc.jwk import KeySet

from conftest import AUDIENCE, REDIRECT


def _verify(idp, token, audience=AUDIENCE):
    """발급된 JWT 를 /.well-known/jwks.json 공개키로 검증"""
    keys = KeySet.import_key_set(idp.http.get("/.well-known/jwks.json").json())
    decoded = jwt.decode(token, keys, algorithms=["RS256"])
    jwt.JWTClaimsRegistry(
        iss={"essential": True, "value": "http://testserver"},
        aud={"essential": True, "value": audience},
        exp={"essential": True},
    ).validate(decoded.claims)
    return decoded


def test_discovery_and_jwks(idp):
    meta = idp.http.get("/.well-known/oauth-authorization-server").json()
    assert meta["issuer"] == "http://testserver"
    assert meta["token_endpoint"] == "http://testserver/token"
    assert meta["code_challenge_methods_supported"] == ["S256"]
    assert "registration_endpoint" not in meta  # DCR 기본 꺼짐
    # id_token 을 발급하지 않으므로 OIDC discovery 는 두지 않는다 (RFC 8414 만)
    assert idp.http.get("/.well-known/openid-configuration").status_code == 404
    jwks = idp.http.get("/.well-known/jwks.json").json()
    assert len(jwks["keys"]) == 1
    # 공개키만: RSA 개인키 성분이 없어야 한다
    assert not {"d", "p", "q", "dp", "dq", "qi"} & set(jwks["keys"][0])


def test_private_key_file_permissions(idp):
    keystore = idp.config.resolve("keys")
    pems = list(keystore.glob("*.pem"))
    assert pems and all(stat.S_IMODE(os.stat(p).st_mode) == 0o600 for p in pems)
    assert stat.S_IMODE(os.stat(keystore).st_mode) == 0o700


def test_client_credentials_basic_and_post(idp):
    secret = idp.add_confidential()
    basic = base64.b64encode(f"svc:{secret}".encode()).decode()
    r = idp.http.post("/token", data={"grant_type": "client_credentials"}, headers={"Authorization": f"Basic {basic}"})
    assert r.status_code == 200, r.text
    assert r.headers["cache-control"] == "no-store"
    body = r.json()
    assert "refresh_token" not in body
    decoded = _verify(idp, body["access_token"])
    assert decoded.header["typ"] == "at+jwt"
    claims = decoded.claims
    assert claims["sub"] == "svc" and claims["client_id"] == "svc" and claims["scope"] == "mcp"
    assert {"jti", "iat", "nbf", "exp"} <= set(claims)
    assert claims["exp"] - claims["iat"] == 900

    r = idp.http.post("/token", data={"grant_type": "client_credentials", "client_id": "svc", "client_secret": secret,
                                      "resource": "http://other/mcp"})
    assert r.status_code == 200
    _verify(idp, r.json()["access_token"], audience="http://other/mcp")


def test_authorization_code_pkce_and_refresh_rotation(idp):
    user_id = idp.add_user()
    idp.add_public()
    code, verifier, query = idp.get_code()
    assert query["state"] == ["xyz"] and query["iss"] == ["http://testserver"]

    r = idp.exchange(code, verifier)
    assert r.status_code == 200, r.text
    tokens = r.json()
    claims = _verify(idp, tokens["access_token"]).claims
    assert claims["sub"] == user_id and claims["client_id"] == "cli"

    r = idp.refresh(tokens["refresh_token"])
    assert r.status_code == 200, r.text
    rotated = r.json()
    assert rotated["refresh_token"] != tokens["refresh_token"]
    _verify(idp, rotated["access_token"])
    # 회전된 새 토큰은 계속 쓸 수 있다
    assert idp.refresh(rotated["refresh_token"]).status_code == 200


def test_loopback_redirect_any_port_for_public_client(idp):
    idp.add_user()
    idp.add_public()
    code, verifier, _ = idp.get_code(redirect_uri="http://127.0.0.1:51111/callback")
    assert idp.exchange(code, verifier, redirect_uri="http://127.0.0.1:51111/callback").status_code == 200


def test_refresh_can_narrow_scope(idp):
    idp.add_user()
    idp.add_public(scopes=("mcp", "admin"))
    code, verifier, _ = idp.get_code(scope="mcp admin")
    tokens = idp.exchange(code, verifier).json()
    assert tokens["scope"] == "mcp admin"
    narrowed = idp.refresh(tokens["refresh_token"], scope="mcp").json()
    assert narrowed["scope"] == "mcp"


def test_revoke_refresh_token(idp):
    idp.add_user()
    idp.add_public()
    code, verifier, _ = idp.get_code()
    tokens = idp.exchange(code, verifier).json()
    r = idp.http.post("/revoke", data={"token": tokens["refresh_token"], "client_id": "cli"})
    assert r.status_code == 200
    assert idp.refresh(tokens["refresh_token"]).json()["error"] == "invalid_grant"
    # 없는 토큰도 200 (존재 여부를 알려주지 않는다)
    assert idp.http.post("/revoke", data={"token": "nope", "client_id": "cli"}).status_code == 200


def test_userinfo(idp):
    user_id = idp.add_user()
    idp.add_public()
    code, verifier, _ = idp.get_code()
    access = idp.exchange(code, verifier).json()["access_token"]
    r = idp.http.get("/userinfo", headers={"Authorization": f"Bearer {access}"})
    assert r.json() == {"sub": user_id, "preferred_username": "alice"}
    assert idp.http.get("/userinfo", headers={"Authorization": "Bearer garbage"}).status_code == 401


def test_dynamic_client_registration_then_login(make_idp):
    idp = make_idp(dcr={"enabled": True, "default_scopes": ["mcp"]})
    assert idp.http.get("/.well-known/oauth-authorization-server").json()["registration_endpoint"]
    r = idp.http.post("/register", json={"client_name": "Claude Code", "redirect_uris": [REDIRECT],
                                         "token_endpoint_auth_method": "none"})
    assert r.status_code == 201, r.text
    client = r.json()
    assert client["client_id"].startswith("dcr-") and client["scope"] == "mcp"
    assert "client_secret" not in client

    idp.add_user()
    code, verifier, _ = idp.get_code(client_id=client["client_id"])
    assert idp.exchange(code, verifier, client_id=client["client_id"]).status_code == 200


def test_audit_never_contains_secrets(idp):
    secret = idp.add_confidential()
    idp.add_user()
    idp.add_public()
    idp.http.post("/token", data={"grant_type": "client_credentials", "client_id": "svc", "client_secret": secret})
    code, verifier, _ = idp.get_code()
    tokens = idp.exchange(code, verifier).json()
    idp.refresh(tokens["refresh_token"])
    idp.login(*idp.open_login(challenge="x" * 43), password="wrong-password")
    text = (idp.tmp_path / "audit.jsonl").read_text(encoding="utf-8")
    for value in (secret, code, verifier, tokens["refresh_token"], tokens["access_token"], "correct-horse-battery",
                  "wrong-password"):
        assert value not in text
    events = {r["event"] for r in idp.audit()}
    assert {"token_issued", "login_success", "login_failure"} <= events
