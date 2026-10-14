"""보안 부정 테스트: 거부돼야 하는 요청이 거부되는지"""

import base64
import time
from urllib.parse import parse_qs, urlsplit

import pytest
from joserfc import jwt
from joserfc.jwk import KeySet

from conftest import AUDIENCE, PASSWORD, REDIRECT, make_pkce


def _error_redirect(response):
    assert response.status_code == 303, response.text
    return parse_qs(urlsplit(response.headers["location"]).query)


# ------------------------------------------------------------------ PKCE
def test_pkce_required(idp):
    idp.add_public()
    r = idp.http.get("/authorize", params=idp.authorize_params())  # code_challenge 없음
    assert _error_redirect(r)["error"] == ["invalid_request"]


def test_pkce_plain_rejected(idp):
    idp.add_public()
    verifier, _ = make_pkce()
    r = idp.http.get("/authorize", params=idp.authorize_params(challenge=verifier[:43], code_challenge_method="plain"))
    assert _error_redirect(r)["error"] == ["invalid_request"]


def test_pkce_verifier_mismatch(idp):
    idp.add_user()
    idp.add_public()
    code, _, _ = idp.get_code()
    other_verifier, _ = make_pkce()
    r = idp.exchange(code, other_verifier)
    assert r.status_code == 400 and r.json()["error"] == "invalid_grant"


def test_pkce_verifier_missing(idp):
    idp.add_user()
    idp.add_public()
    code, _, _ = idp.get_code()
    assert idp.exchange(code, "").json()["error"] == "invalid_grant"


# ------------------------------------------------------------------ 인가 코드
def test_code_reuse_revokes_family(idp):
    idp.add_user()
    idp.add_public()
    code, verifier, _ = idp.get_code()
    tokens = idp.exchange(code, verifier).json()
    r = idp.exchange(code, verifier)
    assert r.json()["error"] == "invalid_grant"
    # 첫 교환으로 받은 refresh token 도 폐기된다
    assert idp.refresh(tokens["refresh_token"]).json()["error"] == "invalid_grant"
    assert "code_reuse" in {e["event"] for e in idp.audit()}


def test_code_expired(make_idp):
    idp = make_idp(code_ttl_s=0)
    idp.add_user()
    idp.add_public()
    code, verifier, _ = idp.get_code()
    time.sleep(0.05)
    assert idp.exchange(code, verifier).json()["error"] == "invalid_grant"


def test_code_redirect_uri_mismatch(idp):
    idp.add_user()
    idp.add_public()
    code, verifier, _ = idp.get_code()
    r = idp.exchange(code, verifier, redirect_uri="http://127.0.0.1:33418/other")
    assert r.json()["error"] == "invalid_grant"


def test_code_bound_to_client(idp):
    idp.add_user()
    idp.add_public()
    idp.add_public(client_id="other")
    code, verifier, _ = idp.get_code()
    assert idp.exchange(code, verifier, client_id="other").json()["error"] == "invalid_grant"


# ------------------------------------------------------------------ redirect_uri
@pytest.mark.parametrize("redirect_uri", [
    "https://evil.example/callback",
    "http://127.0.0.1:33418/callback/../evil",
    "http://127.0.0.1:33418/callback#frag",
    "http://127.0.0.1.evil.example/callback",
])
def test_unregistered_redirect_never_redirected(idp, redirect_uri):
    idp.add_public()
    _, challenge = make_pkce()
    r = idp.http.get("/authorize", params=idp.authorize_params(redirect_uri=redirect_uri, challenge=challenge))
    assert r.status_code == 400 and "location" not in r.headers


def test_unknown_client_not_redirected(idp):
    _, challenge = make_pkce()
    r = idp.http.get("/authorize", params=idp.authorize_params(client_id="ghost", challenge=challenge))
    assert r.status_code == 400 and "location" not in r.headers


def test_confidential_client_loopback_needs_exact_port(idp):
    idp.add_confidential(client_id="web", grants=("authorization_code",), redirect_uris=(REDIRECT,))
    _, challenge = make_pkce()
    r = idp.http.get("/authorize", params=idp.authorize_params(
        client_id="web", redirect_uri="http://127.0.0.1:1234/callback", challenge=challenge))
    assert r.status_code == 400 and "location" not in r.headers


# ------------------------------------------------------------------ 클라이언트 인증
def test_wrong_client_secret(idp):
    idp.add_confidential()
    basic = base64.b64encode(b"svc:wrong").decode()
    r = idp.http.post("/token", data={"grant_type": "client_credentials"}, headers={"Authorization": f"Basic {basic}"})
    assert r.status_code == 401 and r.json()["error"] == "invalid_client"
    assert r.headers["www-authenticate"].startswith("Basic")


def test_confidential_client_without_secret(idp):
    idp.add_confidential()
    r = idp.http.post("/token", data={"grant_type": "client_credentials", "client_id": "svc"})
    assert r.status_code == 401


def test_public_client_cannot_use_client_credentials(idp):
    idp.add_public(grants=("authorization_code", "refresh_token", "client_credentials"))
    r = idp.http.post("/token", data={"grant_type": "client_credentials", "client_id": "cli"})
    assert r.status_code == 400 and r.json()["error"] == "unauthorized_client"


def test_two_auth_methods_rejected(idp):
    secret = idp.add_confidential()
    basic = base64.b64encode(f"svc:{secret}".encode()).decode()
    r = idp.http.post("/token", data={"grant_type": "client_credentials", "client_secret": secret},
                      headers={"Authorization": f"Basic {basic}"})
    assert r.json()["error"] == "invalid_request"


def test_unsupported_grant_type(idp):
    secret = idp.add_confidential()
    r = idp.http.post("/token", data={"grant_type": "password", "client_id": "svc", "client_secret": secret})
    assert r.json()["error"] == "unsupported_grant_type"


# ------------------------------------------------------------------ refresh
def test_refresh_reuse_revokes_family(idp):
    idp.add_user()
    idp.add_public()
    code, verifier, _ = idp.get_code()
    first = idp.exchange(code, verifier).json()["refresh_token"]
    second = idp.refresh(first).json()["refresh_token"]
    # 이미 회전된 토큰을 다시 쓰면 family 전체가 폐기된다
    assert idp.refresh(first).json()["error"] == "invalid_grant"
    assert idp.refresh(second).json()["error"] == "invalid_grant"
    assert "refresh_reuse" in {e["event"] for e in idp.audit()}


def test_refresh_bound_to_client(idp):
    idp.add_user()
    idp.add_public()
    idp.add_public(client_id="other")
    code, verifier, _ = idp.get_code()
    refresh = idp.exchange(code, verifier).json()["refresh_token"]
    assert idp.refresh(refresh, client_id="other").json()["error"] == "invalid_grant"


def test_disabled_user_cannot_refresh(idp):
    idp.add_user()
    idp.add_public()
    code, verifier, _ = idp.get_code()
    refresh = idp.exchange(code, verifier).json()["refresh_token"]
    idp.db.set_user_disabled("alice", True)
    assert idp.refresh(refresh).json()["error"] == "invalid_grant"


# ------------------------------------------------------------------ scope / audience
def test_scope_escalation_authorize(idp):
    idp.add_public(scopes=("mcp",))
    _, challenge = make_pkce()
    r = idp.http.get("/authorize", params=idp.authorize_params(challenge=challenge, scope="mcp admin"))
    assert _error_redirect(r)["error"] == ["invalid_scope"]


def test_scope_escalation_client_credentials(idp):
    secret = idp.add_confidential(scopes=("mcp",))
    r = idp.http.post("/token", data={"grant_type": "client_credentials", "client_id": "svc", "client_secret": secret,
                                      "scope": "admin"})
    assert r.json()["error"] == "invalid_scope"


def test_scope_escalation_refresh(idp):
    idp.add_user()
    idp.add_public(scopes=("mcp", "admin"))
    code, verifier, _ = idp.get_code(scope="mcp")
    refresh = idp.exchange(code, verifier).json()["refresh_token"]
    assert idp.refresh(refresh, scope="mcp admin").json()["error"] == "invalid_scope"


def test_resource_not_allowed(idp):
    secret = idp.add_confidential()
    r = idp.http.post("/token", data={"grant_type": "client_credentials", "client_id": "svc", "client_secret": secret,
                                      "resource": "https://evil.example/mcp"})
    assert r.json()["error"] == "invalid_target"
    idp.add_public()
    _, challenge = make_pkce()
    r = idp.http.get("/authorize", params=idp.authorize_params(challenge=challenge, resource="https://evil.example/mcp"))
    assert _error_redirect(r)["error"] == ["invalid_target"]


def test_resource_cannot_change_at_exchange(idp):
    idp.add_user()
    idp.add_public()
    code, verifier, _ = idp.get_code(resource=AUDIENCE)
    r = idp.exchange(code, verifier, resource="http://other/mcp")
    assert r.json()["error"] == "invalid_target"


# ------------------------------------------------------------------ 로그인
def test_login_lockout(make_idp):
    idp = make_idp(lockout={"window_s": 900, "user_max_failures": 3, "ip_max_failures": 100})
    idp.add_user()
    idp.add_public()
    _, challenge = make_pkce()
    request_id, csrf = idp.open_login(challenge=challenge)
    for _ in range(3):
        assert idp.login(request_id, csrf, password="wrong-password").status_code == 401
    # 잠긴 뒤에는 올바른 비밀번호도 거부한다
    r = idp.login(request_id, csrf, password=PASSWORD)
    assert r.status_code == 429 and "location" not in r.headers


def test_login_ip_lockout(make_idp):
    idp = make_idp(lockout={"window_s": 900, "user_max_failures": 100, "ip_max_failures": 2})
    idp.add_user()
    idp.add_public()
    _, challenge = make_pkce()
    request_id, csrf = idp.open_login(challenge=challenge)
    idp.login(request_id, csrf, username="bob", password="x" * 12)
    idp.login(request_id, csrf, username="carol", password="x" * 12)
    assert idp.login(request_id, csrf).status_code == 429


def test_login_csrf_token_missing_or_wrong(idp):
    idp.add_user()
    idp.add_public()
    _, challenge = make_pkce()
    request_id, csrf = idp.open_login(challenge=challenge)
    assert idp.login(request_id, "").status_code == 403
    assert idp.login(request_id, "forged-token").status_code == 403


def test_login_without_browser_cookie(idp):
    """다른 브라우저(쿠키 없음)에서 request_id·csrf 만 가지고 제출하는 login CSRF"""
    idp.add_user()
    idp.add_public()
    _, challenge = make_pkce()
    request_id, csrf = idp.open_login(challenge=challenge)
    idp.http.cookies.clear()
    assert idp.login(request_id, csrf).status_code == 403


def test_login_request_single_use(idp):
    idp.add_user()
    idp.add_public()
    _, challenge = make_pkce()
    request_id, csrf = idp.open_login(challenge=challenge)
    assert idp.login(request_id, csrf).status_code == 303
    r = idp.login(request_id, csrf)
    assert r.status_code == 400 and "location" not in r.headers


def test_disabled_user_cannot_login(idp):
    idp.add_user()
    idp.db.set_user_disabled("alice", True)
    idp.add_public()
    _, challenge = make_pkce()
    request_id, csrf = idp.open_login(challenge=challenge)
    assert idp.login(request_id, csrf).status_code == 401


def test_login_page_security_headers(idp):
    idp.add_public()
    _, challenge = make_pkce()
    r = idp.http.get("/authorize", params=idp.authorize_params(challenge=challenge))
    assert r.headers["x-frame-options"] == "DENY"
    assert "frame-ancestors 'none'" in r.headers["content-security-policy"]
    assert r.headers["cache-control"] == "no-store"
    cookie = r.headers["set-cookie"].lower()
    assert "httponly" in cookie and "samesite=lax" in cookie


def test_login_page_escapes_client_name(idp):
    idp.db.add_client("xss", "public", None, [REDIRECT], ["authorization_code"], ["mcp"], "test",
                      name="<script>alert(1)</script>")
    _, challenge = make_pkce()
    r = idp.http.get("/authorize", params=idp.authorize_params(client_id="xss", challenge=challenge))
    assert "<script>" not in r.text and "&lt;script&gt;" in r.text


# ------------------------------------------------------------------ DCR
def test_dcr_disabled_by_default(idp):
    r = idp.http.post("/register", json={"redirect_uris": [REDIRECT]})
    assert r.status_code == 404


@pytest.mark.parametrize("body", [
    {"redirect_uris": ["https://evil.example/cb"]},
    {"redirect_uris": [REDIRECT], "token_endpoint_auth_method": "client_secret_basic"},
    {"redirect_uris": [REDIRECT], "grant_types": ["client_credentials"]},
    {"redirect_uris": [REDIRECT], "scope": "admin"},
    {"redirect_uris": []},
])
def test_dcr_rejects_unsafe_metadata(make_idp, body):
    idp = make_idp(dcr={"enabled": True, "default_scopes": ["mcp"]})
    r = idp.http.post("/register", json=body)
    assert r.status_code == 400, r.text


def test_dcr_rate_limited(make_idp):
    idp = make_idp(dcr={"enabled": True, "default_scopes": ["mcp"], "rate_limit_per_hour": 2})
    for _ in range(2):
        assert idp.http.post("/register", json={"redirect_uris": [REDIRECT]}).status_code == 201
    assert idp.http.post("/register", json={"redirect_uris": [REDIRECT]}).status_code == 429


# ------------------------------------------------------------------ 키 교체
def test_key_rotation_keeps_old_tokens_verifiable(make_idp):
    idp = make_idp(published_previous_keys=1)
    secret = idp.add_confidential()

    def issue():
        r = idp.http.post("/token", data={"grant_type": "client_credentials", "client_id": "svc", "client_secret": secret})
        return r.json()["access_token"]

    def verifiable(token):
        keys = KeySet.import_key_set(idp.http.get("/.well-known/jwks.json").json())
        try:
            jwt.decode(token, keys, algorithms=["RS256"])
            return True
        except Exception:
            return False

    old = issue()
    idp.server.keys.rotate()
    new = issue()
    assert jwt.decode(old, idp.server.keys.key_set()).header["kid"] != jwt.decode(new, idp.server.keys.key_set()).header["kid"]
    assert len(idp.http.get("/.well-known/jwks.json").json()["keys"]) == 2
    assert verifiable(old) and verifiable(new)

    # 한 번 더 교체하면 가장 오래된 키는 내려가고, 그 키로 서명한 토큰은 더 이상 검증되지 않는다
    idp.server.keys.rotate()
    assert len(idp.http.get("/.well-known/jwks.json").json()["keys"]) == 2
    assert not verifiable(old) and verifiable(new)


def test_token_signed_by_unknown_key_rejected(idp, tmp_path):
    from joserfc.jwk import RSAKey

    rogue = RSAKey.generate_key(2048, parameters={"kid": idp.server.keys.signing_key().kid}, private=True)
    forged = jwt.encode({"alg": "RS256", "kid": rogue.kid}, {"iss": "http://testserver", "sub": "x",
                                                            "exp": int(time.time()) + 60}, rogue)
    r = idp.http.get("/userinfo", headers={"Authorization": f"Bearer {forged}"})
    assert r.status_code == 401
