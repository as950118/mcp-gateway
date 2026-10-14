"""2차 보안 리뷰(2026-10-14) 발견 사항 회귀 테스트. 테스트 이름 앞 번호는 리뷰의 N 번호"""

import asyncio
import json
import time
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
import yaml

from conftest import AUDIENCE, PASSWORD, REDIRECT, make_pkce
from satc_idp.app import RateLimiter
from satc_idp.config import IdpConfig, load_config
from satc_idp.security import token_hash


def _base(**overrides):
    return {"issuer": "http://127.0.0.1:5700", "allowed_audiences": [AUDIENCE], **overrides}


async def _login(app, ip, request_id, csrf, cookies, username="alice", password=PASSWORD):
    transport = httpx.ASGITransport(app=app, client=(ip, 40000))
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver", cookies=cookies) as c:
        return await c.post("/authorize", data={"request_id": request_id, "csrf_token": csrf,
                                                "username": username, "password": password})


def _attempt(idp, ip, password=PASSWORD, device=None, username="alice"):
    """ip 에서 새 로그인 폼을 열고 제출한다. device: 신뢰 기기 쿠키 값"""
    request_id, csrf = idp.open_login(challenge=make_pkce()[1])
    name = f"satc_idp_login_{request_id}"
    cookies = {name: idp.http.cookies.get(name)}
    if device:
        cookies["satc_idp_device"] = device
    return asyncio.run(_login(idp.app, ip, request_id, csrf, cookies, username, password))


# ------------------------------------------------- N1 피해자 계정 잠그기
def _n1_idp(make_idp):
    idp = make_idp(lockout={"pair_max_failures": 5, "ip_max_failures": 100, "user_max_failures": 1000,
                            "backoff_after": 3, "backoff_base_s": 60, "backoff_max_s": 60},
                   rate_limits={"authorize_per_minute": 10_000})
    idp.add_user()
    idp.add_public()
    return idp


def test_n1_backoff_counts_distinct_ips(make_idp):
    idp = _n1_idp(make_idp)
    # 같은 IP 2곳에서 여러 번 실패해도 사용자 전체 백오프는 시작되지 않는다 (쌍 잠금이 막는다)
    for ip in ("203.0.113.1", "203.0.113.2"):
        for _ in range(4):
            assert _attempt(idp, ip, password="wrong-password").status_code == 401
    assert _attempt(idp, "198.51.100.9").status_code == 303
    # 서로 다른 IP 3곳이 되면 처음 보는 IP 는 백오프에 걸린다
    assert _attempt(idp, "203.0.113.3", password="wrong-password").status_code == 401
    assert _attempt(idp, "198.51.100.10").status_code == 429


def test_n1_known_ip_and_trusted_device_exempt_from_user_backoff(make_idp):
    idp = _n1_idp(make_idp)
    # 피해자가 한 번 로그인해 두면 (IP 기억 + 기기 쿠키)
    first = _attempt(idp, "198.51.100.7")
    assert first.status_code == 303
    device = first.cookies.get("satc_idp_device")
    assert device and idp.db.trusted_device_user(token_hash(device))
    # 공격자가 여러 IP 로 사용자 전체 백오프를 건다 (서로 다른 IP 3곳부터 백오프라 4번째부터는 429)
    attacker = [_attempt(idp, f"203.0.113.{i + 1}", password="wrong-password").status_code for i in range(6)]
    assert attacker[:3] == [401] * 3 and set(attacker[3:]) == {429}
    assert _attempt(idp, "192.0.2.50").status_code == 429  # 처음 보는 IP·기기: 백오프
    # 전에 성공한 IP 는 면제 (수정 전: 429)
    assert _attempt(idp, "198.51.100.7").status_code == 303
    # 다른 IP 라도 신뢰 기기 쿠키가 있으면 면제
    assert _attempt(idp, "192.0.2.51", device=device).status_code == 303
    # 위조한 기기 쿠키는 면제되지 않는다
    assert _attempt(idp, "192.0.2.52", device="forged-value").status_code == 429


def test_n1_trusted_still_subject_to_pair_lock(make_idp):
    idp = _n1_idp(make_idp)
    assert _attempt(idp, "198.51.100.7").status_code == 303
    # 면제는 사용자 전체 백오프·잠금만. 같은 (사용자, IP) 대입은 쌍 잠금에 걸린다
    statuses = [_attempt(idp, "198.51.100.7", password="wrong-password").status_code for _ in range(6)]
    assert statuses[:5] == [401] * 5 and statuses[5] == 429


def test_n1_hard_lock_exempts_trusted(make_idp):
    idp = make_idp(lockout={"pair_max_failures": 100, "ip_max_failures": 100, "user_max_failures": 3,
                            "backoff_after": 1000}, rate_limits={"authorize_per_minute": 10_000})
    idp.add_user()
    idp.add_public()
    assert _attempt(idp, "198.51.100.7").status_code == 303
    for i in range(3):
        _attempt(idp, f"203.0.113.{i + 1}", password="wrong-password")
    assert _attempt(idp, "192.0.2.9").status_code == 429
    assert _attempt(idp, "198.51.100.7").status_code == 303


def test_n1_password_change_drops_trusted_devices(idp):
    idp.add_user()
    idp.add_public()
    first = _attempt(idp, "198.51.100.7")
    device = first.cookies.get("satc_idp_device")
    user = idp.db.get_user_by_name("alice")
    idp.db.revoke_user_tokens(user["id"], "password_changed")
    assert idp.db.trusted_device_user(token_hash(device)) is None


# ---------------------------------------------- N2 forwarded_allow_ips "*"
@pytest.mark.parametrize("entry", ["*", "0.0.0.0/0", "::/0", " * "])
def test_n2_trust_everyone_rejected(entry):
    with pytest.raises(ValueError, match="forwarded_allow_ips"):
        IdpConfig.model_validate(_base(forwarded_allow_ips=[entry]))


def test_n2_specific_proxy_allowed_and_https_empty_warns(tmp_path, caplog):
    IdpConfig.model_validate(_base(forwarded_allow_ips=["10.0.0.1", "10.0.0.0/8"]))
    raw = {"issuer": "https://idp.example.com", "allowed_audiences": [AUDIENCE], "db_path": "db.sqlite3",
           "keystore_dir": "keys", "audit_path": None}
    (tmp_path / "idp.yaml").write_text(yaml.safe_dump(raw), encoding="utf-8")
    from satc_idp.app import create_app

    with caplog.at_level("WARNING"):
        create_app(load_config(str(tmp_path / "idp.yaml")))
    assert any("forwarded_allow_ips" in r.message for r in caplog.records)


# ------------------------------------------- N3 묶인 aud·scope 재확인
def test_n3_refresh_rechecks_audience_and_scope(idp):
    idp.add_user()
    idp.db.add_client("cli", "public", None, [REDIRECT], ["authorization_code", "refresh_token"], ["mcp", "admin"], "test")
    code, verifier, _ = idp.get_code(resource="http://other/mcp", scope="mcp admin")
    tokens = idp.exchange(code, verifier).json()
    assert tokens["scope"] == "mcp admin"
    # 클라이언트 scope 에서 admin 을 빼면 refresh 로 admin 을 더 받지 못한다
    idp.db._exec("UPDATE clients SET scopes = ? WHERE client_id = 'cli'", (json.dumps(["mcp"]),))
    r = idp.refresh(tokens["refresh_token"])
    assert r.status_code == 200 and r.json()["scope"] == "mcp"
    # 클라이언트 허용 aud 에서 빼면 묶인 aud 로도 더 발급하지 않는다 (수정 전: 200)
    idp.db._exec("UPDATE clients SET allowed_audiences = ? WHERE client_id = 'cli'", (json.dumps([AUDIENCE]),))
    r = idp.refresh(r.json()["refresh_token"])
    assert r.status_code == 400 and r.json()["error"] == "invalid_target"


def test_n3_refresh_with_no_remaining_scope_rejected(idp):
    idp.add_user()
    idp.add_public()
    code, verifier, _ = idp.get_code()
    refresh = idp.exchange(code, verifier).json()["refresh_token"]
    idp.db._exec("UPDATE clients SET scopes = '[]' WHERE client_id = 'cli'")
    r = idp.refresh(refresh)
    assert r.status_code == 400 and r.json()["error"] == "invalid_scope"


def test_n3_code_exchange_rechecks_audience(idp):
    idp.add_user()
    idp.add_public()
    code, verifier, _ = idp.get_code(resource="http://other/mcp")
    idp.db._exec("UPDATE clients SET allowed_audiences = ? WHERE client_id = 'cli'", (json.dumps([AUDIENCE]),))
    r = idp.exchange(code, verifier)
    assert r.status_code == 400 and r.json()["error"] == "invalid_target"


# ------------------------------------------------ N4 깊게 중첩된 JSON
@pytest.mark.parametrize("body", [b"[" * 10000, b'{"client_name": ' + b"[" * 10000 + b"]" * 10000 + b"}"])
def test_n4_deep_json_is_400(make_idp, body):
    idp = make_idp(dcr={"enabled": True, "rate_limit_per_hour": 1000, "max_body_bytes": 64 * 1024})
    r = idp.http.post("/register", content=body, headers={"content-type": "application/json"})
    assert r.status_code == 400 and r.json()["error"] == "invalid_client_metadata"


# --------------------------------------------- N5 PKCE 없이 코드 태우기
def test_n5_wrong_verifier_does_not_burn_code(idp):
    idp.add_user()
    idp.add_public()
    code, verifier, _ = idp.get_code()
    wrong, _ = make_pkce()
    r = idp.exchange(code, wrong)
    assert r.status_code == 400 and "PKCE" in r.json()["error_description"]
    assert idp.exchange(code, verifier, redirect_uri="http://127.0.0.1:1/other").status_code == 400
    # 정상 클라이언트의 교환은 성공한다 (수정 전: "이미 사용한 코드입니다")
    ok = idp.exchange(code, verifier)
    assert ok.status_code == 200
    assert not any(e["event"] == "code_reuse" for e in idp.audit())


def test_n5_reuse_with_verifier_still_revokes_family(idp):
    idp.add_user()
    idp.add_public()
    code, verifier, _ = idp.get_code()
    refresh = idp.exchange(code, verifier).json()["refresh_token"]
    # 사용한 코드를 verifier 없이 다시 내면 폐기하지 않는다 (DoS 방지)
    assert idp.exchange(code, make_pkce()[0]).status_code == 400
    assert idp.refresh(refresh).status_code == 200
    # verifier 까지 가진 쪽의 재사용은 탈취로 보고 family 를 폐기한다
    code2, verifier2, _ = idp.get_code()
    refresh2 = idp.exchange(code2, verifier2).json()["refresh_token"]
    r = idp.exchange(code2, verifier2)
    assert r.status_code == 400 and "이미 사용한" in r.json()["error_description"]
    assert idp.refresh(refresh2).status_code == 400


# -------------------------------------------- N6 IP 당 대기 로그인 요청
def test_n6_pending_login_requests_capped_per_ip(make_idp):
    idp = make_idp(max_pending_login_requests_per_ip=3, rate_limits={"authorize_per_minute": 10_000})
    idp.add_public()
    params = idp.authorize_params(challenge=make_pkce()[1])
    for _ in range(3):
        assert idp.http.get("/authorize", params=params).status_code == 200
    assert idp.http.get("/authorize", params=params).status_code == 429

    async def other_ip():
        transport = httpx.ASGITransport(app=idp.app, client=("198.51.100.2", 40000))
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as c:
            return (await c.get("/authorize", params=params)).status_code

    # 다른 IP 는 영향을 받지 않는다
    assert asyncio.run(other_ip()) == 200


# --------------------------------------------------- N7 form 본문 크기
@pytest.mark.parametrize("path", ["/token", "/revoke", "/authorize"])
def test_n7_large_form_rejected(idp, path):
    r = idp.http.post(path, content=b"a=" + b"x" * (20 * 1024),
                      headers={"content-type": "application/x-www-form-urlencoded"})
    assert r.status_code == 413


def test_n7_too_many_fields_and_wrong_type_rejected(idp):
    many = "&".join(f"f{i}=1" for i in range(100))
    r = idp.http.post("/token", content=many, headers={"content-type": "application/x-www-form-urlencoded"})
    assert r.status_code == 400 and r.json()["error"] == "invalid_request"
    r = idp.http.post("/token", content=b"--x\r\n", headers={"content-type": "multipart/form-data; boundary=x"})
    assert r.status_code == 400


def test_n7_normal_form_still_works(idp):
    secret = idp.add_confidential()
    r = idp.http.post("/token", data={"grant_type": "client_credentials", "client_id": "svc", "client_secret": secret,
                                      "resource": AUDIENCE})
    assert r.status_code == 200


# --------------------------------------------------------- N8 RateLimiter
def test_n8_rate_limiter_is_bounded_and_constant_time():
    limiter = RateLimiter(max_keys=1000)
    for i in range(5000):
        limiter.allow(f"k{i}", 10)
    assert len(limiter) <= 1000
    big = RateLimiter()
    for i in range(100_200):
        big.allow(f"ip:{i}", 10)
    started = time.perf_counter()
    for i in range(200):
        big.allow(f"new:{i}", 10)
    per_call_ms = (time.perf_counter() - started) / 200 * 1000
    # 수정 전: key 10만 개에서 호출당 약 14ms (전체 순회)
    assert per_call_ms < 1.0
    assert len(big) <= RateLimiter.MAX_KEYS


def test_n8_rate_limiter_still_limits():
    limiter = RateLimiter()
    assert [limiter.allow("a", 2) for _ in range(3)] == [True, True, False]


# ------------------------------------------------ N9 DCR 정리, /userinfo
def test_n9_dcr_cleanup_keeps_used_clients(make_idp):
    idp = make_idp(dcr={"enabled": True, "rate_limit_per_hour": 1000, "unused_client_ttl_s": 1},
                   refresh_family_max_lifetime_s=3600)
    idp.add_user()
    used = idp.http.post("/register", json={"redirect_uris": [REDIRECT]}).json()["client_id"]
    unused = idp.http.post("/register", json={"redirect_uris": [REDIRECT]}).json()["client_id"]
    code, verifier, _ = idp.get_code(client_id=used)
    assert idp.exchange(code, verifier, client_id=used).status_code == 200
    time.sleep(1.1)
    assert idp.http.post("/register", json={"redirect_uris": [REDIRECT]}).status_code == 201
    # 토큰을 받은 클라이언트는 refresh family 수명이 지나기 전에는 지우지 않는다 (수정 전: 삭제)
    assert idp.db.get_client(used) is not None
    assert idp.db.get_client(unused) is None


def test_n9_userinfo_checks_typ_and_audience(idp):
    from joserfc import jwt

    idp.add_user()
    idp.add_public()
    code, verifier, _ = idp.get_code()
    access = idp.exchange(code, verifier).json()["access_token"]
    assert idp.http.get("/userinfo", headers={"authorization": f"Bearer {access}"}).status_code == 200
    user = idp.db.get_user_by_name("alice")
    key = idp.server.keys.signing_key()
    now = int(time.time())
    claims = {"iss": idp.config.issuer, "sub": user["id"], "aud": AUDIENCE, "exp": now + 60, "iat": now}
    no_typ = jwt.encode({"alg": "RS256", "kid": key.kid}, claims, key)
    other_aud = jwt.encode({"alg": "RS256", "kid": key.kid, "typ": "at+jwt"}, {**claims, "aud": "http://x/mcp"}, key)
    for token in (no_typ, other_aud):
        assert idp.http.get("/userinfo", headers={"authorization": f"Bearer {token}"}).status_code == 401


# ------------------------------------------- 추가: DCR localhost, 기본 scope
def test_dcr_localhost_allowed_by_default_for_claude_code(make_idp):
    idp = make_idp(dcr={"enabled": True, "rate_limit_per_hour": 1000})
    idp.add_user()
    # Claude Code 는 http://localhost:<임의 포트>/callback 을 쓴다
    r = idp.http.post("/register", json={"redirect_uris": ["http://localhost:53682/callback"]})
    assert r.status_code == 201
    # dcr.default_scopes 를 안 써도 전체 scopes 가 기본값 (수정 전: scope '' → invalid_scope)
    assert r.json()["scope"] == "mcp admin"
    client_id = r.json()["client_id"]
    code, verifier, _ = idp.get_code(client_id=client_id, redirect_uri="http://localhost:53682/callback")
    tokens = idp.exchange(code, verifier, client_id=client_id, redirect_uri="http://localhost:53682/callback")
    assert tokens.status_code == 200
    # 외부 호스트는 여전히 거부
    assert idp.http.post("/register", json={"redirect_uris": ["http://localhost.evil.com/cb"]}).status_code == 400


def test_dcr_default_scopes_follow_global_scopes():
    config = IdpConfig.model_validate(_base(scopes=["mcp", "read"], dcr={"enabled": True}))
    assert config.dcr.default_scopes == ["mcp", "read"]
    config = IdpConfig.model_validate(_base(scopes=["mcp", "read"], dcr={"enabled": True, "default_scopes": ["mcp"]}))
    assert config.dcr.default_scopes == ["mcp"]
