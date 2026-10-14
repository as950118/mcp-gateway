"""보안 리뷰(2026-10-14) 발견 사항 회귀 테스트. 테스트 이름 앞 번호는 리뷰 표의 번호"""

import asyncio
import threading
import time
from collections import Counter
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
import yaml
from starlette.testclient import TestClient

from conftest import AUDIENCE, PASSWORD, REDIRECT, make_pkce
from satc_idp.config import IdpConfig, load_config
from satc_idp.security import token_hash

PROXY = "10.0.0.1"


def _login_cookie(idp, request_id):
    name = f"satc_idp_login_{request_id}"
    return name, idp.http.cookies.get(name)


async def _post_login(app, ip, request_id, csrf, cookie, username="alice", password=PASSWORD, headers=None):
    transport = httpx.ASGITransport(app=app, client=(ip, 40000))
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver", cookies=dict([cookie])) as c:
        r = await c.post("/authorize", data={"request_id": request_id, "csrf_token": csrf,
                                             "username": username, "password": password}, headers=headers or {})
        return r.status_code


def _login_from(idp, ip, username="alice", password=PASSWORD, headers=None):
    """ip 에서 새 로그인 폼을 열고 제출한다"""
    request_id, csrf = idp.open_login(challenge=make_pkce()[1])
    cookie = _login_cookie(idp, request_id)
    return asyncio.run(_post_login(idp.app, ip, request_id, csrf, cookie, username, password, headers))


def _count_verifications(monkeypatch):
    import satc_idp.app as app_module

    calls = []
    original = app_module.verify_secret

    def counting(secret_hash, secret):
        calls.append(secret)
        return original(secret_hash, secret)

    monkeypatch.setattr(app_module, "verify_secret", counting)
    return calls


# ------------------------------------------------------------- #1 잠금 경합
def test_01_concurrent_guesses_cannot_exceed_lockout(make_idp, monkeypatch):
    idp = make_idp(lockout={"pair_max_failures": 5, "user_max_failures": 100, "ip_max_failures": 1000,
                            "backoff_after": 1000})
    idp.add_user()
    idp.add_public()
    calls = _count_verifications(monkeypatch)
    request_id, csrf = idp.open_login(challenge=make_pkce()[1])
    cookie = _login_cookie(idp, request_id)

    async def burst(n):
        async def one(i):
            password = PASSWORD if i == n - 1 else f"wrong-{i}"
            return await _post_login(idp.app, "203.0.113.9", request_id, csrf, cookie, password=password)
        return await asyncio.gather(*[one(i) for i in range(n)])

    statuses = Counter(asyncio.run(burst(40)))
    # 비밀번호 검증은 (사용자, IP) 한도 5회를 넘지 않는다 (수정 전: 40회)
    assert len(calls) <= 5, (len(calls), statuses)
    assert statuses[401] + statuses[303] <= 5
    assert idp.db.count_login_failures("pair:alice|203.0.113.9", 900) <= 5


def test_01_reserve_login_attempt_is_atomic(idp):
    results = []
    barrier = threading.Barrier(30)

    def worker():
        barrier.wait()
        results.append(idp.db.reserve_login_attempt({"user:bob": 5}, 900))

    threads = [threading.Thread(target=worker) for _ in range(30)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sum(r is not None for r in results) == 5
    assert idp.db.count_login_failures("user:bob", 900) == 5


# ------------------------------------------------------- #2 X-Forwarded-For
def test_02_xff_ignored_without_trusted_proxy(make_idp):
    idp = make_idp(lockout={"ip_max_failures": 3, "pair_max_failures": 100, "user_max_failures": 100,
                            "backoff_after": 1000})
    idp.add_user()
    idp.add_public()
    statuses = [_login_from(idp, PROXY, username=f"u{i}", password="x" * 12,
                            headers={"X-Forwarded-For": f"1.1.1.{i}"}) for i in range(4)]
    assert statuses == [401, 401, 401, 429]
    assert {e["ip"] for e in idp.audit() if e["event"] == "login_failure"} == {PROXY}


def test_02_trusted_proxy_uses_rightmost_untrusted_address(make_idp):
    idp = make_idp(forwarded_allow_ips=[PROXY],
                   lockout={"ip_max_failures": 3, "pair_max_failures": 100, "user_max_failures": 100,
                            "backoff_after": 1000},
                   dcr={"enabled": True, "default_scopes": ["mcp"], "rate_limit_per_hour": 2})
    idp.add_user()
    idp.add_public()
    # 공격자가 맨 왼쪽 값을 바꿔도, 프록시가 덧붙인 실제 주소(203.0.113.5) 기준으로 센다
    statuses = [_login_from(idp, PROXY, username=f"u{i}", password="x" * 12,
                            headers={"X-Forwarded-For": f"1.1.1.{i}, 203.0.113.5"}) for i in range(4)]
    assert statuses == [401, 401, 401, 429]
    assert {e["ip"] for e in idp.audit() if e["event"] == "login_failure"} == {"203.0.113.5"}

    async def register_all():
        transport = httpx.ASGITransport(app=idp.app, client=(PROXY, 40000))
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as c:
            return [(await c.post("/register", json={"redirect_uris": ["http://127.0.0.1/cb"]},
                                  headers={"X-Forwarded-For": f"9.9.9.{i}, 203.0.113.5"})).status_code
                    for i in range(4)]

    assert asyncio.run(register_all()) == [201, 201, 429, 429]


def test_02_trust_proxy_option_removed(tmp_path):
    raw = {"issuer": "http://127.0.0.1:5700", "allowed_audiences": [AUDIENCE], "trust_proxy": True}
    with pytest.raises(ValueError, match="forwarded_allow_ips"):
        IdpConfig.model_validate(raw)


# ------------------------------------------------- #3 argon2 비용, 속도 제한
def test_03_unknown_client_does_not_run_argon2(idp, monkeypatch):
    calls = _count_verifications(monkeypatch)
    for i in range(5):
        r = idp.http.post("/token", data={"grant_type": "client_credentials", "client_id": f"nope{i}",
                                          "client_secret": "x"})
        assert r.status_code == 401
    assert calls == []


def test_03_token_and_revoke_rate_limited_per_ip(make_idp):
    idp = make_idp(rate_limits={"token_per_minute": 3, "revoke_per_minute": 2, "authorize_per_minute": 100})
    statuses = [idp.http.post("/token", data={"grant_type": "x", "client_id": "nope"}).status_code for _ in range(4)]
    assert statuses == [401, 401, 401, 429]
    statuses = [idp.http.post("/revoke", data={"token": "t", "client_id": "nope"}).status_code for _ in range(3)]
    assert statuses == [401, 401, 429]


def test_03_argon2_concurrency_is_bounded(make_idp, monkeypatch):
    import satc_idp.app as app_module

    idp = make_idp(argon2_max_concurrency=2, rate_limits={"token_per_minute": 1000})
    secret = idp.add_confidential()
    active = [0]
    peak = [0]
    lock = threading.Lock()
    original = app_module.verify_secret

    def slow(secret_hash, value):
        with lock:
            active[0] += 1
            peak[0] = max(peak[0], active[0])
        time.sleep(0.05)
        try:
            return original(secret_hash, value)
        finally:
            with lock:
                active[0] -= 1

    monkeypatch.setattr(app_module, "verify_secret", slow)

    async def burst():
        transport = httpx.ASGITransport(app=idp.app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as c:
            return await asyncio.gather(*[
                c.post("/token", data={"grant_type": "client_credentials", "client_id": "svc", "client_secret": secret})
                for _ in range(8)
            ])

    responses = asyncio.run(burst())
    assert all(r.status_code == 200 for r in responses)
    assert peak[0] <= 2


# ---------------------------------------------------- #4 남의 계정 잠그기
def test_04_attacker_cannot_lock_out_victim_from_other_ip(idp):
    idp.add_user()
    idp.add_public()
    attacker = [_login_from(idp, "198.51.100.66", password="wrong-password") for _ in range(6)]
    # 공격자 IP 에서 그 사용자는 잠기지만
    assert attacker[:5] == [401] * 5 and attacker[5] == 429
    # 다른 IP 의 피해자는 올바른 비밀번호로 로그인할 수 있다 (수정 전: 429)
    assert _login_from(idp, "203.0.113.20") == 303


def test_04_user_wide_backoff_and_hard_limit(make_idp):
    idp = make_idp(lockout={"pair_max_failures": 100, "ip_max_failures": 100, "user_max_failures": 4,
                            "backoff_after": 2, "backoff_base_s": 0.3, "backoff_max_s": 0.3})
    idp.add_user()
    idp.add_public()
    assert _login_from(idp, "192.0.2.1", password="wrong-password") == 401
    assert _login_from(idp, "192.0.2.2", password="wrong-password") == 401
    # 사용자 전체 실패 2회부터 백오프: 바로 다시 시도하면 거부
    assert _login_from(idp, "192.0.2.3") == 429
    time.sleep(0.35)
    assert _login_from(idp, "192.0.2.4", password="wrong-password") == 401
    time.sleep(0.35)
    assert _login_from(idp, "192.0.2.5", password="wrong-password") == 401
    time.sleep(0.35)
    # 사용자 전체 하드 잠금(4회)
    assert _login_from(idp, "192.0.2.6") == 429


# --------------------------------------------- #5 다른 클라이언트의 코드 제출
def test_05_other_client_cannot_burn_or_replay_code(idp):
    idp.add_user()
    idp.add_public()
    idp.add_public("attacker", redirect_uris=("http://127.0.0.1:1/x",))

    def attacker_submit(code):
        return idp.http.post("/token", data={"grant_type": "authorization_code", "code": code,
                                             "client_id": "attacker", "redirect_uri": "http://127.0.0.1:1/x",
                                             "code_verifier": "x" * 43})

    # 아직 교환 전인 코드: 공격자 제출은 실패하고, 정상 교환은 그대로 된다
    code, verifier, _ = idp.get_code()
    assert attacker_submit(code).json()["error"] == "invalid_grant"
    tokens = idp.exchange(code, verifier)
    assert tokens.status_code == 200, tokens.text

    # 교환된 코드를 다른 클라이언트로 다시 내도 피해자 family 는 폐기되지 않는다
    assert attacker_submit(code).json()["error"] == "invalid_grant"
    assert idp.refresh(tokens.json()["refresh_token"]).status_code == 200
    assert not any(e["event"] == "code_reuse" for e in idp.audit())


# ---------------------------------------- #6 비밀번호 변경 시 대기 중인 코드
def test_06_password_change_invalidates_pending_code(idp):
    idp.add_user()
    idp.add_public()
    code, verifier, _ = idp.get_code()
    user_id = idp.db.get_user_by_name("alice")["id"]
    idp.db.revoke_user_tokens(user_id, "password_changed")
    r = idp.exchange(code, verifier)
    assert r.status_code == 400 and r.json()["error"] == "invalid_grant"


# ------------------------------------------------ #7 refresh family 절대 수명
def test_07_refresh_family_has_absolute_lifetime(make_idp):
    idp = make_idp(refresh_family_max_lifetime_s=2)
    idp.add_user()
    idp.add_public()
    code, verifier, _ = idp.get_code()
    first = idp.exchange(code, verifier).json()["refresh_token"]
    row1 = idp.db.get_refresh_token(token_hash(first))
    time.sleep(0.5)
    second = idp.refresh(first).json()["refresh_token"]
    row2 = idp.db.get_refresh_token(token_hash(second))
    # 회전해도 family 만료는 그대로, 토큰 만료는 family 만료를 넘지 않는다
    assert row2["family_expires_at"] == row1["family_expires_at"]
    assert row2["expires_at"] <= row1["family_expires_at"]
    time.sleep(1.7)
    r = idp.refresh(second)
    assert r.status_code == 400 and r.json()["error"] == "invalid_grant"


# ------------------------------------------------------------ #8 DCR 크기
def _dcr_idp(make_idp, **dcr):
    return make_idp(dcr={"enabled": True, "default_scopes": ["mcp"], "rate_limit_per_hour": 1000, **dcr})


def test_08_dcr_size_limits(make_idp):
    idp = _dcr_idp(make_idp, max_body_bytes=4096)
    audit_path = idp.tmp_path / "audit.jsonl"
    assert idp.http.post("/register", json={"redirect_uris": ["http://127.0.0.1/" + "x" * 10_000]}).status_code == 413
    assert idp.http.post("/register", json={"redirect_uris": ["http://127.0.0.1/" + "x" * 2100]}).status_code == 400
    assert idp.http.post("/register", json={"redirect_uris": ["http://127.0.0.1/cb"],
                                            "client_name": "N" * 101}).status_code == 400
    assert idp.http.post("/register", json={"redirect_uris": [f"http://127.0.0.1/{i}" for i in range(11)]}).status_code == 400
    assert audit_path.stat().st_size < 4096


def test_08_dcr_global_cap_and_unused_cleanup(make_idp):
    idp = _dcr_idp(make_idp, max_clients=2, unused_client_ttl_s=1)
    first = idp.http.post("/register", json={"redirect_uris": [REDIRECT]}).json()["client_id"]
    assert idp.http.post("/register", json={"redirect_uris": [REDIRECT]}).status_code == 201
    assert idp.http.post("/register", json={"redirect_uris": [REDIRECT]}).status_code == 503
    time.sleep(1.1)
    # 토큰을 받지 않은 DCR 클라이언트는 정리되어 자리가 난다
    assert idp.http.post("/register", json={"redirect_uris": [REDIRECT]}).status_code == 201
    assert idp.db.get_client(first) is None


# ------------------------------------------------ #9 감사 로그 client_id
def test_09_token_error_logs_sanitized_client_id(idp):
    idp.http.post("/token", data={"grant_type": "x", "client_id": "A" * 1000})
    idp.http.post("/token", data={"grant_type": "x", "client_id": "bad id\n{json}"})
    logged = [e["client_id"] for e in idp.audit() if e["event"] == "token_error"]
    assert logged == ["invalid", "invalid"]


# -------------------------------------------------- #10 DCR 필드 타입
@pytest.mark.parametrize("extra", [
    {"grant_types": [[1]]},
    {"grant_types": "authorization_code"},
    {"grant_types": []},
    {"response_types": "code"},
    {"scope": 123},
    {"client_name": 5},
    {"redirect_uris": [123]},
])
def test_10_dcr_field_types_rejected_not_500(make_idp, extra):
    idp = _dcr_idp(make_idp)
    client = TestClient(idp.app, raise_server_exceptions=False)
    r = client.post("/register", json={"redirect_uris": [REDIRECT], **extra})
    assert r.status_code == 400, r.text


# ------------------------------------------------- #11 로그인 쿠키 재사용
def test_11_login_cookie_never_reuses_received_value(idp):
    idp.add_public()
    idp.http.cookies.set("satc_idp_login", "attacker-fixed", path="/authorize")
    challenge = make_pkce()[1]
    r1 = idp.http.get("/authorize", params=idp.authorize_params(challenge=challenge))
    r2 = idp.http.get("/authorize", params=idp.authorize_params(challenge=challenge))
    c1, c2 = r1.headers["set-cookie"], r2.headers["set-cookie"]
    assert "attacker-fixed" not in c1 + c2
    # 요청마다 이름·값이 다르다
    assert c1.split(";")[0] != c2.split(";")[0]
    assert c1.split("=")[0] != c2.split("=")[0]


def test_11_secure_cookie_uses_host_prefix(tmp_path):
    from conftest import Idp

    idp = Idp(tmp_path, issuer="https://idp.example.com", cookie_secure=True, allow_insecure_issuer=False)
    idp.add_public()
    r = idp.http.get("/authorize", params=idp.authorize_params(challenge=make_pkce()[1]))
    cookie = r.headers["set-cookie"]
    assert cookie.startswith("__Host-satc_idp_login_")
    lowered = cookie.lower()
    assert "secure" in lowered and "path=/;" in lowered and "domain" not in lowered


# ----------------------------------------- #12 /authorize 남용 (state, 속도)
def test_12_long_state_not_echoed(idp):
    idp.add_public()
    r = idp.http.get("/authorize", params=idp.authorize_params(challenge=make_pkce()[1], state="s" * 600))
    assert r.status_code == 303
    query = parse_qs(urlsplit(r.headers["location"]).query)
    assert query["error"] == ["invalid_request"] and "state" not in query
    assert idp.db.count_login_requests() == 0


def test_12_authorize_rate_limited(make_idp):
    idp = make_idp(rate_limits={"authorize_per_minute": 3})
    idp.add_public()
    statuses = [idp.http.get("/authorize", params=idp.authorize_params(challenge=make_pkce()[1])).status_code
                for _ in range(4)]
    assert statuses == [200, 200, 200, 429]


def test_12_pending_login_requests_capped(make_idp):
    idp = make_idp(max_pending_login_requests=2)
    idp.add_public()
    statuses = [idp.http.get("/authorize", params=idp.authorize_params(challenge=make_pkce()[1])).status_code
                for _ in range(3)]
    assert statuses == [200, 200, 503]


# ------------------------------------------------- #13 안전하지 않은 설정
@pytest.mark.parametrize("raw, ok", [
    ({"issuer": "http://idp.example.com"}, False),
    ({"issuer": "https://idp.example.com", "cookie_secure": False}, False),
    ({"issuer": "https://idp.example.com"}, True),
    ({"issuer": "http://127.0.0.1:5700", "cookie_secure": False}, True),
    ({"issuer": "http://localhost:5700"}, True),
])
def test_13_insecure_issuer_rejected(raw, ok):
    data = {"allowed_audiences": [AUDIENCE], **raw}
    if ok:
        IdpConfig.model_validate(data)
    else:
        with pytest.raises(ValueError):
            IdpConfig.model_validate(data)


def test_13_example_config_is_secure():
    path = Path(__file__).resolve().parents[1] / "config" / "idp.example.yaml"
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert raw["cookie_secure"] is True
    config = load_config(str(path))
    assert config.issuer.startswith("https://")


# ----------------------------------------------- #14 DCR localhost·표시
def test_14_dcr_localhost_toggle_and_labels_client(make_idp, tmp_path):
    # allow_localhost: false 면 IP 리터럴 loopback 만
    strict = _dcr_idp(make_idp, allow_localhost=False)
    assert strict.http.post("/register", json={"redirect_uris": ["http://localhost/cb"]}).status_code == 400
    assert strict.http.post("/register", json={"redirect_uris": [REDIRECT]}).status_code == 201
    idp = _dcr_idp(make_idp)
    r = idp.http.post("/register", json={"redirect_uris": [REDIRECT], "client_name": "공식 게이트웨이"})
    assert r.status_code == 201
    page = idp.http.get("/authorize", params=idp.authorize_params(client_id=r.json()["client_id"],
                                                                  challenge=make_pkce()[1]))
    assert "(미검증 클라이언트)" in page.text
    idp.add_public()
    page = idp.http.get("/authorize", params=idp.authorize_params(challenge=make_pkce()[1]))
    assert "(미검증 클라이언트)" not in page.text


# ------------------------------------------- #15 클라이언트별 audience
def test_15_client_audience_restriction(idp):
    secret = idp.add_confidential()
    idp.db._exec("UPDATE clients SET allowed_audiences = ? WHERE client_id = 'svc'", (f'["{AUDIENCE}"]',))

    def token(**extra):
        return idp.http.post("/token", data={"grant_type": "client_credentials", "client_id": "svc",
                                             "client_secret": secret, **extra})

    assert token().status_code == 200
    r = token(resource="http://other/mcp")
    assert r.status_code == 400 and r.json()["error"] == "invalid_target"


def test_15_dcr_audiences_setting(make_idp):
    idp = _dcr_idp(make_idp, audiences=["http://other/mcp"])
    client_id = idp.http.post("/register", json={"redirect_uris": [REDIRECT]}).json()["client_id"]
    assert idp.db.get_client(client_id)["allowed_audiences"] == ["http://other/mcp"]
    idp.add_user()
    params = idp.authorize_params(client_id=client_id, challenge=make_pkce()[1], resource=AUDIENCE)
    r = idp.http.get("/authorize", params=params)
    assert r.status_code == 303
    assert parse_qs(urlsplit(r.headers["location"]).query)["error"] == ["invalid_target"]


# ------------------------------------------------ #17 retired 개인키 삭제
def test_17_retired_private_key_deleted(make_idp):
    idp = make_idp(published_previous_keys=1)
    first = idp.server.keys.ensure_key()
    idp.server.keys.rotate()
    idp.server.keys.rotate()
    keystore = idp.tmp_path / "keys"
    assert not (keystore / f"{first}.pem").exists()
    statuses = {e["kid"]: e["status"] for e in idp.server.keys.list()}
    assert statuses[first] == "retired"
    assert sum(1 for p in keystore.glob("*.pem")) == 2
