"""
sqlite 저장소 (단일 인스턴스 전제)

비밀 값(비밀번호, client secret, 코드, refresh token, 로그인 쿠키)은 해시만 저장한다.
"""

import json
import os
import sqlite3
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    disabled INTEGER NOT NULL DEFAULT 0,
    created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS clients (
    client_id TEXT PRIMARY KEY,
    client_type TEXT NOT NULL CHECK (client_type IN ('confidential', 'public')),
    secret_hash TEXT,
    name TEXT,
    redirect_uris TEXT NOT NULL,
    grant_types TEXT NOT NULL,
    scopes TEXT NOT NULL,
    registered_via TEXT NOT NULL,
    created_at REAL NOT NULL,
    -- 받을 수 있는 aud (JSON 배열). NULL 이면 설정의 allowed_audiences 전체
    allowed_audiences TEXT,
    -- 마지막 토큰 발급 시각 (안 쓰는 DCR 클라이언트 정리용)
    last_used_at REAL
);
-- 로그인 폼 1건 = 검증을 마친 인가 요청 1건
CREATE TABLE IF NOT EXISTS login_requests (
    id TEXT PRIMARY KEY,
    csrf_token TEXT NOT NULL,
    cookie_hash TEXT NOT NULL,
    params TEXT NOT NULL,
    expires_at REAL NOT NULL,
    -- 요청한 IP (IP 당 대기 요청 상한)
    ip TEXT
);
CREATE TABLE IF NOT EXISTS auth_codes (
    code_hash TEXT PRIMARY KEY,
    client_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    redirect_uri TEXT NOT NULL,
    code_challenge TEXT NOT NULL,
    scope TEXT NOT NULL,
    audience TEXT NOT NULL,
    family_id TEXT NOT NULL,
    expires_at REAL NOT NULL,
    used INTEGER NOT NULL DEFAULT 0
);
-- family: 인가 코드 1건에서 이어지는 refresh token 들. 재사용이 감지되면 family 전체를 폐기한다
CREATE TABLE IF NOT EXISTS refresh_tokens (
    token_hash TEXT PRIMARY KEY,
    family_id TEXT NOT NULL,
    client_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    scope TEXT NOT NULL,
    audience TEXT NOT NULL,
    expires_at REAL NOT NULL,
    used INTEGER NOT NULL DEFAULT 0,
    revoked INTEGER NOT NULL DEFAULT 0,
    created_at REAL NOT NULL,
    -- family 절대 만료 (최초 로그인 + refresh_family_max_lifetime_s)
    family_expires_at REAL
);
CREATE INDEX IF NOT EXISTS idx_refresh_family ON refresh_tokens (family_id);
CREATE TABLE IF NOT EXISTS revoked_families (
    family_id TEXT PRIMARY KEY,
    reason TEXT NOT NULL,
    revoked_at REAL NOT NULL
);
-- 로그인 실패 (key = "pair:<username>|<ip>", "user:<username>", "ip:<addr>")
-- 검증 전에 attempt 단위로 먼저 기록하고(예약), 성공하면 그 attempt 행을 지운다
CREATE TABLE IF NOT EXISTS login_failures (
    key TEXT NOT NULL,
    ts REAL NOT NULL,
    attempt TEXT,
    -- 실패한 IP (사용자 전체 백오프는 서로 다른 IP 수 기준)
    ip TEXT
);
CREATE INDEX IF NOT EXISTS idx_login_failures ON login_failures (key, ts);
-- 로그인에 성공한 적 있는 (사용자명, IP) 와 기기 쿠키: 사용자 전체 백오프·잠금에서 뺀다
CREATE TABLE IF NOT EXISTS known_logins (
    username TEXT NOT NULL,
    ip TEXT NOT NULL,
    expires_at REAL NOT NULL,
    PRIMARY KEY (username, ip)
);
CREATE TABLE IF NOT EXISTS trusted_devices (
    token_hash TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    expires_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS registration_events (
    ip TEXT NOT NULL,
    ts REAL NOT NULL
);
"""


# 이전 버전 DB 에 없는 열 (table, column, 타입)
_MIGRATIONS = [
    ("clients", "allowed_audiences", "TEXT"),
    ("clients", "last_used_at", "REAL"),
    ("refresh_tokens", "family_expires_at", "REAL"),
    ("login_failures", "attempt", "TEXT"),
    ("login_failures", "ip", "TEXT"),
    ("login_requests", "ip", "TEXT"),
]


def _now() -> float:
    return time.time()


class Database:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        new = not path.exists()
        self._conn = sqlite3.connect(str(path), check_same_thread=False, isolation_level=None)
        self._conn.row_factory = sqlite3.Row
        self._lock = threading.Lock()
        if new:
            os.chmod(path, 0o600)
        with self._lock:
            self._conn.executescript(SCHEMA)
            self._conn.execute("PRAGMA journal_mode=WAL")
            for table, column, kind in _MIGRATIONS:
                columns = {r["name"] for r in self._conn.execute(f"PRAGMA table_info({table})")}
                if column not in columns:
                    self._conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {kind}")

    def _exec(self, sql: str, args: tuple = ()) -> sqlite3.Cursor:
        with self._lock:
            return self._conn.execute(sql, args)

    def _one(self, sql: str, args: tuple = ()) -> Optional[Dict[str, Any]]:
        with self._lock:
            row = self._conn.execute(sql, args).fetchone()
        return dict(row) if row else None

    def _all(self, sql: str, args: tuple = ()) -> List[Dict[str, Any]]:
        with self._lock:
            return [dict(r) for r in self._conn.execute(sql, args).fetchall()]

    def cleanup(self) -> None:
        now = _now()
        with self._lock:
            self._conn.execute("DELETE FROM login_requests WHERE expires_at < ?", (now,))
            self._conn.execute("DELETE FROM auth_codes WHERE expires_at < ?", (now - 3600,))
            self._conn.execute("DELETE FROM refresh_tokens WHERE expires_at < ?", (now,))
            self._conn.execute("DELETE FROM login_failures WHERE ts < ?", (now - 86400,))
            self._conn.execute("DELETE FROM registration_events WHERE ts < ?", (now - 86400,))
            self._conn.execute("DELETE FROM known_logins WHERE expires_at < ?", (now,))
            self._conn.execute("DELETE FROM trusted_devices WHERE expires_at < ?", (now,))

    # ------------------------------------------------------------------ users
    def add_user(self, username: str, password_hash: str) -> str:
        user_id = str(uuid.uuid4())
        self._exec(
            "INSERT INTO users (id, username, password_hash, created_at) VALUES (?, ?, ?, ?)",
            (user_id, username, password_hash, _now()),
        )
        return user_id

    def get_user_by_name(self, username: str) -> Optional[Dict[str, Any]]:
        return self._one("SELECT * FROM users WHERE username = ?", (username,))

    def get_user(self, user_id: str) -> Optional[Dict[str, Any]]:
        return self._one("SELECT * FROM users WHERE id = ?", (user_id,))

    def list_users(self) -> List[Dict[str, Any]]:
        return self._all("SELECT id, username, disabled, created_at FROM users ORDER BY username")

    def set_user_disabled(self, username: str, disabled: bool) -> bool:
        return self._exec("UPDATE users SET disabled = ? WHERE username = ?", (int(disabled), username)).rowcount == 1

    def set_password(self, username: str, password_hash: str) -> bool:
        return self._exec("UPDATE users SET password_hash = ? WHERE username = ?", (password_hash, username)).rowcount == 1

    def revoke_user_tokens(self, user_id: str, reason: str) -> None:
        """사용자의 refresh family 전체와 아직 교환되지 않은 인가 코드를 폐기한다"""
        for row in self._all("SELECT DISTINCT family_id FROM refresh_tokens WHERE user_id = ?", (user_id,)):
            self.revoke_family(row["family_id"], reason)
        for row in self._all("SELECT family_id FROM auth_codes WHERE user_id = ?", (user_id,)):
            self.revoke_family(row["family_id"], reason)
        self._exec("DELETE FROM auth_codes WHERE user_id = ?", (user_id,))
        # 비밀번호가 바뀌면 신뢰 기기도 다시 확인받는다
        self._exec("DELETE FROM trusted_devices WHERE user_id = ?", (user_id,))

    # ---------------------------------------------------------------- clients
    def add_client(
        self,
        client_id: str,
        client_type: str,
        secret_hash: Optional[str],
        redirect_uris: List[str],
        grant_types: List[str],
        scopes: List[str],
        registered_via: str,
        name: Optional[str] = None,
        allowed_audiences: Optional[List[str]] = None,
    ) -> None:
        self._exec(
            "INSERT INTO clients (client_id, client_type, secret_hash, name, redirect_uris, grant_types, scopes,"
            " registered_via, created_at, allowed_audiences) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (client_id, client_type, secret_hash, name, json.dumps(redirect_uris), json.dumps(grant_types),
             json.dumps(scopes), registered_via, _now(),
             json.dumps(allowed_audiences) if allowed_audiences is not None else None),
        )

    @staticmethod
    def _decode_client(row: Dict[str, Any]) -> Dict[str, Any]:
        for key in ("redirect_uris", "grant_types", "scopes"):
            row[key] = json.loads(row[key])
        row["allowed_audiences"] = json.loads(row["allowed_audiences"]) if row.get("allowed_audiences") else None
        return row

    def get_client(self, client_id: str) -> Optional[Dict[str, Any]]:
        row = self._one("SELECT * FROM clients WHERE client_id = ?", (client_id,))
        return self._decode_client(row) if row else None

    def list_clients(self) -> List[Dict[str, Any]]:
        rows = self._all(
            "SELECT client_id, client_type, name, redirect_uris, grant_types, scopes, registered_via, created_at,"
            " allowed_audiences, last_used_at FROM clients ORDER BY client_id"
        )
        return [self._decode_client(r) for r in rows]

    def touch_client(self, client_id: str) -> None:
        self._exec("UPDATE clients SET last_used_at = ? WHERE client_id = ?", (_now(), client_id))

    def count_dcr_clients(self) -> int:
        row = self._one("SELECT COUNT(*) AS n FROM clients WHERE registered_via = 'dcr'")
        return row["n"] if row else 0

    def cleanup_unused_dcr_clients(self, unused_ttl_s: int, used_ttl_s: int) -> int:
        """DCR 클라이언트 정리.
        - 토큰을 한 번도 받지 않았고 등록한 지 unused_ttl_s 가 지난 것
        - 마지막 토큰 발급이 used_ttl_s(= refresh family 절대 수명 이상) 보다 오래된 것 (남은 refresh 도 이미 만료)"""
        now = _now()
        return self._exec(
            "DELETE FROM clients WHERE registered_via = 'dcr' AND ("
            " (last_used_at IS NULL AND created_at < ?) OR (last_used_at IS NOT NULL AND last_used_at < ?))",
            (now - unused_ttl_s, now - used_ttl_s),
        ).rowcount

    def remove_client(self, client_id: str) -> bool:
        for row in self._all("SELECT DISTINCT family_id FROM refresh_tokens WHERE client_id = ?", (client_id,)):
            self.revoke_family(row["family_id"], "client_removed")
        return self._exec("DELETE FROM clients WHERE client_id = ?", (client_id,)).rowcount == 1

    # --------------------------------------------------------- login requests
    def add_login_request(self, request_id: str, csrf_token: str, cookie_hash: str, params: Dict[str, Any], ttl_s: int,
                          ip: str = "") -> None:
        self._exec(
            "INSERT INTO login_requests (id, csrf_token, cookie_hash, params, expires_at, ip) VALUES (?, ?, ?, ?, ?, ?)",
            (request_id, csrf_token, cookie_hash, json.dumps(params), _now() + ttl_s, ip),
        )

    def get_login_request(self, request_id: str) -> Optional[Dict[str, Any]]:
        row = self._one("SELECT * FROM login_requests WHERE id = ? AND expires_at >= ?", (request_id, _now()))
        if row:
            row["params"] = json.loads(row["params"])
        return row

    def delete_login_request(self, request_id: str) -> bool:
        return self._exec("DELETE FROM login_requests WHERE id = ?", (request_id,)).rowcount == 1

    def count_login_requests(self, ip: Optional[str] = None) -> int:
        if ip is None:
            row = self._one("SELECT COUNT(*) AS n FROM login_requests WHERE expires_at >= ?", (_now(),))
        else:
            row = self._one("SELECT COUNT(*) AS n FROM login_requests WHERE ip = ? AND expires_at >= ?", (ip, _now()))
        return row["n"] if row else 0

    # ----------------------------------------------------------- auth codes
    def add_code(self, code_hash: str, client_id: str, user_id: str, redirect_uri: str, code_challenge: str,
                 scope: str, audience: str, ttl_s: int) -> str:
        family_id = str(uuid.uuid4())
        self._exec(
            "INSERT INTO auth_codes (code_hash, client_id, user_id, redirect_uri, code_challenge, scope, audience,"
            " family_id, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (code_hash, client_id, user_id, redirect_uri, code_challenge, scope, audience, family_id, _now() + ttl_s),
        )
        return family_id

    def redeem_code(self, code_hash: str, client_id: str,
                    check: Callable[[Dict[str, Any]], Optional[str]]) -> Tuple[Optional[Dict[str, Any]], str]:
        """인가 코드 교환. (코드, 결과) — 결과는 ok / missing / reused / expired / 실패 사유

        확인(check: redirect_uri·PKCE, 통과하면 None)과 사용 처리를 같은 락 안에서 한다.
        - 다른 클라이언트의 코드: missing (소모·재사용 판정 없음)
        - check 실패: 그 사유. 코드를 소모하지 않는다 (verifier 없이 코드를 태울 수 없다)
        - 이미 사용한 코드: check 를 통과할 때만 reused (= 정상 교환 뒤 verifier 까지 가진 쪽의 재사용)
        """
        with self._lock:
            found = self._conn.execute(
                "SELECT * FROM auth_codes WHERE code_hash = ? AND client_id = ?", (code_hash, client_id)
            ).fetchone()
            if found is None:
                return None, "missing"
            row = dict(found)
            problem = check(row)
            if row["used"]:
                return row, ("reused" if problem is None else problem)
            if row["expires_at"] < _now():
                return row, "expired"
            if problem is not None:
                return row, problem
            claimed = self._conn.execute(
                "UPDATE auth_codes SET used = 1 WHERE code_hash = ? AND client_id = ? AND used = 0",
                (code_hash, client_id),
            ).rowcount == 1
        return row, ("ok" if claimed else "reused")

    # -------------------------------------------------------- refresh tokens
    def add_refresh_token(self, token_hash: str, family_id: str, client_id: str, user_id: str, scope: str,
                          audience: str, ttl_s: int, family_expires_at: float) -> None:
        """만료 = min(지금 + ttl_s, family 절대 만료). 회전해도 family 수명은 늘지 않는다"""
        now = _now()
        self._exec(
            "INSERT INTO refresh_tokens (token_hash, family_id, client_id, user_id, scope, audience, expires_at,"
            " created_at, family_expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (token_hash, family_id, client_id, user_id, scope, audience, min(now + ttl_s, family_expires_at), now,
             family_expires_at),
        )

    def get_refresh_token(self, token_hash: str) -> Optional[Dict[str, Any]]:
        return self._one("SELECT * FROM refresh_tokens WHERE token_hash = ?", (token_hash,))

    def use_refresh_token(self, token_hash: str) -> bool:
        """처음 사용이면 True (회전: 한 번 쓴 토큰은 다시 못 쓴다)"""
        return self._exec(
            "UPDATE refresh_tokens SET used = 1 WHERE token_hash = ? AND used = 0 AND revoked = 0", (token_hash,)
        ).rowcount == 1

    def revoke_family(self, family_id: str, reason: str) -> None:
        with self._lock:
            self._conn.execute("UPDATE refresh_tokens SET revoked = 1 WHERE family_id = ?", (family_id,))
            self._conn.execute(
                "INSERT OR IGNORE INTO revoked_families (family_id, reason, revoked_at) VALUES (?, ?, ?)",
                (family_id, reason, _now()),
            )

    def is_family_revoked(self, family_id: str) -> bool:
        return self._one("SELECT 1 FROM revoked_families WHERE family_id = ?", (family_id,)) is not None

    # -------------------------------------------------------------- 속도 제한
    def add_login_failure(self, key: str) -> None:
        self._exec("INSERT INTO login_failures (key, ts) VALUES (?, ?)", (key, _now()))

    def count_login_failures(self, key: str, window_s: int) -> int:
        row = self._one("SELECT COUNT(*) AS n FROM login_failures WHERE key = ? AND ts >= ?", (key, _now() - window_s))
        return row["n"] if row else 0

    def reserve_login_attempt(self, limits: Dict[str, int], window_s: int,
                              backoff: Optional[tuple[str, int, float, float]] = None, ip: str = "",
                              record: Optional[List[str]] = None) -> Optional[str]:
        """비밀번호 검증 전에 실패를 먼저 기록한다 (확인과 기록을 한 트랜잭션으로).

        limits: {key: 최대 실패 수}. 하나라도 이미 한도면 None (잠김).
        backoff: (key, 시작 IP 수, 기본 초, 최대 초) — 그 key 의 실패가 **서로 다른 IP** 시작 수 이상에서 나왔으면
                 마지막 실패 뒤 min(기본 * 2^(IP 수-시작), 최대) 초가 지나야 시도할 수 있다.
        record: 실패를 기록할 key (기본 limits 의 key 전체). 검사에서 뺀 key 도 기록은 남길 수 있다.
        통과하면 attempt 행을 넣고 attempt id 를 돌려준다 (성공하면 release_login_attempt)."""
        now = _now()
        since = now - window_s
        attempt = uuid.uuid4().hex
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                for key, maximum in limits.items():
                    n = self._conn.execute(
                        "SELECT COUNT(*) FROM login_failures WHERE key = ? AND ts >= ?", (key, since)
                    ).fetchone()[0]
                    if n >= maximum:
                        self._conn.execute("ROLLBACK")
                        return None
                if backoff is not None:
                    key, start, base, cap = backoff
                    ips, last = self._conn.execute(
                        "SELECT COUNT(DISTINCT ip), MAX(ts) FROM login_failures WHERE key = ? AND ts >= ?", (key, since)
                    ).fetchone()
                    if ips >= start and last is not None and now - last < min(base * 2 ** (ips - start), cap):
                        self._conn.execute("ROLLBACK")
                        return None
                self._conn.executemany(
                    "INSERT INTO login_failures (key, ts, attempt, ip) VALUES (?, ?, ?, ?)",
                    [(key, now, attempt, ip) for key in (record if record is not None else list(limits))],
                )
                self._conn.execute("COMMIT")
            except BaseException:
                self._conn.execute("ROLLBACK")
                raise
        return attempt

    def release_login_attempt(self, attempt: str, clear_keys: List[str] = ()) -> None:
        """성공한 시도: 예약한 실패 행을 지우고, clear_keys 의 실패 기록도 지운다"""
        with self._lock:
            self._conn.execute("DELETE FROM login_failures WHERE attempt = ?", (attempt,))
            for key in clear_keys:
                self._conn.execute("DELETE FROM login_failures WHERE key = ?", (key,))

    def clear_login_failures(self, key: str) -> None:
        self._exec("DELETE FROM login_failures WHERE key = ?", (key,))

    # ------------------------------------------------ 로그인 성공 이력·신뢰 기기
    def remember_login(self, username: str, ip: str, ttl_s: int) -> None:
        self._exec(
            "INSERT INTO known_logins (username, ip, expires_at) VALUES (?, ?, ?)"
            " ON CONFLICT (username, ip) DO UPDATE SET expires_at = excluded.expires_at",
            (username, ip, _now() + ttl_s),
        )

    def is_known_login(self, username: str, ip: str) -> bool:
        return self._one("SELECT 1 FROM known_logins WHERE username = ? AND ip = ? AND expires_at >= ?",
                         (username, ip, _now())) is not None

    def add_trusted_device(self, token_hash: str, user_id: str, ttl_s: int) -> None:
        self._exec("INSERT INTO trusted_devices (token_hash, user_id, expires_at) VALUES (?, ?, ?)",
                   (token_hash, user_id, _now() + ttl_s))

    def trusted_device_user(self, token_hash: str) -> Optional[str]:
        row = self._one("SELECT user_id FROM trusted_devices WHERE token_hash = ? AND expires_at >= ?",
                        (token_hash, _now()))
        return row["user_id"] if row else None

    def add_registration_event(self, ip: str) -> None:
        self._exec("INSERT INTO registration_events (ip, ts) VALUES (?, ?)", (ip, _now()))

    def count_registrations(self, ip: str, window_s: int) -> int:
        row = self._one("SELECT COUNT(*) AS n FROM registration_events WHERE ip = ? AND ts >= ?", (ip, _now() - window_s))
        return row["n"] if row else 0
