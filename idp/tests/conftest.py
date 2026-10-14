import base64
import hashlib
import re
import secrets
from urllib.parse import parse_qs, urlsplit

import pytest
import yaml
from starlette.testclient import TestClient

from satc_idp.app import create_app, new_client_secret
from satc_idp.config import load_config
from satc_idp.security import hash_secret

AUDIENCE = "http://127.0.0.1:5600/mcp"
REDIRECT = "http://127.0.0.1:33418/callback"
PASSWORD = "correct-horse-battery"


def make_pkce():
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    return verifier, challenge


class Idp:
    def __init__(self, tmp_path, **overrides):
        raw = {
            "issuer": "http://testserver",
            "db_path": "idp.sqlite3",
            "keystore_dir": "keys",
            "audit_path": "audit.jsonl",
            "allowed_audiences": [AUDIENCE, "http://other/mcp"],
            "scopes": ["mcp", "admin"],
            "cookie_secure": False,
            # TestClient 의 호스트(testserver)는 loopback 이 아니다
            "allow_insecure_issuer": True,
            **overrides,
        }
        (tmp_path / "idp.yaml").write_text(yaml.safe_dump(raw), encoding="utf-8")
        self.config = load_config(str(tmp_path / "idp.yaml"))
        self.app = create_app(self.config)
        self.server = self.app.state.idp
        self.db = self.server.db
        self.http = TestClient(self.app, follow_redirects=False)
        self.tmp_path = tmp_path

    # ----------------------------------------------------------- 데이터 준비
    def add_user(self, username="alice", password=PASSWORD):
        return self.db.add_user(username, hash_secret(password))

    def add_confidential(self, client_id="svc", grants=("client_credentials",), scopes=("mcp",), redirect_uris=()):
        secret, secret_hash = new_client_secret()
        self.db.add_client(client_id, "confidential", secret_hash, list(redirect_uris), list(grants), list(scopes), "test")
        return secret

    def add_public(self, client_id="cli", redirect_uris=(REDIRECT,), scopes=("mcp",),
                   grants=("authorization_code", "refresh_token")):
        self.db.add_client(client_id, "public", None, list(redirect_uris), list(grants), list(scopes), "test")

    # ----------------------------------------------------------- 흐름
    def authorize_params(self, client_id="cli", redirect_uri=REDIRECT, challenge=None, **extra):
        params = {"response_type": "code", "client_id": client_id, "redirect_uri": redirect_uri, "state": "xyz",
                  "code_challenge": challenge, "code_challenge_method": "S256", **extra}
        return {k: v for k, v in params.items() if v is not None}

    def open_login(self, **kwargs):
        response = self.http.get("/authorize", params=self.authorize_params(**kwargs))
        assert response.status_code == 200, response.text
        request_id = re.search(r'name="request_id" value="([^"]+)"', response.text).group(1)
        csrf = re.search(r'name="csrf_token" value="([^"]+)"', response.text).group(1)
        return request_id, csrf

    def login(self, request_id, csrf, username="alice", password=PASSWORD):
        return self.http.post("/authorize", data={"request_id": request_id, "csrf_token": csrf,
                                                  "username": username, "password": password})

    def get_code(self, client_id="cli", redirect_uri=REDIRECT, **kwargs):
        verifier, challenge = make_pkce()
        request_id, csrf = self.open_login(client_id=client_id, redirect_uri=redirect_uri, challenge=challenge, **kwargs)
        response = self.login(request_id, csrf)
        assert response.status_code == 303, response.text
        query = parse_qs(urlsplit(response.headers["location"]).query)
        return query["code"][0], verifier, query

    def exchange(self, code, verifier, client_id="cli", redirect_uri=REDIRECT, **extra):
        return self.http.post("/token", data={"grant_type": "authorization_code", "code": code, "client_id": client_id,
                                              "redirect_uri": redirect_uri, "code_verifier": verifier, **extra})

    def refresh(self, refresh_token, client_id="cli", **extra):
        return self.http.post("/token", data={"grant_type": "refresh_token", "refresh_token": refresh_token,
                                              "client_id": client_id, **extra})

    def audit(self):
        import json

        path = self.tmp_path / "audit.jsonl"
        return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()] if path.exists() else []


@pytest.fixture
def idp(tmp_path):
    return Idp(tmp_path)


@pytest.fixture
def make_idp(tmp_path):
    def _make(**overrides):
        return Idp(tmp_path, **overrides)

    return _make
