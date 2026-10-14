"""
서명 키 저장소 (RS256)

    <keystore_dir>/keys.json      {"active": kid, "keys": [{"kid", "created_at", "status"}]}
    <keystore_dir>/<kid>.pem      개인키 (권한 600)

교체(rotate): 새 키를 active 로 만들고, 직전 키들은 published_previous_keys 개까지 JWKS 에 남긴다
(교체 전에 발급된 access token 이 만료될 때까지 검증할 수 있도록). 그보다 오래된 키는 retired 로 바꿔 게시하지 않고,
개인키 파일도 지운다 (유출돼도 retired 키로 서명할 수 없게).
"""

import json
import os
import time
from pathlib import Path
from typing import Any, Dict, List

from joserfc.jwk import KeySet, RSAKey

from .security import new_token

ALGORITHM = "RS256"
KEY_SIZE = 2048


class KeyStore:
    def __init__(self, directory: Path, published_previous_keys: int = 1):
        self.directory = directory
        self.published_previous_keys = published_previous_keys
        self._cache: Dict[str, RSAKey] = {}
        self._state_mtime: float = -1
        self._state: Dict[str, Any] = {"active": None, "keys": []}

    # ------------------------------------------------------------------ 상태
    @property
    def _state_path(self) -> Path:
        return self.directory / "keys.json"

    def _load(self) -> None:
        # CLI 로 키를 교체하면 서버가 다음 요청에서 바로 반영하도록 mtime 을 본다
        if not self._state_path.exists():
            self._state = {"active": None, "keys": []}
            return
        mtime = self._state_path.stat().st_mtime
        if mtime != self._state_mtime:
            self._state = json.loads(self._state_path.read_text(encoding="utf-8"))
            self._state_mtime = mtime

    def _save(self) -> None:
        tmp = self._state_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self._state, indent=1), encoding="utf-8")
        os.chmod(tmp, 0o600)
        tmp.replace(self._state_path)

    def _key(self, kid: str) -> RSAKey:
        if kid not in self._cache:
            pem = (self.directory / f"{kid}.pem").read_bytes()
            self._cache[kid] = RSAKey.import_key(pem, parameters={"kid": kid, "use": "sig", "alg": ALGORITHM})
        return self._cache[kid]

    # ------------------------------------------------------------------ 조작
    def rotate(self) -> str:
        self.directory.mkdir(parents=True, exist_ok=True)
        os.chmod(self.directory, 0o700)
        self._load()
        kid = f"{time.strftime('%Y%m%d')}-{new_token(6)}"
        key = RSAKey.generate_key(KEY_SIZE, parameters={"kid": kid, "use": "sig", "alg": ALGORITHM}, private=True)
        # 개인키는 처음부터 600 으로 만든다 (만든 뒤 chmod 하면 잠깐 열려 있다)
        fd = os.open(self.directory / f"{kid}.pem", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(key.as_pem(private=True))

        for entry in self._state["keys"]:
            if entry["status"] == "active":
                entry["status"] = "previous"
        self._state["keys"].append({"kid": kid, "created_at": time.time(), "status": "active"})
        previous = [e for e in self._state["keys"] if e["status"] == "previous"]
        retired = previous[: max(0, len(previous) - self.published_previous_keys)]
        for entry in retired:
            entry["status"] = "retired"
        self._state["active"] = kid
        self._save()
        # 상태를 먼저 저장한 뒤 지운다 (중간에 죽어도 retired 키를 게시하지 않는다)
        for entry in retired:
            (self.directory / f"{entry['kid']}.pem").unlink(missing_ok=True)
            self._cache.pop(entry["kid"], None)
        self._load()
        return kid

    def ensure_key(self) -> str:
        self._load()
        # 이전 버전이 남긴 retired 개인키 정리
        for entry in self._state["keys"]:
            if entry["status"] == "retired":
                (self.directory / f"{entry['kid']}.pem").unlink(missing_ok=True)
        return self._state["active"] or self.rotate()

    def list(self) -> List[Dict[str, Any]]:
        self._load()
        return list(self._state["keys"])

    # ------------------------------------------------------------------ 사용
    def signing_key(self) -> RSAKey:
        self._load()
        if not self._state["active"]:
            raise RuntimeError("서명 키가 없습니다. 'satc-idp keys rotate' 로 만드세요.")
        return self._key(self._state["active"])

    def published(self) -> List[RSAKey]:
        self._load()
        return [self._key(e["kid"]) for e in self._state["keys"] if e["status"] in ("active", "previous")]

    def jwks(self) -> Dict[str, Any]:
        """공개키만 내보낸다"""
        return {"keys": [k.as_dict(private=False) for k in self.published()]}

    def key_set(self) -> KeySet:
        return KeySet(self.published())
