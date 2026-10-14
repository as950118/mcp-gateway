"""
감사 로그 (JSON Lines). 비밀번호·secret·코드·토큰 값은 절대 넣지 않는다.
"""

import json
import logging
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)

# 값이 들어오면 안 되는 필드 (실수 방지용 마지막 방어선)
_FORBIDDEN = {"password", "secret", "client_secret", "code", "code_verifier", "refresh_token", "access_token", "token"}


class Audit:
    def __init__(self, path: Optional[Path]):
        self.path = path
        self._lock = threading.Lock()
        if path is not None:
            path.parent.mkdir(parents=True, exist_ok=True)

    def log(self, event: str, **fields: Any) -> None:
        leaked = _FORBIDDEN & set(fields)
        if leaked:
            raise ValueError(f"감사 로그에 비밀 값 필드를 넣을 수 없습니다: {sorted(leaked)}")
        if self.path is None:
            return
        record = {"ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"), "event": event, **fields}
        try:
            with self._lock, self.path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(record, ensure_ascii=False, default=str) + "\n")
        except OSError as e:
            logger.error("감사 로그 기록 실패: %s", e)
