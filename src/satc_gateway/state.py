"""
게이트웨이 런타임 상태: 레지스트리·검색 인덱스 갱신, 세션별 활성 도구
"""

import asyncio
import logging
import time
from collections import OrderedDict
from dataclasses import dataclass
from typing import Dict, List, Optional, Set

from fastmcp import FastMCP

from .config import GatewayConfig
from .registry import Registry, load_overlay
from .search import BM25ToolSearcher, ToolSearcher

logger = logging.getLogger(__name__)

# 게이트웨이가 직접 제공하는 도구
META_TOOLS = ("search_tools", "activate_tools")

# 세션별 활성 도구를 기억할 최대 세션 수 (오래된 세션부터 버린다)
MAX_SESSIONS = 1000


@dataclass
class Upstream:
    name: str
    prefix: Optional[str]
    server: FastMCP


class GatewayState:
    def __init__(self, config: GatewayConfig, searcher: Optional[ToolSearcher] = None):
        self.config = config
        overlays = {}
        for upstream in config.upstreams:
            if upstream.registry:
                overlays[upstream.name] = load_overlay(config.resolve(upstream.registry))
        self.registry = Registry(overlays)
        self.searcher: ToolSearcher = searcher or BM25ToolSearcher()
        self.upstreams: List[Upstream] = []
        self.warnings: List[str] = []
        self._refreshed_at: Optional[float] = None
        self._lock = asyncio.Lock()
        self._sessions: "OrderedDict[str, Set[str]]" = OrderedDict()

    # ------------------------------------------------------------------
    # 레지스트리 갱신
    # ------------------------------------------------------------------
    async def ensure_fresh(self, force: bool = False) -> None:
        if not force and self._is_fresh():
            return
        async with self._lock:
            if not force and self._is_fresh():
                return
            warnings: List[str] = []
            for upstream in self.upstreams:
                try:
                    tools = await upstream.server.get_tools()
                except Exception as e:  # upstream 장애 시 이전 목록을 유지한다
                    logger.warning("upstream '%s' 도구 목록 조회 실패: %s", upstream.name, e)
                    warnings.append(f"[{upstream.name}] 도구 목록 조회 실패: {e}")
                    continue
                warnings.extend(self.registry.sync(upstream.name, upstream.prefix, tools.values()))
            self.searcher.rebuild(self.registry.entries())
            self.warnings = warnings
            self._refreshed_at = time.monotonic()
            for w in warnings:
                logger.warning(w)

    def _is_fresh(self) -> bool:
        return (
            self._refreshed_at is not None
            and time.monotonic() - self._refreshed_at < self.config.registry_ttl_s
        )

    # ------------------------------------------------------------------
    # 세션별 노출 (dynamic 모드)
    # ------------------------------------------------------------------
    @property
    def dynamic(self) -> bool:
        return self.config.exposure.mode == "dynamic"

    def active_tools(self, session_id: Optional[str]) -> Set[str]:
        if session_id is None:
            return set()
        return self._sessions.get(session_id, set())

    def activate(self, session_id: str, names: List[str]) -> None:
        active = self._sessions.setdefault(session_id, set())
        active.update(names)
        self._sessions.move_to_end(session_id)
        while len(self._sessions) > MAX_SESSIONS:
            self._sessions.popitem(last=False)

    def is_visible(self, name: str, session_id: Optional[str]) -> bool:
        if not self.dynamic or name in META_TOOLS:
            return True
        entry = self.registry.get(name)
        if entry is not None and entry.meta.core:
            return True
        return name in self.active_tools(session_id)

    def side_effect_of(self, name: str) -> str:
        entry = self.registry.get(name)
        return entry.meta.side_effect if entry else "unknown"

    def upstream_of(self, name: str) -> Optional[str]:
        entry = self.registry.get(name)
        return entry.upstream if entry else None
