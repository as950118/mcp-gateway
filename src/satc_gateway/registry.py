"""
Tool Registry

upstream 이 알려주는 도구 정의(이름·설명·스키마)에 게이트웨이가 관리하는 메타데이터
(도메인·태그·부작용·질의 예시·core 여부)를 합친다. 메타데이터는 upstream 별 YAML 로 관리한다.

    tools:
      get_pod_logs:
        domain: k8s
        side_effect: exec
        tags: [pod, 파드, 로그]
        examples: ["argo 네임스페이스 파드 로그 보여줘"]
        core: false
"""

import logging
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

import yaml
from pydantic import BaseModel, Field

from .config import SideEffect

logger = logging.getLogger(__name__)


class ToolMeta(BaseModel):
    domain: str = "general"
    side_effect: SideEffect = "unknown"
    tags: List[str] = Field(default_factory=list)
    # 사용자가 이 도구를 원할 때 할 법한 말. 검색 인덱스에 들어간다
    examples: List[str] = Field(default_factory=list)
    # dynamic 노출 모드에서도 항상 보이는 도구
    core: bool = False


class ToolEntry(BaseModel):
    # 클라이언트에 노출되는 이름 (prefix 포함)
    name: str
    upstream: str
    # upstream 에서의 원래 이름
    original_name: str
    description: str = ""
    parameters: Dict[str, Any] = Field(default_factory=dict)
    meta: ToolMeta = Field(default_factory=ToolMeta)
    # 레지스트리 YAML 에 메타데이터가 있는지
    registered: bool = False

    @property
    def summary(self) -> str:
        """설명 첫 줄"""
        for line in self.description.splitlines():
            if line.strip():
                return line.strip()
        return ""


def load_overlay(path: Path) -> Dict[str, ToolMeta]:
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return {name: ToolMeta.model_validate(meta or {}) for name, meta in (raw.get("tools") or {}).items()}


def exposed_name(prefix: Optional[str], original_name: str) -> str:
    # fastmcp mount 와 같은 규칙
    return f"{prefix}_{original_name}" if prefix else original_name


class Registry:
    def __init__(self, overlays: Optional[Dict[str, Dict[str, ToolMeta]]] = None):
        # upstream 이름 -> {원래 도구 이름 -> 메타데이터}
        self._overlays = overlays or {}
        # upstream 이름 -> {노출 이름 -> 항목}
        self._by_upstream: Dict[str, Dict[str, ToolEntry]] = {}

    def sync(self, upstream: str, prefix: Optional[str], tools: Iterable[Any]) -> List[str]:
        """upstream 도구 목록으로 갱신하고, 레지스트리와 어긋나는 점을 경고로 돌려준다.

        tools 는 name/description/parameters 를 가진 객체 (fastmcp Tool)
        """
        overlay = self._overlays.get(upstream, {})
        entries: Dict[str, ToolEntry] = {}
        for tool in tools:
            meta = overlay.get(tool.name)
            name = exposed_name(prefix, tool.name)
            entries[name] = ToolEntry(
                name=name,
                upstream=upstream,
                original_name=tool.name,
                description=tool.description or "",
                parameters=getattr(tool, "parameters", None) or {},
                meta=meta or ToolMeta(),
                registered=meta is not None,
            )
        self._by_upstream[upstream] = entries

        warnings = []
        upstream_names = {e.original_name for e in entries.values()}
        for name in sorted(upstream_names - set(overlay)):
            warnings.append(f"[{upstream}] 레지스트리에 없는 도구: {name} (side_effect=unknown 으로 처리)")
        for name in sorted(set(overlay) - upstream_names):
            warnings.append(f"[{upstream}] 레지스트리에만 있고 upstream 에 없는 도구: {name}")
        return warnings

    def entries(self) -> List[ToolEntry]:
        return [e for entries in self._by_upstream.values() for e in entries.values()]

    def get(self, name: str) -> Optional[ToolEntry]:
        for entries in self._by_upstream.values():
            if name in entries:
                return entries[name]
        return None

    def domains(self) -> List[str]:
        return sorted({e.meta.domain for e in self.entries()})

    def core_names(self) -> List[str]:
        return [e.name for e in self.entries() if e.meta.core]
