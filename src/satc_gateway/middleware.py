"""
실행 Gateway 미들웨어

등록 순서가 바깥 -> 안쪽 실행 순서다 (fastmcp: 먼저 add 한 미들웨어가 가장 바깥).
    AuditMiddleware     모든 tools/call 을 결과(ok/tool_error/error/denied/timeout/hidden)와 함께 기록
    ExposureMiddleware  tools/list 에 부작용 annotation 주입, dynamic 모드에서 세션별 노출 필터
    PolicyMiddleware    부작용 분류·도구별 차단, 타임아웃
"""

import asyncio
import json
import logging
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import mcp.types as mt
from fastmcp.exceptions import ToolError
from fastmcp.server.middleware import CallNext, Middleware, MiddlewareContext
from fastmcp.tools.tool import Tool, ToolResult

from .state import META_TOOLS, GatewayState

logger = logging.getLogger(__name__)


class PolicyDenied(ToolError):
    pass


class ToolTimeout(ToolError):
    pass


class ToolHidden(ToolError):
    pass


def _session_id(context: MiddlewareContext) -> Optional[str]:
    ctx = context.fastmcp_context
    if ctx is None:
        return None
    try:
        return ctx.session_id
    except Exception:  # 요청 컨텍스트 밖
        return None


# 부작용 분류 -> MCP tool annotation (upstream 이 이미 준 값은 덮어쓰지 않는다)
_ANNOTATIONS: Dict[str, Dict[str, Any]] = {
    "read": {"readOnlyHint": True, "destructiveHint": False},
    "write": {"readOnlyHint": False},
    "exec": {"readOnlyHint": False, "openWorldHint": True},
    "external": {"readOnlyHint": False, "openWorldHint": True},
}


def _with_annotations(tool: Tool, side_effect: str) -> Tool:
    hints = _ANNOTATIONS.get(side_effect)
    if not hints:
        return tool
    current = tool.annotations.model_dump(exclude_none=True) if tool.annotations else {}
    merged = {**hints, **current}
    if merged == current:
        return tool
    return tool.model_copy(update={"annotations": mt.ToolAnnotations(**merged)})


class AuditMiddleware(Middleware):
    def __init__(self, state: GatewayState, path: Optional[Path]):
        self.state = state
        self.path = path
        self.audit = state.config.audit
        if path is not None:
            path.parent.mkdir(parents=True, exist_ok=True)

    async def on_call_tool(
        self,
        context: MiddlewareContext[mt.CallToolRequestParams],
        call_next: CallNext[mt.CallToolRequestParams, ToolResult],
    ) -> ToolResult:
        started = time.perf_counter()
        outcome, error = "ok", None
        try:
            result = await call_next(context)
            # satc-mcp-server 는 실패를 MCP 에러가 아니라 {"status": "error", "error": ...} 응답으로 돌려준다
            payload = result.structured_content
            if isinstance(payload, dict) and payload.get("status") == "error":
                outcome, error = "tool_error", str(payload.get("error") or payload.get("message") or "")
            return result
        except PolicyDenied as e:
            outcome, error = "denied", str(e)
            raise
        except ToolTimeout as e:
            outcome, error = "timeout", str(e)
            raise
        except ToolHidden as e:
            outcome, error = "hidden", str(e)
            raise
        except Exception as e:
            outcome, error = "error", str(e)
            raise
        finally:
            self._write(context, outcome, error, (time.perf_counter() - started) * 1000)

    def _write(self, context, outcome: str, error: Optional[str], duration_ms: float) -> None:
        if self.path is None:
            return
        name = context.message.name
        record = {
            "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
            "session": _session_id(context),
            "tool": name,
            "upstream": self.state.upstream_of(name) or ("gateway" if name in META_TOOLS else None),
            "side_effect": "read" if name in META_TOOLS else self.state.side_effect_of(name),
            "arguments": self._sanitize(context.message.arguments or {}),
            "outcome": outcome,
            "error": error[:1000] if error else None,
            "duration_ms": round(duration_ms, 1),
        }
        try:
            with self.path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(record, ensure_ascii=False, default=str) + "\n")
        except OSError as e:
            logger.error("감사 로그 기록 실패: %s", e)

    def _sanitize(self, value: Any, key: str = "") -> Any:
        if any(k in key.lower() for k in self.audit.redact_keys):
            return "***"
        if isinstance(value, dict):
            return {k: self._sanitize(v, k) for k, v in value.items()}
        if isinstance(value, list):
            return [self._sanitize(v, key) for v in value]
        if isinstance(value, str) and len(value) > self.audit.max_arg_chars:
            return value[: self.audit.max_arg_chars] + f"...(+{len(value) - self.audit.max_arg_chars})"
        return value


class ExposureMiddleware(Middleware):
    def __init__(self, state: GatewayState):
        self.state = state

    async def on_list_tools(
        self,
        context: MiddlewareContext[mt.ListToolsRequest],
        call_next: CallNext[mt.ListToolsRequest, List[Tool]],
    ) -> List[Tool]:
        tools = await call_next(context)
        await self.state.ensure_fresh()
        session_id = _session_id(context)
        return [
            _with_annotations(tool, self.state.side_effect_of(tool.name))
            for tool in tools
            if self.state.is_visible(tool.name, session_id)
        ]

    async def on_call_tool(
        self,
        context: MiddlewareContext[mt.CallToolRequestParams],
        call_next: CallNext[mt.CallToolRequestParams, ToolResult],
    ) -> ToolResult:
        name = context.message.name
        if self.state.dynamic:
            await self.state.ensure_fresh()
            if not self.state.is_visible(name, _session_id(context)):
                raise ToolHidden(f"'{name}' 은(는) 아직 활성화되지 않았습니다. activate_tools 로 먼저 활성화하세요.")
        return await call_next(context)


class PolicyMiddleware(Middleware):
    def __init__(self, state: GatewayState):
        self.state = state

    async def on_call_tool(
        self,
        context: MiddlewareContext[mt.CallToolRequestParams],
        call_next: CallNext[mt.CallToolRequestParams, ToolResult],
    ) -> ToolResult:
        name = context.message.name
        if name in META_TOOLS:
            return await call_next(context)

        await self.state.ensure_fresh()
        policy = self.state.config.policy
        side_effect = self.state.side_effect_of(name)
        if policy.action_for(name, side_effect) == "deny":
            raise PolicyDenied(f"게이트웨이 정책으로 차단된 도구입니다: {name} (side_effect={side_effect})")

        timeout = policy.timeout_for(name, side_effect)
        try:
            return await asyncio.wait_for(call_next(context), timeout=timeout)
        except asyncio.TimeoutError:
            raise ToolTimeout(f"'{name}' 실행이 {timeout:g}초를 넘겨 중단했습니다.") from None
