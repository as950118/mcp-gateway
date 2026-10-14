"""
실행 Gateway 미들웨어

등록 순서가 바깥 -> 안쪽 실행 순서다 (fastmcp: 먼저 add 한 미들웨어가 가장 바깥).
    AuditMiddleware     모든 tools/call 을 결과(ok/tool_error/error/denied/timeout/hidden)와 함께 기록
    ExposureMiddleware  tools/list 에 부작용 annotation 주입, dynamic 모드에서 세션별 노출 필터
    PolicyMiddleware    부작용 분류·도구별 차단/확인(elicitation), 타임아웃
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
from fastmcp.server.elicitation import AcceptedElicitation
from fastmcp.server.middleware import CallNext, Middleware, MiddlewareContext
from fastmcp.tools.tool import Tool, ToolResult

from .auth import current_client
from .config import AuditConfig
from .state import META_TOOLS, GatewayState

logger = logging.getLogger(__name__)


class PolicyDenied(ToolError):
    pass


class ToolTimeout(ToolError):
    pass


class ToolHidden(ToolError):
    pass


# 요청 단위 상태 키: 사용자가 confirm 에 응답한 결과 (accepted/declined/cancelled/fallback_allow/fallback_deny)
CONFIRM_STATE = "gateway.confirm"


def sanitize(value: Any, audit: AuditConfig, key: str = "") -> Any:
    """비밀값 키는 가리고 긴 문자열은 자른다"""
    if any(k in key.lower() for k in audit.redact_keys):
        return "***"
    if isinstance(value, dict):
        return {k: sanitize(v, audit, k) for k, v in value.items()}
    if isinstance(value, list):
        return [sanitize(v, audit, key) for v in value]
    if isinstance(value, str) and len(value) > audit.max_arg_chars:
        return value[: audit.max_arg_chars] + f"...(+{len(value) - audit.max_arg_chars})"
    return value


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
            "client": current_client(),
            "tool": name,
            "upstream": self.state.upstream_of(name) or ("gateway" if name in META_TOOLS else None),
            "side_effect": "read" if name in META_TOOLS else self.state.side_effect_of(name),
            "arguments": sanitize(context.message.arguments or {}, self.audit),
            "outcome": outcome,
            "confirm": context.fastmcp_context.get_state(CONFIRM_STATE) if context.fastmcp_context else None,
            "error": error[:1000] if error else None,
            "duration_ms": round(duration_ms, 1),
        }
        try:
            with self.path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(record, ensure_ascii=False, default=str) + "\n")
        except OSError as e:
            logger.error("감사 로그 기록 실패: %s", e)


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
        action = policy.action_for(name, side_effect)
        if action == "deny":
            raise PolicyDenied(f"게이트웨이 정책으로 차단된 도구입니다: {name} (side_effect={side_effect})")
        if action == "confirm":
            # 사용자 응답을 기다리는 시간은 타임아웃에 넣지 않는다
            await self._confirm(context, name, side_effect)

        timeout = policy.timeout_for(name, side_effect)
        try:
            return await asyncio.wait_for(call_next(context), timeout=timeout)
        except asyncio.TimeoutError:
            raise ToolTimeout(f"'{name}' 실행이 {timeout:g}초를 넘겨 중단했습니다.") from None

    async def _confirm(self, context: MiddlewareContext[mt.CallToolRequestParams], name: str, side_effect: str) -> None:
        ctx = context.fastmcp_context
        policy = self.state.config.policy
        if ctx is None or not _supports_elicitation(ctx):
            if policy.confirm_fallback == "allow":
                if ctx is not None:
                    ctx.set_state(CONFIRM_STATE, "fallback_allow")
                return
            if ctx is not None:
                ctx.set_state(CONFIRM_STATE, "fallback_deny")
            raise PolicyDenied(
                f"'{name}' 은(는) 실행 전 확인이 필요한데, 클라이언트가 확인 요청(elicitation)을 지원하지 않아 차단했습니다."
            )

        arguments = sanitize(context.message.arguments or {}, self.state.config.audit)
        message = (
            f"'{name}' 을(를) 실행할까요? (side_effect={side_effect})\n"
            f"인자: {json.dumps(arguments, ensure_ascii=False, default=str)}"
        )
        result = await ctx.elicit(message, response_type=None)
        ctx.set_state(CONFIRM_STATE, result.action)
        if not isinstance(result, AcceptedElicitation):
            raise PolicyDenied(f"사용자가 '{name}' 실행을 승인하지 않았습니다 ({result.action}).")


def _supports_elicitation(ctx) -> bool:
    try:
        params = ctx.session.client_params
    except Exception:
        return False
    return bool(params and params.capabilities and params.capabilities.elicitation is not None)
