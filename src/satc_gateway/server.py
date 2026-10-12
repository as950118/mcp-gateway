"""
게이트웨이 서버 조립

    클라이언트 ──> [Audit] ──> [Exposure] ──> [Policy] ──> mount(proxy) ──> upstream MCP 서버
                                   │
                         Registry + ToolSearcher  (search_tools / activate_tools)
"""

from typing import Any, Dict, List, Optional

from fastmcp import Context, FastMCP

from .config import GatewayConfig
from .middleware import AuditMiddleware, ExposureMiddleware, PolicyMiddleware
from .state import GatewayState, Upstream

INSTRUCTIONS = """\
SATC MCP Gateway 입니다. 여러 SATC MCP 서버의 도구를 한곳에서 제공합니다.
- 어떤 도구를 써야 할지 모르면 search_tools 로 먼저 찾으세요.
- 검색 결과의 도구가 목록에 없으면 activate_tools 로 활성화한 뒤 호출하세요.
"""


def build_gateway(
    config: GatewayConfig,
    backends: Optional[Dict[str, Any]] = None,
) -> tuple[FastMCP, GatewayState]:
    """설정으로 게이트웨이를 만든다.

    backends: upstream 이름 -> 프록시 대상 (테스트에서 FastMCP 인스턴스를 직접 넘길 때 사용).
              없으면 config 의 url 로 연결한다.
    """
    backends = backends or {}
    state = GatewayState(config)
    gateway = FastMCP(name=config.name, instructions=INSTRUCTIONS)

    for upstream in config.upstreams:
        proxy = FastMCP.as_proxy(backends.get(upstream.name, upstream.url), name=upstream.name)
        gateway.mount(proxy, prefix=upstream.prefix)
        state.upstreams.append(Upstream(name=upstream.name, prefix=upstream.prefix, server=proxy))

    _register_meta_tools(gateway, state)

    audit_path = config.resolve(config.audit.path) if config.audit.path else None
    gateway.add_middleware(AuditMiddleware(state, audit_path))
    gateway.add_middleware(ExposureMiddleware(state))
    gateway.add_middleware(PolicyMiddleware(state))
    return gateway, state


def _register_meta_tools(gateway: FastMCP, state: GatewayState) -> None:
    @gateway.tool(annotations={"readOnlyHint": True})
    async def search_tools(
        query: str,
        top_k: Optional[int] = None,
        domain: Optional[str] = None,
        ctx: Context = None,
    ) -> Dict[str, Any]:
        """사용 가능한 도구를 자연어로 검색합니다. 어떤 도구를 써야 할지 모를 때 먼저 호출하세요.

        Args:
            query: 하려는 작업 (예: "argo 네임스페이스 파드 로그 보기", "테이블 컬럼 조회")
            top_k: 돌려받을 최대 개수 (기본 5)
            domain: 특정 도메인으로 한정 (결과의 domains 목록 참고)
        """
        await state.ensure_fresh()
        session_id = ctx.session_id if ctx else None
        hits = state.searcher.search(query, top_k or state.config.exposure.search_top_k, domain)
        return {
            "query": query,
            "results": [
                {
                    "name": h.entry.name,
                    "summary": h.entry.summary,
                    "domain": h.entry.meta.domain,
                    "side_effect": h.entry.meta.side_effect,
                    "score": h.score,
                    "visible": state.is_visible(h.entry.name, session_id),
                }
                for h in hits
            ],
            "domains": state.registry.domains(),
            "hint": (
                "visible=false 인 도구는 activate_tools 로 활성화한 뒤 호출하세요."
                if state.dynamic
                else "모든 도구가 이미 노출되어 있습니다. 결과의 name 으로 바로 호출하세요."
            ),
        }

    @gateway.tool()
    async def activate_tools(names: List[str], ctx: Context = None) -> Dict[str, Any]:
        """search_tools 로 찾은 도구를 이 세션에서 쓸 수 있게 활성화합니다.
        활성화하면 도구 목록이 갱신되고, 각 도구의 입력 스키마를 함께 돌려줍니다.

        Args:
            names: 활성화할 도구 이름 목록 (search_tools 결과의 name)
        """
        await state.ensure_fresh()
        known = [n for n in names if state.registry.get(n) is not None]
        unknown = [n for n in names if state.registry.get(n) is None]
        if state.dynamic and known and ctx is not None:
            state.activate(ctx.session_id, known)
            await ctx.send_tool_list_changed()
        return {
            "activated": known,
            "unknown": unknown,
            "mode": state.config.exposure.mode,
            "tools": [
                {
                    "name": e.name,
                    "description": e.description,
                    "side_effect": e.meta.side_effect,
                    "input_schema": e.parameters,
                }
                for e in (state.registry.get(n) for n in known)
            ],
        }
