"""
satc-mcp-gateway CLI

    satc-mcp-gateway serve  [-c config/gateway.yaml] [--transport stdio|http] [--host] [--port]
    satc-mcp-gateway check  [-c ...]           upstream 도구와 레지스트리 대조
    satc-mcp-gateway search [-c ...] "질의"     검색 결과 확인 (디버깅용)
"""

import argparse
import asyncio
import logging
import os
import sys

from .config import load_config
from .server import build_gateway

DEFAULT_CONFIG = os.getenv("SATC_GATEWAY_CONFIG", "config/gateway.yaml")


def main(argv=None) -> None:
    parser = argparse.ArgumentParser(prog="satc-mcp-gateway")
    sub = parser.add_subparsers(dest="command")

    serve = sub.add_parser("serve", help="게이트웨이 실행 (기본)")
    serve.add_argument("--transport", default=os.getenv("MCP_TRANSPORT", "stdio"), choices=["stdio", "http"])
    serve.add_argument("--host", default=os.getenv("GATEWAY_HOST", "0.0.0.0"))
    serve.add_argument("--port", type=int, default=int(os.getenv("GATEWAY_PORT", "5600")))

    sub.add_parser("check", help="upstream 도구와 레지스트리 대조")

    search = sub.add_parser("search", help="도구 검색 결과 확인")
    search.add_argument("query")
    search.add_argument("-k", "--top-k", type=int, default=5)
    search.add_argument("--domain")

    for p in sub.choices.values():
        p.add_argument("-c", "--config", default=DEFAULT_CONFIG)

    args = parser.parse_args(argv)
    # stdio 모드에서는 stdout 이 MCP 채널이므로 로그는 stderr 로
    logging.basicConfig(level=logging.INFO, stream=sys.stderr, format="%(asctime)s [%(levelname)s] %(name)s %(message)s")
    # upstream 호출마다 찍히는 HTTP 로그는 끈다
    for noisy in ("httpx", "mcp.client.streamable_http"):
        logging.getLogger(noisy).setLevel(logging.WARNING)

    command = args.command or "serve"
    config = load_config(getattr(args, "config", DEFAULT_CONFIG))
    gateway, state = build_gateway(config)

    if command == "serve":
        if args.transport == "stdio":
            gateway.run(transport="stdio")
        else:
            gateway.run(transport="streamable-http", host=args.host, port=args.port)
    elif command == "check":
        asyncio.run(_check(state))
    elif command == "search":
        asyncio.run(_search(state, args.query, args.top_k, args.domain))


async def _check(state) -> None:
    await state.ensure_fresh(force=True)
    entries = state.registry.entries()
    print(f"도구 {len(entries)}개 (레지스트리 등록 {sum(e.registered for e in entries)}개)")
    for e in sorted(entries, key=lambda e: (e.meta.domain, e.name)):
        flag = " core" if e.meta.core else ""
        print(f"  {e.meta.domain:<10} {e.meta.side_effect:<9} {e.name}{flag}")
    if state.warnings:
        print("\n경고:")
        for w in state.warnings:
            print(f"  - {w}")
        sys.exit(1)


async def _search(state, query: str, top_k: int, domain) -> None:
    await state.ensure_fresh(force=True)
    for i, hit in enumerate(state.searcher.search(query, top_k, domain), 1):
        print(f"{i}. {hit.score:7.3f}  {hit.entry.name}  [{hit.entry.meta.domain}/{hit.entry.meta.side_effect}]  {' '.join(hit.matched_terms)}")


if __name__ == "__main__":
    main()
