import asyncio
from pathlib import Path

import pytest
import yaml
from fastmcp import FastMCP

from satc_gateway.config import load_config
from satc_gateway.server import build_gateway


def make_upstream() -> FastMCP:
    """satc-mcp-server 대신 쓰는 메모리 upstream"""
    upstream = FastMCP("fake-upstream")

    @upstream.tool()
    def get_pod_logs(pod_name: str = "api") -> str:
        """지정된 파드의 로그를 조회하는 도구"""
        return f"logs of {pod_name}"

    @upstream.tool()
    def list_db_tables(schema_name: str) -> list[str]:
        """지정된 스키마의 모든 테이블 목록을 조회하는 Tool"""
        return [f"{schema_name}.users", f"{schema_name}.orders"]

    @upstream.tool()
    def create_pull_request(title: str, app_password: str = "") -> str:
        """언어별 Repository에 Pull Request 생성 Tool (커밋 포함)"""
        return f"PR created: {title}"

    @upstream.tool()
    async def slow_tool() -> str:
        """오래 걸리는 도구"""
        await asyncio.sleep(5)
        return "done"

    @upstream.tool()
    def list_db_schemas() -> dict:
        """satc-mcp-server 처럼 실패를 status=error 응답으로 돌려주는 도구"""
        return {"status": "error", "error": "DB 연결에 실패했습니다."}

    @upstream.tool()
    def unregistered_tool() -> str:
        """레지스트리에 없는 도구"""
        return "ok"

    return upstream


REGISTRY = {
    "tools": {
        "get_pod_logs": {"domain": "k8s", "side_effect": "exec", "tags": ["pod", "파드", "로그"], "core": True},
        "list_db_tables": {"domain": "database", "side_effect": "read", "tags": ["db", "테이블"]},
        "create_pull_request": {"domain": "git", "side_effect": "external", "tags": ["pr", "git"]},
        "slow_tool": {"domain": "misc", "side_effect": "read"},
        "only_in_registry": {"domain": "misc", "side_effect": "read"},
    }
}


@pytest.fixture
def make_gateway(tmp_path: Path):
    """설정 일부를 바꿔 게이트웨이를 만든다: make_gateway(exposure={"mode": "dynamic"})"""

    def _make(prefix=None, **overrides):
        (tmp_path / "registry.yaml").write_text(yaml.safe_dump(REGISTRY, allow_unicode=True), encoding="utf-8")
        raw = {
            "upstreams": [{"name": "fake", "url": "unused", "prefix": prefix, "registry": "registry.yaml"}],
            "audit": {"path": "audit.jsonl"},
            **overrides,
        }
        (tmp_path / "gateway.yaml").write_text(yaml.safe_dump(raw, allow_unicode=True), encoding="utf-8")
        config = load_config(tmp_path / "gateway.yaml")
        return build_gateway(config, backends={"fake": make_upstream()})

    return _make
