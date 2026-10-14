import asyncio
import json

import pytest
from fastmcp import Client
from fastmcp.client.elicitation import ElicitResult
from fastmcp.exceptions import ToolError


def _audit(state):
    path = state.config.resolve(state.config.audit.path)
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


async def test_all_mode_lists_every_tool_with_annotations(make_gateway):
    gateway, _ = make_gateway()
    async with Client(gateway) as client:
        tools = {t.name: t for t in await client.list_tools()}

    assert {"get_pod_logs", "list_db_tables", "create_pull_request", "search_tools", "activate_tools"} <= set(tools)
    assert tools["list_db_tables"].annotations.readOnlyHint is True
    assert tools["create_pull_request"].annotations.readOnlyHint is False
    assert tools["create_pull_request"].annotations.openWorldHint is True
    # 레지스트리에 없는 도구는 annotation 을 붙이지 않는다
    assert tools["unregistered_tool"].annotations is None


async def test_call_passes_through_and_is_audited(make_gateway):
    gateway, state = make_gateway()
    async with Client(gateway) as client:
        result = await client.call_tool("list_db_tables", {"schema_name": "shop"})
    assert result.data == ["shop.users", "shop.orders"]

    [record] = _audit(state)
    assert record["tool"] == "list_db_tables"
    assert record["upstream"] == "fake"
    assert record["side_effect"] == "read"
    assert record["outcome"] == "ok"
    assert record["arguments"] == {"schema_name": "shop"}


async def test_audit_records_error_payload(make_gateway):
    gateway, state = make_gateway()
    async with Client(gateway) as client:
        result = await client.call_tool("list_db_schemas", {})
    # 클라이언트에는 그대로 전달하고, 감사 로그에만 tool_error 로 남긴다
    assert result.is_error is False
    record = _audit(state)[0]
    assert record["outcome"] == "tool_error"
    assert "DB 연결" in record["error"]


async def test_audit_redacts_secrets(make_gateway):
    gateway, state = make_gateway()
    async with Client(gateway) as client:
        await client.call_tool("create_pull_request", {"title": "x", "app_password": "s3cret"})
    assert _audit(state)[0]["arguments"]["app_password"] == "***"


async def test_policy_denies_by_side_effect(make_gateway):
    gateway, state = make_gateway(policy={"side_effects": {"external": "deny"}})
    async with Client(gateway) as client:
        with pytest.raises(ToolError, match="차단"):
            await client.call_tool("create_pull_request", {"title": "x"})
        # 다른 분류는 그대로
        await client.call_tool("get_pod_logs", {})
    outcomes = [(r["tool"], r["outcome"]) for r in _audit(state)]
    assert outcomes == [("create_pull_request", "denied"), ("get_pod_logs", "ok")]


async def test_policy_denies_by_tool_name(make_gateway):
    gateway, _ = make_gateway(policy={"deny_tools": ["get_pod_logs"]})
    async with Client(gateway) as client:
        with pytest.raises(ToolError, match="차단"):
            await client.call_tool("get_pod_logs", {})


async def test_policy_timeout(make_gateway):
    gateway, state = make_gateway(policy={"tool_timeouts": {"slow_tool": 0.2}})
    async with Client(gateway) as client:
        with pytest.raises(ToolError, match="초를 넘겨"):
            await client.call_tool("slow_tool", {})
    assert _audit(state)[0]["outcome"] == "timeout"


async def test_search_tools(make_gateway):
    gateway, _ = make_gateway()
    async with Client(gateway) as client:
        result = await client.call_tool("search_tools", {"query": "파드 로그"})
    top = result.data["results"][0]
    assert top["name"] == "get_pod_logs"
    assert top["side_effect"] == "exec"
    assert top["visible"] is True


async def test_dynamic_mode_hides_until_activated(make_gateway):
    gateway, state = make_gateway(exposure={"mode": "dynamic"})
    notifications = []

    async def on_message(message):
        notifications.append(message)

    async with Client(gateway, message_handler=on_message) as client:
        names = {t.name for t in await client.list_tools()}
        # core 와 메타 도구만 보인다
        assert names == {"get_pod_logs", "search_tools", "activate_tools"}

        with pytest.raises(ToolError, match="activate_tools"):
            await client.call_tool("list_db_tables", {"schema_name": "shop"})

        search = await client.call_tool("search_tools", {"query": "테이블 목록"})
        hit = next(r for r in search.data["results"] if r["name"] == "list_db_tables")
        assert hit["visible"] is False

        activated = await client.call_tool("activate_tools", {"names": ["list_db_tables", "nope"]})
        assert activated.data["activated"] == ["list_db_tables"]
        assert activated.data["unknown"] == ["nope"]
        assert "schema_name" in activated.data["tools"][0]["input_schema"]["properties"]

        names = {t.name for t in await client.list_tools()}
        assert "list_db_tables" in names
        result = await client.call_tool("list_db_tables", {"schema_name": "shop"})
        assert result.data == ["shop.users", "shop.orders"]

    assert any("tools/list_changed" in str(n) for n in notifications)
    assert [r["outcome"] for r in _audit(state) if r["tool"] == "list_db_tables"] == ["hidden", "ok"]


async def test_dynamic_activation_is_per_session(make_gateway):
    gateway, _ = make_gateway(exposure={"mode": "dynamic"})
    async with Client(gateway) as first:
        await first.call_tool("activate_tools", {"names": ["list_db_tables"]})
    async with Client(gateway) as second:
        names = {t.name for t in await second.list_tools()}
    assert "list_db_tables" not in names


async def test_prefix_applies_to_exposed_names(make_gateway):
    gateway, state = make_gateway(prefix="satc", policy={"deny_tools": ["satc_get_pod_logs"]})
    async with Client(gateway) as client:
        names = {t.name for t in await client.list_tools()}
        assert "satc_list_db_tables" in names
        with pytest.raises(ToolError, match="차단"):
            await client.call_tool("satc_get_pod_logs", {})
    assert state.registry.get("satc_list_db_tables").meta.domain == "database"


async def test_check_warnings(make_gateway):
    _, state = make_gateway()
    await state.ensure_fresh(force=True)
    assert any("unregistered_tool" in w for w in state.warnings)
    assert any("only_in_registry" in w for w in state.warnings)


def _elicit_handler(action: str, seen: list):
    async def handler(message, response_type, params, context):
        seen.append(message)
        if action == "accept":
            return {}
        return ElicitResult(action=action)

    return handler


async def test_confirm_accepted_runs_tool(make_gateway):
    gateway, state = make_gateway(policy={"side_effects": {"external": "confirm"}})
    seen = []
    async with Client(gateway, elicitation_handler=_elicit_handler("accept", seen)) as client:
        result = await client.call_tool("create_pull_request", {"title": "x", "app_password": "s3cret"})
    assert result.data == "PR created: x"
    # 확인 메시지에 도구·인자가 들어가고 비밀값은 가린다
    assert "create_pull_request" in seen[0] and "***" in seen[0] and "s3cret" not in seen[0]
    record = _audit(state)[0]
    assert (record["outcome"], record["confirm"]) == ("ok", "accept")


@pytest.mark.parametrize("action", ["decline", "cancel"])
async def test_confirm_declined_blocks_tool(make_gateway, action):
    gateway, state = make_gateway(policy={"confirm_tools": ["create_pull_request"]})
    async with Client(gateway, elicitation_handler=_elicit_handler(action, [])) as client:
        with pytest.raises(ToolError, match="승인하지 않았습니다"):
            await client.call_tool("create_pull_request", {"title": "x"})
    record = _audit(state)[0]
    assert (record["outcome"], record["confirm"]) == ("denied", action)


async def test_confirm_without_elicitation_support_uses_fallback(make_gateway):
    # elicitation_handler 가 없는 클라이언트는 elicitation capability 를 광고하지 않는다
    gateway, state = make_gateway(policy={"confirm_tools": ["create_pull_request"]})
    async with Client(gateway) as client:
        with pytest.raises(ToolError, match="지원하지 않아"):
            await client.call_tool("create_pull_request", {"title": "x"})
    assert _audit(state)[0]["confirm"] == "fallback_deny"

    gateway, state = make_gateway(policy={"confirm_tools": ["create_pull_request"], "confirm_fallback": "allow"})
    async with Client(gateway) as client:
        result = await client.call_tool("create_pull_request", {"title": "y"})
    assert result.data == "PR created: y"


async def test_confirm_wait_not_counted_in_timeout(make_gateway):
    async def slow_accept(message, response_type, params, context):
        await asyncio.sleep(0.5)
        return {}

    gateway, _ = make_gateway(policy={"confirm_tools": ["get_pod_logs"], "tool_timeouts": {"get_pod_logs": 0.3}})
    async with Client(gateway, elicitation_handler=slow_accept) as client:
        result = await client.call_tool("get_pod_logs", {})
    assert result.data == "logs of api"
