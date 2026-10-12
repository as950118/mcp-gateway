from types import SimpleNamespace

from satc_gateway.registry import Registry, ToolMeta
from satc_gateway.search import BM25ToolSearcher, tokenize


def test_tokenize_korean_bigram_and_snake_case():
    assert tokenize("get_pod_logs") == ["get", "pod", "logs"]
    assert tokenize("로그를 조회") == ["로그", "그를", "조회"]
    assert tokenize("getPodLogs") == ["get", "pod", "logs"]


def test_tokenize_drops_stopwords():
    assert "ctx" not in tokenize("ctx: MCP 실행 컨텍스트")
    assert "컨텍" not in tokenize("ctx: MCP 실행 컨텍스트")


def _searcher(overlay=None):
    tools = [
        SimpleNamespace(name="get_pod_logs", description="지정된 파드의 로그를 조회하는 도구", parameters={}),
        SimpleNamespace(name="list_db_tables", description="스키마의 테이블 목록을 조회", parameters={}),
        SimpleNamespace(name="create_pull_request", description="Pull Request 생성", parameters={}),
    ]
    registry = Registry({"up": overlay or {}})
    registry.sync("up", None, tools)
    searcher = BM25ToolSearcher()
    searcher.rebuild(registry.entries())
    return searcher


def test_search_matches_korean_with_particles():
    hits = _searcher().search("파드 로그 보여줘")
    assert hits[0].entry.name == "get_pod_logs"


def test_registry_tags_bridge_vocabulary():
    # 설명에 없는 단어("쿠버네티스")도 태그로 찾는다
    assert _searcher().search("쿠버네티스") == []
    hits = _searcher({"get_pod_logs": ToolMeta(tags=["쿠버네티스"])}).search("쿠버네티스")
    assert hits[0].entry.name == "get_pod_logs"


def test_search_domain_filter():
    overlay = {"get_pod_logs": ToolMeta(domain="k8s"), "list_db_tables": ToolMeta(domain="database")}
    hits = _searcher(overlay).search("조회", domain="database")
    assert [h.entry.name for h in hits] == ["list_db_tables"]


def test_registry_sync_reports_mismatch():
    registry = Registry({"up": {"get_pod_logs": ToolMeta(), "gone": ToolMeta()}})
    warnings = registry.sync("up", "satc", [SimpleNamespace(name="get_pod_logs", description=""), SimpleNamespace(name="new", description="")])
    assert any("new" in w and "레지스트리에 없는" in w for w in warnings)
    assert any("gone" in w for w in warnings)
    assert registry.get("satc_get_pod_logs").original_name == "get_pod_logs"
    assert registry.get("satc_new").meta.side_effect == "unknown"
