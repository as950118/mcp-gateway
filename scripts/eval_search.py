"""
도구 검색 평가

    .venv/bin/python scripts/eval_search.py [--snapshot eval/upstream_tools.snapshot.json]
                                            [--queries eval/tool_queries.yaml] [--misses]

upstream 도구 스냅샷(이름·설명·스키마)에 레지스트리 메타데이터를 붙여 인덱싱하고,
평가 질의마다 expected 중 하나가 상위 k 안에 있는지 본다.
"설명만" (레지스트리 없이 upstream docstring 만) 과 "레지스트리" 를 나란히 비교한다.

실제 데이터(eval/upstream_tools.snapshot.json, eval/tool_queries.yaml, config/registry/satc-mcp-server.yaml)는
커밋하지 않는다. 없으면 *.example.* 파일로 돌린다.
"""

import argparse
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from satc_gateway.registry import Registry, load_overlay  # noqa: E402
from satc_gateway.search import BM25ToolSearcher  # noqa: E402

UPSTREAM = "satc-mcp-server"


def _default(path: str, example: str) -> Path:
    """실제 파일이 없으면 예시 파일"""
    real = ROOT / path
    return real if real.exists() else ROOT / example


def build(snapshot, overlay):
    registry = Registry({UPSTREAM: overlay} if overlay else {})
    registry.sync(UPSTREAM, None, [SimpleNamespace(**t) for t in snapshot])
    searcher = BM25ToolSearcher()
    searcher.rebuild(registry.entries())
    return searcher


def evaluate(searcher, queries):
    hit1 = hit3 = hit5 = 0
    rr = 0.0
    misses = []
    for q in queries:
        names = [h.entry.name for h in searcher.search(q["query"], top_k=10)]
        rank = next((i for i, n in enumerate(names, 1) if n in q["expected"]), None)
        hit1 += rank == 1
        hit3 += rank is not None and rank <= 3
        hit5 += rank is not None and rank <= 5
        rr += 1 / rank if rank else 0
        if rank != 1:
            misses.append((q["query"], q["expected"], rank, names[:3]))
    n = len(queries)
    return {"hit@1": hit1 / n, "hit@3": hit3 / n, "hit@5": hit5 / n, "mrr": rr / n}, misses


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--snapshot", default=_default("eval/upstream_tools.snapshot.json", "eval/upstream_tools.snapshot.example.json"))
    parser.add_argument("--queries", default=_default("eval/tool_queries.yaml", "eval/tool_queries.example.yaml"))
    parser.add_argument("--registry", default=_default("config/registry/satc-mcp-server.yaml", "config/registry/example.yaml"))
    parser.add_argument("--misses", action="store_true", help="1위가 아닌 질의 출력 (레지스트리 기준)")
    args = parser.parse_args()

    snapshot = json.loads(Path(args.snapshot).read_text(encoding="utf-8"))
    queries = yaml.safe_load(Path(args.queries).read_text(encoding="utf-8"))["queries"]

    known = {t["name"] for t in snapshot}
    for q in queries:
        unknown = set(q["expected"]) - known
        if unknown:
            raise SystemExit(f"평가셋에 없는 도구: {unknown} ({q['query']})")

    print(f"스냅샷 {Path(args.snapshot).name}, 질의 {Path(args.queries).name}, 레지스트리 {Path(args.registry).name}")
    print(f"도구 {len(snapshot)}개, 질의 {len(queries)}개\n")
    print(f"{'구성':<10} {'hit@1':>6} {'hit@3':>6} {'hit@5':>6} {'MRR':>6}")
    results = {}
    for label, overlay in (("설명만", None), ("레지스트리", load_overlay(Path(args.registry)))):
        metrics, misses = evaluate(build(snapshot, overlay), queries)
        results[label] = misses
        print(f"{label:<10} " + " ".join(f"{metrics[k]:>6.2f}" for k in ("hit@1", "hit@3", "hit@5", "mrr")))

    if args.misses:
        print("\n1위가 아닌 질의 (레지스트리):")
        for query, expected, rank, top3 in results["레지스트리"]:
            print(f"  [{rank or '-'}] {query}\n      정답 {expected} / 상위 {top3}")


if __name__ == "__main__":
    main()
