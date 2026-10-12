"""
도구 검색

ToolSearcher 인터페이스 뒤에 구현을 바꿔 끼울 수 있게 둔다. 기본 구현은 메모리 BM25.
도구 수가 늘어 의미 검색이 필요해지면 하이브리드 색인(BM25 + 임베딩, RRF)을
쓰는 구현을 추가한다.

한국어는 형태소 분석 없이 음절 bigram 으로 쪼갠다 ("로그를" -> "로그", "그를").
조사가 붙은 질의도 bigram 이 겹쳐서 맞는다.
"""

import math
import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Protocol, Sequence

from .registry import ToolEntry

_TOKEN_RE = re.compile(r"[a-z0-9]+|[가-힣]+")
_CAMEL_RE = re.compile(r"([a-z0-9])([A-Z])")

# 거의 모든 도구 설명에 들어가 변별력이 없는 토큰
STOPWORDS = {
    "tool", "tools", "ctx", "mcp", "args", "returns", "dict", "str", "none", "the", "of", "a",
    "컨텍", "텍스",  # "MCP 실행 컨텍스트"
    "도구",
}

# 필드 가중치 (토큰 반복 횟수)
FIELD_WEIGHTS = {"name": 3, "tags": 3, "domain": 2, "examples": 2, "description": 1}


def tokenize(text: str) -> List[str]:
    text = _CAMEL_RE.sub(r"\1 \2", text or "").lower()
    tokens: List[str] = []
    for match in _TOKEN_RE.finditer(text):
        word = match.group(0)
        if word[0] >= "가":
            if len(word) == 1:
                tokens.append(word)
            else:
                tokens.extend(word[i : i + 2] for i in range(len(word) - 1))
        else:
            tokens.append(word)
    return [t for t in tokens if t not in STOPWORDS]


def entry_tokens(entry: ToolEntry) -> List[str]:
    fields = {
        "name": entry.name,
        "tags": " ".join(entry.meta.tags),
        "domain": entry.meta.domain,
        "examples": " ".join(entry.meta.examples),
        "description": entry.description,
    }
    tokens: List[str] = []
    for field_name, text in fields.items():
        tokens.extend(tokenize(text) * FIELD_WEIGHTS[field_name])
    return tokens


@dataclass
class SearchHit:
    entry: ToolEntry
    score: float
    matched_terms: List[str] = field(default_factory=list)


class ToolSearcher(Protocol):
    def rebuild(self, entries: Sequence[ToolEntry]) -> None: ...

    def search(self, query: str, top_k: int = 5, domain: Optional[str] = None) -> List[SearchHit]: ...


class BM25ToolSearcher:
    def __init__(self, k1: float = 1.5, b: float = 0.75):
        self.k1 = k1
        self.b = b
        self._entries: List[ToolEntry] = []
        self._tfs: List[Counter] = []
        self._lengths: List[int] = []
        self._idf: Dict[str, float] = {}
        self._avg_len = 0.0

    def rebuild(self, entries: Sequence[ToolEntry]) -> None:
        self._entries = list(entries)
        docs = [entry_tokens(e) for e in self._entries]
        self._tfs = [Counter(d) for d in docs]
        self._lengths = [len(d) for d in docs]
        self._avg_len = (sum(self._lengths) / len(docs)) if docs else 0.0
        n = len(docs)
        df: Counter = Counter()
        for tf in self._tfs:
            df.update(tf.keys())
        # BM25+ 형태의 양수 idf
        self._idf = {t: math.log(1 + (n - c + 0.5) / (c + 0.5)) for t, c in df.items()}

    def search(self, query: str, top_k: int = 5, domain: Optional[str] = None) -> List[SearchHit]:
        terms = list(dict.fromkeys(tokenize(query)))
        hits: List[SearchHit] = []
        for entry, tf, length in zip(self._entries, self._tfs, self._lengths):
            if domain and entry.meta.domain != domain:
                continue
            score = 0.0
            matched = []
            for term in terms:
                freq = tf.get(term)
                if not freq:
                    continue
                norm = self.k1 * (1 - self.b + self.b * length / (self._avg_len or 1))
                score += self._idf[term] * freq * (self.k1 + 1) / (freq + norm)
                matched.append(term)
            if score > 0:
                hits.append(SearchHit(entry=entry, score=round(score, 4), matched_terms=matched))
        hits.sort(key=lambda h: (-h.score, h.entry.name))
        return hits[:top_k]
