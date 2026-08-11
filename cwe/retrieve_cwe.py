#!/usr/bin/env python3
"""
查詢函式：拿一段文字（例如 finding 的 title 或 detail 內容）去 Qdrant
的 "cwe" collection 找最相關的 CWE 條目。

跟 keyword_rules.py 的關係：這是未來要取代/補強 keyword_rules.py
的其中一個資料來源。介面刻意設計成回傳跟 keyword_rules 相容的資訊
（cwe_id/name/description/mitigations + score 當作 confidence 的依據），
方便之後接進 analyze_findings() 那一層的統一介面。
"""
try:
    # cwe_kb 是子資料夾（package）的情況，用相對匯入
    from .build_cwe_index import COLLECTION_NAME, EMBEDDING_MODEL, QDRANT_HOST, QDRANT_PORT
except ImportError:
    # 攤平在同一層的情況，用一般匯入
    from cwe.build_cwe_index import COLLECTION_NAME, EMBEDDING_MODEL, QDRANT_HOST, QDRANT_PORT

from fastembed import TextEmbedding
from qdrant_client import QdrantClient

_model = None
_client = None


def _get_model() -> "TextEmbedding":
    global _model
    if _model is None:
        _model = TextEmbedding(EMBEDDING_MODEL)
    return _model


def _get_client() -> "QdrantClient":
    global _client
    if _client is None:
        _client = QdrantClient(host=QDRANT_HOST, port=QDRANT_PORT)
    return _client


def retrieve_cwe(query_text: str, top_k: int = 3) -> list[dict]:
    """
    回傳最相關的 top_k 筆 CWE 條目，每筆附上相似度分數（score，0~1，
    越高越相關），供之後的信心分數門檻機制使用。
    """
    model = _get_model()
    client = _get_client()

    query_vector = next(model.embed([query_text]))

    results = client.query_points(
        collection_name=COLLECTION_NAME,
        query=query_vector.tolist(),
        limit=top_k,
    ).points

    return [
        {
            "cwe_id": hit.payload["cwe_id"],
            "name": hit.payload["name"],
            "description": hit.payload["description"],
            "mitigations": hit.payload["mitigations"],
            "score": hit.score,
        }
        for hit in results
    ]


if __name__ == "__main__":
    import sys
    query = " ".join(sys.argv[1:]) or "device uses hardcoded default password"
    for r in retrieve_cwe(query):
        print(f"[{r['score']:.3f}] {r['cwe_id']} — {r['name']}")