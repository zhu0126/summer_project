#!/usr/bin/env python3
"""
查詢函式：拿一段文字（例如 finding 的 title 或 detail 內容）去 Qdrant
的 "cra" collection 找最相關的 CRA 條文。

跟 keyword_rules.py 的關係：這是 cra_reference 欄位未來要從「手動挑選
的佔位範例」升級成「真正語意檢索到的條文」的資料來源。回傳欄位刻意
跟 retrieve_cwe.py 對齊風格（article_no 對應 cwe_id、text 對應
description），方便之後用同一套邏輯整合進 analyze_findings()。

注意：CRA 是具強制力的法規，不是 CWE 那種弱點分類參考資料。這裡回傳
的是「語意上最相關的條文」，不代表法律上必然適用，仍然需要人工複核，
之前分析層設計時就一直強調的這個原則同樣適用在這裡。
"""
try:
    # cra_kb 是子資料夾（package）的情況，用相對匯入
    from .build_cra_index import COLLECTION_NAME, EMBEDDING_MODEL, QDRANT_HOST, QDRANT_PORT
except ImportError:
    # 攤平在同一層的情況，用一般匯入
    from cra.build_cra_index import COLLECTION_NAME, EMBEDDING_MODEL, QDRANT_HOST, QDRANT_PORT

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


def retrieve_cra(query_text: str, top_k: int = 3) -> list[dict]:
    """
    回傳最相關的 top_k 條 CRA 條文，每筆附上相似度分數（score，0~1，
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
            "article_no": hit.payload["article_no"],
            "title": hit.payload["title"],
            "text": hit.payload["text"],
            "score": hit.score,
        }
        for hit in results
    ]


if __name__ == "__main__":
    import sys
    query = " ".join(sys.argv[1:]) or "manufacturer obligations for vulnerability handling"
    for r in retrieve_cra(query):
        print(f"[{r['score']:.3f}] {r['article_no']} — {r['title']}")