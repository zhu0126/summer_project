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

retrieve_cra()：純向量語意檢索，保留當作 debug/對照用。
retrieve_cra_hybrid()：向量檢索 + BM25 關鍵字檢索合併（RRF），
正式流程建議使用這一版，理由跟 retrieve_cwe.py 一致。
"""
import importlib.util
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_HYBRID_SEARCH_PATH = _PROJECT_ROOT / "core" / "hybrid_search.py"


def _load_hybrid_search():
    """跟 cwe_kb/retrieve_cwe.py 的 _load_hybrid_search() 邏輯一致，
    直接照絕對路徑載入，不依賴 sys.path 搜尋順序。"""
    if not _HYBRID_SEARCH_PATH.is_file():
        print(f"[retrieve_cra] 警告：找不到 {_HYBRID_SEARCH_PATH}")
        return None, None, None
    try:
        spec = importlib.util.spec_from_file_location("hybrid_search", _HYBRID_SEARCH_PATH)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module.build_bm25_index, module.reciprocal_rank_fusion, module.tokenize
    except Exception as e:
        print(f"[retrieve_cra] 警告：載入 {_HYBRID_SEARCH_PATH} 失敗（{e}）")
        return None, None, None


try:
    # cra_kb 是子資料夾（package）的情況，用相對匯入
    from .build_cra_index import COLLECTION_NAME, EMBEDDING_MODEL, QDRANT_HOST, QDRANT_PORT
except ImportError:
    # 攤平在同一層的情況，用一般匯入
    from build_cra_index import COLLECTION_NAME, EMBEDDING_MODEL, QDRANT_HOST, QDRANT_PORT

build_bm25_index, reciprocal_rank_fusion, tokenize = _load_hybrid_search()

from fastembed import TextEmbedding
from qdrant_client import QdrantClient

CRA_DATA_PATH = Path(__file__).resolve().parent / "cra_data" / "cra_articles.json"

_model = None
_client = None
_bm25_index = None
_bm25_entries = None


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


def _get_bm25():
    global _bm25_index, _bm25_entries
    if _bm25_index is None:
        if build_bm25_index is None:
            raise ImportError("hybrid_search 無法匯入，請確認 core/hybrid_search.py 存在")
        _bm25_index, _bm25_entries = build_bm25_index(CRA_DATA_PATH)
    return _bm25_index, _bm25_entries


def _bm25_search(query_text: str, top_k: int) -> list[dict]:
    index, entries = _get_bm25()
    scores = index.get_scores(tokenize(query_text))
    ranked_idx = sorted(range(len(scores)), key=lambda i: scores[i], reverse=True)[:top_k]
    return [
        {
            "article_no": entries[i]["article_no"],
            "title": entries[i]["title"],
            "text": entries[i]["text"],
            "score": None,
        }
        for i in ranked_idx
    ]


def retrieve_cra(query_text: str, top_k: int = 3) -> list[dict]:
    """
    回傳最相關的 top_k 條 CRA 條文，每筆附上相似度分數（score，0~1，
    越高越相關）。純向量檢索，正式流程建議改用 retrieve_cra_hybrid()。
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


def retrieve_cra_hybrid(query_text: str, top_k: int = 3, candidate_k: int = 10) -> list[dict]:
    """
    混合檢索：dense（向量）+ sparse（BM25）合併排名，邏輯跟
    cwe_kb/retrieve_cwe.py 的 retrieve_cwe_hybrid() 完全對稱。
    每筆結果附 matched_by，標示是被哪種方法找到的。
    """
    try:
        dense_results = retrieve_cra(query_text, top_k=candidate_k)
    except Exception as e:
        print(f"[retrieve_cra] dense 檢索失敗，僅用 sparse 結果（{e}）")
        dense_results = []

    try:
        sparse_results = _bm25_search(query_text, candidate_k)
    except Exception as e:
        print(f"[retrieve_cra] sparse（BM25）檢索失敗，僅用 dense 結果（{e}）")
        sparse_results = []

    if not dense_results and not sparse_results:
        return []

    dense_ids = [r["article_no"] for r in dense_results]
    sparse_ids = [r["article_no"] for r in sparse_results]

    if reciprocal_rank_fusion is None:
        print("[retrieve_cra] hybrid_search 不可用，退化為 dense-only 排名")
        return [{**r, "matched_by": ["dense"]} for r in dense_results[:top_k]]

    fused_scores = reciprocal_rank_fusion([dense_ids, sparse_ids])

    dense_set = set(dense_ids)
    sparse_set = set(sparse_ids)

    payload_by_id = {r["article_no"]: r for r in sparse_results}
    payload_by_id.update({r["article_no"]: r for r in dense_results})

    ranked_ids = sorted(fused_scores.keys(), key=lambda i: fused_scores[i], reverse=True)[:top_k]

    results = []
    for article_no in ranked_ids:
        matched_by = []
        if article_no in dense_set:
            matched_by.append("dense")
        if article_no in sparse_set:
            matched_by.append("sparse")
        results.append({**payload_by_id[article_no], "matched_by": matched_by})

    return results


if __name__ == "__main__":
    query = " ".join(sys.argv[1:]) or "manufacturer obligations for vulnerability handling"
    for r in retrieve_cra_hybrid(query):
        matched = "+".join(r["matched_by"])
        score_str = f"{r['score']:.3f}" if r["score"] is not None else "n/a"
        print(f"[{matched:>11}] score={score_str}  {r['article_no']} — {r['title']}")