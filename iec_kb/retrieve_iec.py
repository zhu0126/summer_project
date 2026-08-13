#!/usr/bin/env python3
"""
查詢函式：拿一段文字去 Qdrant 的 iec62443_4_1 / iec62443_4_2 collection
找最相關的要求條目。結構跟 cra_kb/retrieve_cra.py 完全對稱，差別只在
多一個 part 參數（要查哪一部標準）。

回傳欄位刻意跟 retrieve_cra.py 對齊（article_no / title / text / score /
matched_by），下游 core/rag_context.py、core/analysis.py、報告樣板才能
用同一套邏輯處理三個知識庫的候選，不用為 IEC 另外寫一份。

跟 CRA 的定位差異（複核時要記得的）：CRA 是具強制力的法規，62443 是
自願性標準——除非產品所在的產業或客戶合約明確要求符合 62443，否則
「對應到某條 CR」不代表有法律義務。這裡回傳的一樣只是「語意上最相關
的條目」，不是適用性判定，仍然需要人工複核。

retrieve_iec()：純向量語意檢索，保留當作 debug/對照用。
retrieve_iec_hybrid()：向量檢索 + BM25 關鍵字檢索合併（RRF），
正式流程使用這一版，理由跟另外兩個知識庫一致。
"""
import importlib.util
import sys
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_HYBRID_SEARCH_PATH = _PROJECT_ROOT / "core" / "hybrid_search.py"


def _load_hybrid_search():
    """跟 cwe_kb/cra_kb 的同名函式邏輯一致：照絕對路徑載入，
    不依賴 sys.path 搜尋順序。"""
    if not _HYBRID_SEARCH_PATH.is_file():
        print(f"[retrieve_iec] 警告：找不到 {_HYBRID_SEARCH_PATH}")
        return None, None, None
    try:
        spec = importlib.util.spec_from_file_location("hybrid_search", _HYBRID_SEARCH_PATH)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module.build_bm25_index, module.reciprocal_rank_fusion, module.tokenize
    except Exception as e:
        print(f"[retrieve_iec] 警告：載入 {_HYBRID_SEARCH_PATH} 失敗（{e}）")
        return None, None, None


try:
    from .build_iec_index import (
        DEFAULT_FINDING_PART, EMBEDDING_MODEL, PARTS, QDRANT_HOST, QDRANT_PORT, data_path,
    )
except ImportError:
    from build_iec_index import (  # type: ignore[no-redef]
        DEFAULT_FINDING_PART, EMBEDDING_MODEL, PARTS, QDRANT_HOST, QDRANT_PORT, data_path,
    )

build_bm25_index, reciprocal_rank_fusion, tokenize = _load_hybrid_search()

from fastembed import TextEmbedding
from qdrant_client import QdrantClient

_model = None
_client = None
# BM25 索引 per part：兩部標準各自一份語料，不共用（合併會讓 BM25 的
# 詞頻統計跨越兩份性質不同的文件，稀釋掉各自的鑑別度）
_bm25_cache: dict[str, tuple] = {}


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


def _get_bm25(part: str):
    if part not in _bm25_cache:
        if build_bm25_index is None:
            raise ImportError("hybrid_search 無法匯入，請確認 core/hybrid_search.py 存在")
        _bm25_cache[part] = build_bm25_index(data_path(part))
    return _bm25_cache[part]


def _entry_to_result(entry: dict, score: float | None) -> dict:
    return {
        "article_no": entry["article_no"],
        "clause_id": entry.get("clause_id", ""),
        "standard": entry.get("standard", ""),
        "title": entry.get("title", ""),
        "group": entry.get("group", ""),
        "text": entry.get("text", ""),
        "security_levels": entry.get("security_levels", ""),
        "score": score,
    }


def _bm25_search(query_text: str, part: str, top_k: int) -> list[dict]:
    index, entries = _get_bm25(part)
    scores = index.get_scores(tokenize(query_text))
    ranked_idx = sorted(range(len(scores)), key=lambda i: scores[i], reverse=True)[:top_k]
    return [_entry_to_result(entries[i], None) for i in ranked_idx]


def retrieve_iec(query_text: str, part: str = DEFAULT_FINDING_PART, top_k: int = 3) -> list[dict]:
    """
    回傳最相關的 top_k 條要求條目，每筆附相似度分數（score，0~1）。
    純向量檢索，正式流程建議改用 retrieve_iec_hybrid()。
    """
    if part not in PARTS:
        raise ValueError(f"未知的 part：{part}（可用：{', '.join(sorted(PARTS))}）")

    model = _get_model()
    client = _get_client()
    query_vector = next(model.embed([query_text]))

    results = client.query_points(
        collection_name=PARTS[part]["collection"],
        query=query_vector.tolist(),
        limit=top_k,
    ).points

    return [_entry_to_result(hit.payload, hit.score) for hit in results]


def retrieve_iec_hybrid(
    query_text: str,
    part: str = DEFAULT_FINDING_PART,
    top_k: int = 3,
    candidate_k: int = 10,
) -> list[dict]:
    """
    混合檢索：dense（向量）+ sparse（BM25）用 RRF 合併排名，邏輯跟
    retrieve_cra_hybrid() / retrieve_cwe_hybrid() 完全對稱。
    每筆結果附 matched_by，標示是被哪種方法找到的。

    BM25 這一路對這份語料特別重要：62443 的條文用的是 "the component
    shall provide the capability to..." 這種制式法規句型，跟掃描結果的
    詞彙（telnet、TLS、firmware）差距很大，純向量檢索容易被句型帶偏；
    關鍵字比對反而能穩定命中 authentication / encryption / session
    這些真正該對上的詞。
    """
    try:
        dense_results = retrieve_iec(query_text, part=part, top_k=candidate_k)
    except Exception as e:
        print(f"[retrieve_iec] dense 檢索失敗，僅用 sparse 結果（{e}）")
        dense_results = []

    try:
        sparse_results = _bm25_search(query_text, part, candidate_k)
    except Exception as e:
        print(f"[retrieve_iec] sparse（BM25）檢索失敗，僅用 dense 結果（{e}）")
        sparse_results = []

    if not dense_results and not sparse_results:
        return []

    dense_ids = [r["article_no"] for r in dense_results]
    sparse_ids = [r["article_no"] for r in sparse_results]

    if reciprocal_rank_fusion is None:
        print("[retrieve_iec] hybrid_search 不可用，退化為 dense-only 排名")
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
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    part = next((a.split("=", 1)[1] for a in sys.argv[1:] if a.startswith("--part=")),
                DEFAULT_FINDING_PART)
    query = " ".join(args) or "telnet service transmits credentials in cleartext"

    print(f"查詢 IEC 62443-{part}：{query}\n")
    for r in retrieve_iec_hybrid(query, part=part):
        matched = "+".join(r["matched_by"])
        score_str = f"{r['score']:.3f}" if r["score"] is not None else "n/a"
        print(f"[{matched:>11}] score={score_str}  {r['article_no']} — {r['title']}")
