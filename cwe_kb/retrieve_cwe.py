#!/usr/bin/env python3
"""
查詢函式：拿一段文字（例如 finding 的 title 或 detail 內容）去 Qdrant
的 "cwe" collection 找最相關的 CWE 條目。

跟 keyword_rules.py 的關係：這是未來要取代/補強 keyword_rules.py
的其中一個資料來源。介面刻意設計成回傳跟 keyword_rules 相容的資訊
（cwe_id/name/description/mitigations + score 當作 confidence 的依據），
方便之後接進 analyze_findings() 那一層的統一介面。

retrieve_cwe()：純向量語意檢索，保留下來當作 debug 用（跟只測
dense 這一路的分數時方便對照），正式流程建議改用下面的
retrieve_cwe_hybrid()。

retrieve_cwe_hybrid()：向量檢索（dense）+ BM25 關鍵字檢索（sparse）
合併結果，用 hybrid_search.py 的 RRF 邏輯排名。單純向量檢索對
「redis」「modbus」這種產品/協定名稱的查詢效果不好（CWE 條目描述
的是抽象弱點類型，原文不會出現這些專有名詞），BM25 關鍵字比對能
補上這塊——如果查詢字串本身包含跟 CWE 條目重疊的專有詞彙（例如
finding 標題含有 "authentication"、"encryption" 這類字眼），BM25
能直接命中，dense 檢索則負責抓語意上相關但用詞不同的內容，兩者互補。
"""
import sys
from pathlib import Path

# 確保不管是「從專案根目錄呼叫」還是「cd 進 cwe_kb 單獨測試」，都能
# 找到專案根目錄的 hybrid_search.py——後者的情況下 cwe_kb/ 本身
# 不會自動把上一層目錄加進搜尋路徑。
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

try:
    # cwe_kb 是子資料夾（package）的情況，用相對匯入
    from .build_cwe_index import COLLECTION_NAME, EMBEDDING_MODEL, QDRANT_HOST, QDRANT_PORT
except ImportError:
    # 攤平在同一層的情況，用一般匯入
    from build_cwe_index import COLLECTION_NAME, EMBEDDING_MODEL, QDRANT_HOST, QDRANT_PORT

try:
    from hybrid_search import build_bm25_index, reciprocal_rank_fusion, tokenize
except ImportError:
    build_bm25_index = reciprocal_rank_fusion = tokenize = None

from fastembed import TextEmbedding
from qdrant_client import QdrantClient

# 用 __file__ 錨定絕對路徑，不用 build_cwe_index.py 裡那個相對路徑的
# INPUT_PATH——那個相對路徑是設計給「在 cwe_kb/ 資料夾裡手動執行」
# 的情境，透過 analysis.py 從專案根目錄呼叫時，CWD 不是 cwe_kb/，
# 相對路徑會解析到錯的地方（跟先前 output_dir 遇到的問題同一種陷阱）。
CWE_DATA_PATH = Path(__file__).resolve().parent / "cwe_data" / "cwe_entries.json"

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
            raise ImportError("hybrid_search 無法匯入，請確認 hybrid_search.py 存在於專案根目錄")
        _bm25_index, _bm25_entries = build_bm25_index(CWE_DATA_PATH)
    return _bm25_index, _bm25_entries


def _bm25_search(query_text: str, top_k: int) -> list[dict]:
    index, entries = _get_bm25()
    scores = index.get_scores(tokenize(query_text))
    ranked_idx = sorted(range(len(scores)), key=lambda i: scores[i], reverse=True)[:top_k]
    return [
        {
            "cwe_id": entries[i]["cwe_id"],
            "name": entries[i]["name"],
            "description": entries[i]["description"],
            "mitigations": entries[i]["mitigations"],
            "score": None,  # BM25 分數量級跟 cosine 不同，不直接顯示，避免使用者誤解成同一種分數
        }
        for i in ranked_idx
    ]


def retrieve_cwe(query_text: str, top_k: int = 3) -> list[dict]:
    """
    回傳最相關的 top_k 筆 CWE 條目，每筆附上相似度分數（score，0~1，
    越高越相關）。這是純向量檢索，正式流程建議改用下面的
    retrieve_cwe_hybrid()，這支保留當作 debug/對照用。
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


def retrieve_cwe_hybrid(query_text: str, top_k: int = 3, candidate_k: int = 10) -> list[dict]:
    """
    混合檢索：dense（向量語意）+ sparse（BM25 關鍵字）各自取
    candidate_k 筆候選，用 RRF 合併排名，回傳前 top_k 筆。

    任一路徑失敗都優雅降級，不讓整個查詢掛掉：
    - dense 失敗（Qdrant 連不上）→ 只用 sparse 結果
    - sparse 失敗（rank_bm25 沒裝、cwe_entries.json 不存在）→ 只用 dense 結果
    - 兩者都失敗 → 回傳空 list，交給呼叫端（analysis.py）處理

    每筆結果額外帶 matched_by 欄位，標示這筆是被哪一種或兩種方法
    找到的——同時被 dense 跟 sparse 都選中的候選，通常比只被單一
    方法選中的更值得信賴，這個資訊對人工複核判斷很有參考價值，
    比單看一個混合後的抽象分數更直覺。
    """
    try:
        dense_results = retrieve_cwe(query_text, top_k=candidate_k)
    except Exception as e:
        print(f"[retrieve_cwe] dense 檢索失敗，僅用 sparse 結果（{e}）")
        dense_results = []

    try:
        sparse_results = _bm25_search(query_text, candidate_k)
    except Exception as e:
        print(f"[retrieve_cwe] sparse（BM25）檢索失敗，僅用 dense 結果（{e}）")
        sparse_results = []

    if not dense_results and not sparse_results:
        return []

    dense_ids = [r["cwe_id"] for r in dense_results]
    sparse_ids = [r["cwe_id"] for r in sparse_results]

    # reciprocal_rank_fusion 本身也可能是 None（hybrid_search.py 整個
    # 匯入失敗時，見檔案開頭的 try/except）——這是先前的漏洞：只保護了
    # _bm25_search 那一段，卻沒保護緊接著呼叫 reciprocal_rank_fusion
    # 這一步，一旦匯入失敗就會撞上 "'NoneType' object is not callable"
    # 這種看起來莫名其妙的錯誤。這裡補上防護：沒有 RRF 可用時，直接
    # 退化成只用 dense 排名（sparse 那份候選就不合併了），不要整個掛掉。
    if reciprocal_rank_fusion is None:
        print("[retrieve_cwe] hybrid_search 不可用，退化為 dense-only 排名")
        return [{**r, "matched_by": ["dense"]} for r in dense_results[:top_k]]

    fused_scores = reciprocal_rank_fusion([dense_ids, sparse_ids])

    dense_set = set(dense_ids)
    sparse_set = set(sparse_ids)

    # payload 優先用 dense 結果（帶真實 cosine score，比較有參考價值），
    # dense 沒有的才用 sparse 的 payload 補上
    payload_by_id = {r["cwe_id"]: r for r in sparse_results}
    payload_by_id.update({r["cwe_id"]: r for r in dense_results})

    ranked_ids = sorted(fused_scores.keys(), key=lambda i: fused_scores[i], reverse=True)[:top_k]

    results = []
    for cwe_id in ranked_ids:
        matched_by = []
        if cwe_id in dense_set:
            matched_by.append("dense")
        if cwe_id in sparse_set:
            matched_by.append("sparse")
        results.append({**payload_by_id[cwe_id], "matched_by": matched_by})

    return results


if __name__ == "__main__":
    import sys
    query = " ".join(sys.argv[1:]) or "device uses hardcoded default password"
    for r in retrieve_cwe_hybrid(query):
        matched = "+".join(r["matched_by"])
        score_str = f"{r['score']:.3f}" if r["score"] is not None else "n/a"
        print(f"[{matched:>11}] score={score_str}  {r['cwe_id']} — {r['name']}")