#!/usr/bin/env python3
"""
Hybrid search 共用工具：BM25 關鍵字檢索的建置邏輯，跟合併 dense
（向量）/ sparse（關鍵字）兩路排名結果的 Reciprocal Rank Fusion（RRF）。

為什麼不直接改 Qdrant collection 加 sparse vector（Qdrant 原生支援
混合檢索的做法）：那樣需要重新 embedding、重建整個索引，你們已經
在建索引這步撞過一次 OOM，風險偏高。這裡改在應用層另外做一份 BM25
索引（純 Python，輕量，不用重新 embedding），跟現有的向量檢索結果
在記憶體裡合併，完全不用動 Qdrant 的資料。

為什麼合併方式選 RRF，不是直接加權平均兩種分數：
cosine 相似度是 0~1 的界定範圍，BM25 分數沒有上限、量級因語料庫
而異，兩者直接加權平均需要先校準才有意義，校準本身又是一次沒有
依據的猜測（跟先前信心門檻踩到的坑一樣）。RRF 只看「排名的名次」，
不看分數的絕對值，兩種完全不同量級的排名結果可以直接合併，不需要
額外校準這一步。
"""
import re
from pathlib import Path

try:
    from rank_bm25 import BM25Okapi
except ImportError:
    BM25Okapi = None


def tokenize(text: str) -> list[str]:
    """
    簡單的英文斷詞：轉小寫、只留英數字。CWE/CRA 條文都是英文技術/
    法律文本，不需要處理中文分詞，用正規表示式切字就足夠。
    """
    return re.findall(r"[a-z0-9]+", text.lower())


def build_bm25_index(data_path: Path, text_field: str = "embedding_text"):
    """
    從既有的 entries json（cwe_entries.json / cra_articles.json）
    建 BM25 索引，直接沿用 fetch_*.py 已經產生好的 embedding_text
    欄位當語料，不用另外重新整理一份文字。

    回傳 (bm25_index, entries)，entries 保留原始 list，之後依索引
    位置對回完整的條目內容（cwe_id/article_no 等欄位）。
    """
    if BM25Okapi is None:
        raise ImportError("rank_bm25 not installed. Run: pip install rank-bm25")
    if not data_path.is_file():
        raise FileNotFoundError(f"{data_path} not found，請先執行對應的 fetch_*.py")

    import json
    entries = json.loads(data_path.read_text(encoding="utf-8"))
    corpus = [tokenize(e[text_field]) for e in entries]
    return BM25Okapi(corpus), entries


def reciprocal_rank_fusion(rank_lists: list[list[str]], k: int = 60) -> dict[str, float]:
    """
    標準 RRF 公式：score(d) = Σ 1 / (k + rank(d))，rank 從 1 開始算，
    只在某個排名列表裡出現過的文件才會被加總，同時出現在多個列表
    裡的文件分數會疊加（等於是在給「多方法都認同」的候選加分）。
    k=60 是 RRF 原始論文跟後續實務上常用的預設值，不是隨便選的數字，
    這個常數的作用是壓低排名靠後結果的影響力，不需要每個應用場景
    重新調參。
    """
    scores: dict[str, float] = {}
    for rank_list in rank_lists:
        for rank, doc_id in enumerate(rank_list, start=1):
            scores[doc_id] = scores.get(doc_id, 0.0) + 1.0 / (k + rank)
    return scores