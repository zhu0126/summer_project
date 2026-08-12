#!/usr/bin/env python3
"""
RAG 分數取樣工具：對一批具代表性的查詢，分別打 CWE 跟 CRA 兩個
collection，把 top-5 的完整分數印出來，用來實際觀察分數分佈，
而不是憑感覺猜一個信心門檻。

刻意不在這裡假設「正確答案應該是哪個 CWE/CRA 條文」——網路安全
領域很多情況下，同一個弱點可以合理對應到好幾種不同粒度的 CWE
分類，硬性認定一個「標準答案」容易帶入我自己的偏見。這支工具
只負責把數字攤開來，交給你依實際判斷力去看「這個分數/margin
組合，第一名到底像不像真的答案」。

用法：
    python3 test_rag_scores.py
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cwe_kb.retrieve_cwe import retrieve_cwe
from cra_kb.retrieve_cra import retrieve_cra

# 涵蓋幾種不同情境：規則已覆蓋的（當對照組，理論上 RAG 也該查得到
# 類似結果）、規則沒覆蓋的常見服務、韌體常見元件、故意放的無意義
# 查詢（當雜訊基準線，看看「完全不該有答案」的查詢分數長怎樣）。
SAMPLE_QUERIES = [
    # 規則已覆蓋，當對照組
    "telnet service",
    "ftp service",

    # 規則沒覆蓋，常見網路服務
    "redis service",
    "mqtt service",
    "modbus service",
    "vnc service",
    "microsoft-ds service Samba",
    "ms-wbt-server service",

    # 韌體常見元件
    "U-Boot version string",
    "BusyBox v1.19.4",

    # 雜訊基準線：完全無意義或過於籠統的查詢，觀察「不該有好答案」
    # 的查詢，分數大概落在什麼範圍，當作雜訊基準參考
    "xyz123 random string",
    "generic network service",
]


def print_results(label: str, results: list[dict], id_key: str, name_key: str) -> None:
    if not results:
        print(f"    {label}: (no results)")
        return

    top_score = results[0]["score"]
    margin = top_score - results[1]["score"] if len(results) > 1 else None
    margin_str = f"{margin:.3f}" if margin is not None else "n/a"

    print(f"    {label}  (top1={top_score:.3f}, margin={margin_str})")
    for i, r in enumerate(results):
        print(f"      #{i+1} score={r['score']:.3f}  {r[id_key]} — {r[name_key][:70]}")


def main():
    for query in SAMPLE_QUERIES:
        print(f"[QUERY] {query!r}")

        try:
            cwe_results = retrieve_cwe(query, top_k=5)
        except Exception as e:
            cwe_results = []
            print(f"    CWE 查詢失敗: {e}")
        print_results("CWE", cwe_results, "cwe_id", "name")

        try:
            cra_results = retrieve_cra(query, top_k=5)
        except Exception as e:
            cra_results = []
            print(f"    CRA 查詢失敗: {e}")
        print_results("CRA", cra_results, "article_no", "title")

        print()


if __name__ == "__main__":
    main()