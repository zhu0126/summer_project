#!/usr/bin/env python3
"""
分析層的合併入口：串接 keyword_rules.py（規則查表）跟
cwe_kb/retrieve_cwe.py（RAG 語意檢索）兩條路徑。

合併原則：規則優先，RAG 補位，不是兩者都做取分數高的那個。
- 規則比對的內容是人工驗證過的（telnet→CWE-319 這種對應你確認過），
  可信度天生比向量相似度分數高。
- RAG 檢索的分數只反映「語意上多相似」，不代表「多正確」。
  兩者都做再比大小，容易讓規則已經確定的答案，被 RAG 檢索出的
  高分但不準的結果覆蓋掉。RAG 的定位是「補規則涵蓋不到的空白」，
  不是跟規則搶答案。

跟下游的關係：report.py 目前呼叫的是 keyword_rules.analyze_findings()，
這支模組的 analyze_findings() 回傳格式完全相容（多了 cwe_id/confidence
兩個新欄位），report.py 換過來呼叫這裡不需要改動樣板或合併邏輯。

CWE 知識庫是選用依賴：容器/測試環境可能沒有 Qdrant 或還沒建好索引，
import 失敗或查詢失敗都不該讓整條分析流程掛掉——退回只用規則比對的
結果，並印出警告讓使用者知道 RAG 這條路徑目前不可用。
"""
from keyword_rules import analyze_finding as rule_analyze_finding

try:
    # cwe_kb 是子資料夾的情況
    from cwe_kb.retrieve_cwe import retrieve_cwe
except ImportError:
    try:
        # cwe_kb 底下的檔案跟其他模組攤平在同一層的情況
        from retrieve_cwe import retrieve_cwe
    except ImportError:
        retrieve_cwe = None

try:
    from cra_kb.retrieve_cra import retrieve_cra
except ImportError:
    try:
        from retrieve_cra import retrieve_cra
    except ImportError:
        retrieve_cra = None

# 語意檢索分數低於這個門檻，不採用，直接標記 needs_review，
# 避免把「語意上勉強相關」的結果當成可信的判讀結果呈現出去。
CONFIDENCE_THRESHOLD = 0.5

# CRA 目前只用同一個門檻值當起點——實測發現分數分佈沒有明顯的
# 「相關/不相關」斷點（真正相關的 0.573 跟不相關的 Article 24 只
# 差 0.03），這個門檻值還沒有足夠的查詢樣本驗證過，先沿用 CWE 的
# 設定，之後累積更多真實查詢結果再回頭校準。
CRA_CONFIDENCE_THRESHOLD = 0.5

# 找不到 CWE 對應的具體風險等級時的預設值——CWE 本身不像
# keyword_rules 那樣附帶人工評定的風險等級，先給 medium 當保守估計，
# 之後有更好的判斷依據（例如串接 CVSS）再取代這個寫死的值。
RAG_DEFAULT_RISK_LEVEL = "medium"


def _rag_lookup(finding: dict) -> dict | None:
    """
    嘗試用 RAG 查詢，任何失敗（模組不存在、Qdrant 連不上、collection
    還沒建立）都回傳 None，讓呼叫端自然 fallback 到 needs_review，
    不讓分析層因為 RAG 這條選用路徑掛掉整個流程。
    """
    if retrieve_cwe is None:
        return None

    try:
        candidates = retrieve_cwe(finding["title"], top_k=1)
    except Exception as e:
        print(f"[analysis] RAG 查詢失敗，略過此路徑（{e}）")
        return None

    if not candidates:
        return None

    top = candidates[0]
    if top["score"] < CONFIDENCE_THRESHOLD:
        return None

    return top


def _cra_lookup(finding: dict) -> dict | None:
    """
    跟 _rag_lookup 邏輯一致，但查詢對象是 CRA collection。
    只取 top_k=1（不是 top 3）——實測發現向量資料庫裡的 Article
    （程序性條文）常常會以接近的分數混進第二三名，把不相關的內容
    也一起呈現只會誤導使用者；只看分數最高的第一名，配合信心門檻
    決定要不要採用，比「多給幾個候選讓使用者自己判斷」更不容易
    誤導人。
    """
    if retrieve_cra is None:
        return None

    try:
        candidates = retrieve_cra(finding["title"], top_k=1)
    except Exception as e:
        print(f"[analysis] CRA RAG 查詢失敗，略過此路徑（{e}）")
        return None

    if not candidates:
        return None

    top = candidates[0]
    if top["score"] < CRA_CONFIDENCE_THRESHOLD:
        return None

    return top


def _enrich_cra_reference(result: dict, finding: dict) -> dict:
    """
    只在這筆結果還沒有 cra_reference 時才嘗試用 RAG 補上——已經有
    值代表是 keyword_rules.py 裡人工確認過的引用，可信度比向量檢索
    高，不能被 RAG 結果覆蓋掉。needs_review 的結果不做這個補強：
    連「有沒有問題」都還不確定時，附上法規引用反而顯得像是已經
    做出判斷，容易誤導。
    """
    if result["status"] != "matched" or result.get("cra_reference"):
        return result

    hit = _cra_lookup(finding)
    if hit is None:
        return result

    # 明確標示這是 RAG 檢索出來的，附上信心分數，跟人工確認過的
    # 引用（沒有這個標記跟分數）在呈現上有區別，避免使用者誤以為
    # 兩者可信度一樣。
    result["cra_reference"] = (
        f"{hit['article_no']}（{hit['title']}）"
        f" — 語意檢索建議，信心分數 {hit['score']:.2f}，建議人工複核"
    )
    return result


def analyze_finding(finding: dict) -> dict:
    """
    分析單一 finding，依序：
    1. 規則比對（keyword_rules），比對到就直接採用
    2. 規則沒比對到，改用 RAG 語意檢索（CWE），信心分數過門檻才採用
    3. 兩者都沒有可信結果，標記 needs_review，不硬掰答案
    4. 只要最終判定是 matched，且還沒有 CRA 條文引用，額外嘗試用
       CRA RAG 補上（不覆蓋已經人工確認過的引用）
    """
    rule_result = rule_analyze_finding(finding)
    if rule_result["status"] == "matched":
        result = {**rule_result, "cwe_id": None, "confidence": None}
        return _enrich_cra_reference(result, finding)

    rag_hit = _rag_lookup(finding)
    if rag_hit is not None:
        recommendation = (
            rag_hit["mitigations"][0] if rag_hit["mitigations"] else rag_hit["description"]
        )
        result = {
            "finding_id": finding["finding_id"],
            "target": finding["target"],
            "title": finding["title"],
            "status": "matched",
            "risk_level": RAG_DEFAULT_RISK_LEVEL,
            "recommendation": recommendation,
            "cra_reference": None,  # CWE 不是法規條文，這欄留空，交給下面的 CRA 補強
            "cwe_id": rag_hit["cwe_id"],
            "confidence": rag_hit["score"],
        }
        return _enrich_cra_reference(result, finding)

    # 規則跟 RAG 都沒有可信結果，誠實標記需要人工複核
    return {**rule_result, "status": "needs_review", "cwe_id": None, "confidence": None}


def analyze_findings(findings: list[dict]) -> list[dict]:
    """對一批 findings 逐一分析，回傳合併後的分析結果清單。"""
    return [analyze_finding(f) for f in findings]


if __name__ == "__main__":
    from common import make_finding

    sample_findings = [
        make_finding("network", "nmap", "192.168.1.20", "info", "tcp/23 telnet",
                     detail={"service": "telnet", "state": "open"}),
        make_finding("network", "nmap", "192.168.1.20", "info", "tcp/9999 unknown-svc",
                     detail={"service": "unknown-svc", "state": "open"}),
    ]
    for r in analyze_findings(sample_findings):
        print(r)