#!/usr/bin/env python3
"""
分析層的合併入口：串接 keyword_rules.py（規則查表）跟
cwe_kb/retrieve_cwe.py、cra_kb/retrieve_cra.py（RAG 語意檢索）。

設計轉折（重要）：RAG 曾經被設計成「規則沒比對到時，信心分數過
門檻就自動判定 matched」，但實測發現這個門檻在數學上不成立——
拿完全無意義的查詢字串（如 "xyz123 random string"）當雜訊基準線，
它的分數（0.651）比已知正確的規則對照組（telnet, 0.589）還高。
這代表向量相似度分數在這個 embedding model + 這個領域的組合下，
沒有能力區分「真的相關」跟「純粹雜訊」，任何固定門檻要嘛太寬鬆
（雜訊也放行），要嘛太嚴格（連正確答案也被擋掉）。

因此改變 RAG 在系統裡的角色：規則沒比對到時，RAG **不再自己判定
matched**，一律維持 status="needs_review"，只附上 CWE/CRA 各前
幾名候選（含分數）給使用者在複核時參考。這比較誠實地反映目前
系統實際的判讀能力，也符合一路以來的原則——AI 判讀是輔助，
不是最終定論。

跟下游的關係：report.py 呼叫的是 analyze_findings()，回傳格式
比舊版多了 rag_suggestions 這個欄位（規則已比對到時是 None，
規則沒比對到時是 {"cwe": [...], "cra": [...]}），report.py 的
樣板要相應調整才能呈現這份候選建議。

LLM 研判（llm_advice）：analyze_findings(use_llm=True) 時，會把上面
那份候選再交給 core/llm_advisor.py 產出一段文字研判。這一步同樣
不改變 status——它只是把「這五條可能有關」變成「這筆發現跟這幾條的
關係是什麼」，讓人工複核有個起點，判定權仍然在人身上。預設關閉，
理由見 analyze_finding() 的 docstring。

CWE/CRA 知識庫都是選用依賴：import 失敗或查詢失敗都不該讓整條
分析流程掛掉——退回只用規則比對的結果，並印出警告讓使用者知道
RAG 這條路徑目前不可用。
"""
from core.keyword_rules import analyze_finding as rule_analyze_finding

try:
    # cwe_kb 是子資料夾的情況
    from cwe_kb.retrieve_cwe import retrieve_cwe_hybrid
except ImportError:
    try:
        # cwe_kb 底下的檔案跟其他模組攤平在同一層的情況
        from retrieve_cwe import retrieve_cwe_hybrid
    except ImportError:
        retrieve_cwe_hybrid = None
        print("[analysis] 警告：cwe_kb 無法匯入，CWE 候選建議停用")

try:
    from cra_kb.retrieve_cra import retrieve_cra_hybrid
except ImportError:
    try:
        from retrieve_cra import retrieve_cra_hybrid
    except ImportError:
        retrieve_cra_hybrid = None
        print("[analysis] 警告：cra_kb 無法匯入，CRA 候選建議停用")

try:
    from core.llm_advisor import advise_finding as llm_advise_finding
except ImportError:
    llm_advise_finding = None
    print("[analysis] 警告：llm_advisor 無法匯入，LLM 研判建議停用")

# 每個知識庫各給幾筆候選——不做信心分數過濾（實測證明單一門檻無法
# 區分雜訊跟真訊號），改成把前幾名都列出來，交給人腦判斷，而不是
# 假裝系統能自動篩出「唯一正確答案」。
RAG_SUGGESTION_TOP_K = 5


def _build_rag_query(finding: dict) -> str:
    """
    RAG 查詢用的文字，不要直接拿 finding['title'] 那種帶 port/protocol
    格式的字串去查（例如 network 類別的 title 長得像 "tcp/6379 redis"）。
    這種格式混雜了協定名稱、port 數字這些對語意檢索沒有幫助的雜訊，
    會稀釋掉真正有意義的關鍵字（"redis"）。

    改成依 category 組一段更接近自然語言的描述：
    - network：用 service（+product/version，如果有）組成 "xxx service"
      這種描述，不帶 protocol/port 數字
    - firmware/webapp：title 本身已經是描述性文字（例如 binwalk 的
      訊號描述、ZAP 的 alert 名稱），直接沿用即可
    """
    category = finding.get("category")
    detail = finding.get("detail", {})

    if category == "network":
        service = detail.get("service") or finding["title"]
        parts = [f"{service} service"]
        product = detail.get("product", "")
        version = detail.get("version", "")
        if product:
            parts.append(product)
        if version:
            parts.append(version)
        return " ".join(parts)

    return finding["title"]


def _cwe_candidates(finding: dict) -> list[dict]:
    """
    回傳 CWE 候選清單（hybrid：dense+sparse 合併排名，不做信心分數
    過濾），任何失敗（模組不存在、Qdrant 連不上、collection 還沒
    建立）都回傳空 list，不讓分析層因為這條選用路徑掛掉整個流程。
    """
    if retrieve_cwe_hybrid is None:
        return []
    try:
        return retrieve_cwe_hybrid(_build_rag_query(finding), top_k=RAG_SUGGESTION_TOP_K)
    except Exception as e:
        print(f"[analysis] CWE 候選查詢失敗，略過（{e}）")
        return []


def _cra_candidates(finding: dict) -> list[dict]:
    """跟 _cwe_candidates 邏輯一致，查詢對象是 CRA collection。"""
    if retrieve_cra_hybrid is None:
        return []
    try:
        return retrieve_cra_hybrid(_build_rag_query(finding), top_k=RAG_SUGGESTION_TOP_K)
    except Exception as e:
        print(f"[analysis] CRA 候選查詢失敗，略過（{e}）")
        return []


def _llm_advice(finding: dict, suggestions: dict) -> dict | None:
    """
    把檢索到的候選交給 LLM 產出一段研判建議（llm_advisor.py）。

    只在 needs_review 這條路徑上呼叫，而且吃的是上面剛檢索出來的
    同一份 suggestions——報告裡列給人看的候選，跟 LLM 實際讀到的
    候選必須是同一份，否則人工複核時無從判斷這段建議是根據什麼寫的。

    任何失敗都回 None（沒裝 google-genai、沒設金鑰、API 呼叫失敗），
    跟 CWE/CRA 檢索的降級原則一致：這是選用的加值路徑，不該讓整份
    分析結果產不出來。
    """
    if llm_advise_finding is None:
        return None
    try:
        return llm_advise_finding(finding, suggestions)
    except Exception as e:
        print(f"[analysis] LLM 研判失敗，略過（{e}）")
        return None


def analyze_finding(finding: dict, use_llm: bool = False) -> dict:
    """
    分析單一 finding：
    1. 規則比對（keyword_rules）成功 → 直接採用，這條路徑完全不變，
       仍然是系統裡唯一會自動判定 status="matched" 的來源
    2. 規則沒比對到 → 維持 status="needs_review"，附上 rag_suggestions
       （CWE/CRA 各前 N 名候選 + 分數），供人工複核時參考，不自動判定
    3. use_llm=True 時，額外把候選交給 LLM 產出一段文字研判
       （llm_advice），一樣只是附加的參考意見，不影響 status

    use_llm 預設 False 的理由：這條路徑會對外送出請求（掃描結果含
    目標 IP 與服務清單）、需要 API 金鑰、而且逐筆呼叫是有成本的。
    這種有外部副作用又要花錢的行為應該由使用者明確開啟，不該是
    跑一次 analyze_findings() 就默默發生的預設行為。
    """
    rule_result = rule_analyze_finding(finding)
    if rule_result["status"] == "matched":
        return {**rule_result, "cwe_id": None, "confidence": None,
                "rag_suggestions": None, "llm_advice": None}

    suggestions = {
        "cwe": _cwe_candidates(finding),
        "cra": _cra_candidates(finding),
    }

    return {
        "finding_id": finding["finding_id"],
        "target": finding["target"],
        "title": finding["title"],
        "status": "needs_review",
        "risk_level": "info",
        "recommendation": None,
        "cra_reference": None,
        "cwe_id": None,
        "confidence": None,
        "rag_suggestions": suggestions,
        "llm_advice": _llm_advice(finding, suggestions) if use_llm else None,
    }


def analyze_findings(findings: list[dict], use_llm: bool = False) -> list[dict]:
    """對一批 findings 逐一分析，回傳合併後的分析結果清單。"""
    return [analyze_finding(f, use_llm=use_llm) for f in findings]


if __name__ == "__main__":
    from core.common import make_finding

    sample_findings = [
        make_finding("network", "nmap", "192.168.1.20", "info", "tcp/23 telnet",
                     detail={"service": "telnet", "state": "open"}),
        make_finding("network", "nmap", "192.168.1.20", "info", "tcp/6379 redis",
                     detail={"service": "redis", "state": "open"}),
    ]
    for r in analyze_findings(sample_findings):
        print(r)