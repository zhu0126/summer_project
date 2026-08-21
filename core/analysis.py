#!/usr/bin/env python3
"""
分析層的合併入口：串接 keyword_rules.py（規則查表）跟
cwe_kb/retrieve_cwe.py、iec_kb/retrieve_iec.py、cra_kb/retrieve_cra.py
（RAG 語意檢索）。

設計轉折（重要）：RAG 曾經被設計成「規則沒比對到時，信心分數過
門檻就自動判定 matched」，但實測發現這個門檻在數學上不成立——
拿完全無意義的查詢字串（如 "xyz123 random string"）當雜訊基準線，
它的分數（0.651）比已知正確的規則對照組（telnet, 0.589）還高。
這代表向量相似度分數在這個 embedding model + 這個領域的組合下，
沒有能力區分「真的相關」跟「純粹雜訊」，任何固定門檻要嘛太寬鬆
（雜訊也放行），要嘛太嚴格（連正確答案也被擋掉）。

因此改變 RAG 在系統裡的角色：規則沒比對到時，RAG **不再自己判定
matched**，一律維持 status="needs_review"，只附上 CWE/IEC/CRA 各
信心最高的 1 筆候選，配上針對這筆 finding 產出的一句話修補建議，
給使用者在複核時參考。這比較誠實地反映目前系統實際的判讀能力，
也符合一路以來的原則——AI 判讀是輔助，不是最終定論。

跟下游的關係：report.py 呼叫的是 analyze_findings()，回傳格式
比舊版多了 rag_suggestions 這個欄位（規則已比對到時是 None，
規則沒比對到時是 {"cwe": [...], "iec": [...], "cra": [...]}），
report.py 的樣板要相應調整才能呈現這份候選建議。needs_review 項目
另外多一個 finding_summary 欄位（{"weakness_name", "weakness_reason",
"remediation"} 或 None），是把 rag_suggestions 三個知識庫的候選再讀一次
Claude 產出的卡片內容，供 webapp Compliance 頁待複核卡片使用，
見 llm_advisor.derive_finding_summary()。matched 項目（規則比對／CVE
比對）則是另外多一個 weakness_name 欄位（字串或 None），把規則表／CVE
判定已經算出的 recommendation、cra_reference 濃縮成卡片標題用的簡短
弱點名稱，取代直接顯示 finding.title 這種給人比對用的技術識別字串，
見 llm_advisor.derive_weakness_name()。兩個欄位的生成規則都明確禁止
把 IP、韌體/檔案名稱、URL 等識別特定目標的資訊寫進名稱本身——目標
資訊由呈現層另外附加在名稱旁邊，不該混進弱點名稱的敘述裡。

matched 項目另外帶 weakness_reason（弱點原因）與 iec_reference
（IEC 62443-4-2 條號），來源是 keyword_rules.py 的規則表或 _cve_match()，
都是人工維護、已查證的固定文字，不經過 LLM——理由見 keyword_rules.py
的說明（規則這條路徑的價值就在於離線可用且輸出穩定）。加上這兩個欄位
之後，matched 與 needs_review 兩種項目在呈現層可以用同一套「弱點原因／
未合規法規／修補建議」版面渲染，差別只在資料是查表來的還是檢索來的：

    matched       weakness_reason  / iec_reference + cra_reference / recommendation
    needs_review  finding_summary.weakness_reason
                                   / rag_suggestions.iec + .cra    / finding_summary.remediation

matched 的第三欄（修補建議）是這三欄裡唯一會經過 LLM 的：規則表寫死的
recommendation 是「這個服務該怎麼處理」的通則，並沒有對著哪一條條文寫，
但卡片上就列著那兩條要求，讀的人會想知道各自要求他做到什麼。因此改由
llm_advisor.derive_rule_remediation() 拿卡片上列出的那幾條（連同本地知識庫
裡的條文全文）生成，並在產出後跑引用查核，只要出現沒給過的條號就整段
捨棄、退回規則表原句——見 _finalize_matched()。前兩欄仍然完全不碰 LLM，
所以 LLM 不可用時卡片只是修補建議退回通則版，不會開天窗。這個轉換的
來源記在 recommendation_source（"llm"／"rule"），呈現層據此標示。

三個知識庫的分工：CWE 是弱點分類（這是什麼問題），IEC 62443-4-2 是
元件層級的技術要求（技術上該具備什麼能力），CRA 是法規義務（法律上
為什麼非做不可）。62443 的另一部 4-1 規範的是開發流程，跟逐筆掃描
結果對不上，改由 scan_level_process_requirements() 在整場掃描層級
查一次，理由見該函式的說明。

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
    from iec_kb.retrieve_iec import retrieve_iec_hybrid
except ImportError:
    try:
        from retrieve_iec import retrieve_iec_hybrid
    except ImportError:
        retrieve_iec_hybrid = None
        print("[analysis] 警告：iec_kb 無法匯入，IEC 62443 候選建議停用")

try:
    from core.llm_advisor import advise_finding as llm_advise_finding
    from core.llm_advisor import derive_cra_remediation
    from core.llm_advisor import derive_cwe_remediation
    from core.llm_advisor import derive_iec_remediation
    from core.llm_advisor import derive_finding_summary
    from core.llm_advisor import derive_weakness_name
    from core.llm_advisor import derive_rule_remediation
except ImportError:
    llm_advise_finding = None
    derive_cra_remediation = None
    derive_cwe_remediation = None
    derive_iec_remediation = None
    derive_finding_summary = None
    derive_weakness_name = None
    derive_rule_remediation = None
    print("[analysis] 警告：llm_advisor 無法匯入，LLM 研判建議停用")

# 每個知識庫只取信心最高的 1 筆——不做信心分數過濾（實測證明單一門檻
# 無法區分雜訊跟真訊號，見本檔案開頭說明），但列出多筆候選要求使用者
# 自己篩選的體驗也不好，改成只呈現最相關的一筆，配上 LLM 針對這筆
# finding 產出的一句話修補建議（見 _with_*_remediation()）。
RAG_SUGGESTION_TOP_K = 1


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


def _with_cwe_remediation(finding: dict, candidate: dict) -> dict:
    """跟 _with_cra_remediation 同一套邏輯，套用在 CWE 候選上。"""
    if derive_cwe_remediation is None:
        return {**candidate, "text_zh": None}
    try:
        text_zh = derive_cwe_remediation(
            finding, candidate.get("cwe_id", ""), candidate.get("name", ""), candidate.get("description", "")
        )
    except Exception as e:
        print(f"[analysis] CWE 修補建議產生失敗，略過（{e}）")
        text_zh = None
    return {**candidate, "text_zh": text_zh}


def _cwe_candidates(finding: dict) -> list[dict]:
    """
    回傳 CWE 候選清單（hybrid：dense+sparse 合併排名），只取信心最高的
    1 筆（見 RAG_SUGGESTION_TOP_K 的說明），附上針對這筆 finding 產出的
    一句話修補建議。任何失敗（模組不存在、Qdrant 連不上、collection
    還沒建立）都回傳空 list，不讓分析層因為這條選用路徑掛掉整個流程。
    """
    if retrieve_cwe_hybrid is None:
        return []
    try:
        candidates = retrieve_cwe_hybrid(_build_rag_query(finding), top_k=RAG_SUGGESTION_TOP_K)
    except Exception as e:
        print(f"[analysis] CWE 候選查詢失敗，略過（{e}）")
        return []

    return [_with_cwe_remediation(finding, c) for c in candidates]


def _cra_candidates(finding: dict) -> list[dict]:
    """
    跟 _cwe_candidates 邏輯一致，查詢對象是 CRA collection。額外幫每筆
    候選附上 text_zh——CRA 條文的 title 常常只是像 "Reporting obligations"
    這種抽象標題，條文全文（text）本身也是寫給所有產品類型看的通用法規
    文字，使用者讀了還是不知道「所以我該做什麼」。改附一句用 Claude 把
    「finding 本身 + 條文」一起讀完後產出的具體修補建議（見
    llm_advisor.derive_cra_remediation() 的說明），呈現層（webapp/report）
    改成優先顯示這欄。
    """
    if retrieve_cra_hybrid is None:
        return []
    try:
        candidates = retrieve_cra_hybrid(_build_rag_query(finding), top_k=RAG_SUGGESTION_TOP_K)
    except Exception as e:
        print(f"[analysis] CRA 候選查詢失敗，略過（{e}）")
        return []

    return [_with_cra_remediation(finding, c) for c in candidates]


def _with_cra_remediation(finding: dict, candidate: dict) -> dict:
    """
    附上 text_zh；找不到 LLM 路徑或呼叫失敗都回傳 text_zh=None，讓呈現層
    自己退回顯示 text（英文原文）——不能因為這條選用路徑失敗，就讓
    整筆候選消失或擋住其他候選的顯示。
    """
    if derive_cra_remediation is None:
        return {**candidate, "text_zh": None}
    try:
        text_zh = derive_cra_remediation(
            finding, candidate.get("article_no", ""), candidate.get("title", ""), candidate.get("text", "")
        )
    except Exception as e:
        print(f"[analysis] CRA 修補建議產生失敗，略過（{e}）")
        text_zh = None
    return {**candidate, "text_zh": text_zh}


def _with_iec_remediation(finding: dict, candidate: dict) -> dict:
    """跟 _with_cra_remediation 同一套邏輯，套用在 IEC 62443-4-2 候選上。"""
    if derive_iec_remediation is None:
        return {**candidate, "text_zh": None}
    try:
        text_zh = derive_iec_remediation(
            finding, candidate.get("article_no", ""), candidate.get("title", ""),
            candidate.get("group", ""), candidate.get("text", ""),
        )
    except Exception as e:
        print(f"[analysis] IEC 修補建議產生失敗，略過（{e}）")
        text_zh = None
    return {**candidate, "text_zh": text_zh}


def _iec_candidates(finding: dict) -> list[dict]:
    """
    跟 _cwe_candidates 邏輯一致，查詢對象是 IEC 62443-4-2（元件技術要求），
    只取信心最高的 1 筆，附上針對這筆 finding 產出的一句話修補建議。

    只查 4-2、不查 4-1：4-1 是開發流程要求（SM-4 安全專業能力、SVV-4
    滲透測試…），跟單一筆掃描結果在語意上沒有對應關係，混進同一份
    top-K 只會擠掉真正相關的 CR。4-1 改成整場掃描層級呈現，見
    scan_level_process_requirements()。
    """
    if retrieve_iec_hybrid is None:
        return []
    try:
        candidates = retrieve_iec_hybrid(_build_rag_query(finding), top_k=RAG_SUGGESTION_TOP_K)
    except Exception as e:
        print(f"[analysis] IEC 62443 候選查詢失敗，略過（{e}）")
        return []

    return [_with_iec_remediation(finding, c) for c in candidates]


def _llm_advice(finding: dict, suggestions: dict) -> dict | None:
    """
    把檢索到的候選交給 LLM 產出一段研判建議（llm_advisor.py）。

    只在 needs_review 這條路徑上呼叫，而且吃的是上面剛檢索出來的
    同一份 suggestions——報告裡列給人看的候選，跟 LLM 實際讀到的
    候選必須是同一份，否則人工複核時無從判斷這段建議是根據什麼寫的。

    任何失敗都回 None（沒裝 anthropic、沒設金鑰、API 呼叫失敗），
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


def _finding_summary(finding: dict, suggestions: dict) -> dict | None:
    """
    Compliance 頁待複核卡片要用的「弱點名稱／弱點原因／修補建議」，讀
    suggestions 裡剛檢索出的 CWE/IEC/CRA 各信心最高 1 筆候選（跟 llm_advice
    吃同一份，理由同 _llm_advice()：呈現給人看的候選跟 LLM 實際讀到的
    候選必須一致）。跟 text_zh（各知識庫獨立的一句話行動建議）不是同一
    份資料，是額外呼叫一次 Claude 產出的三段式卡片內容，見
    llm_advisor.derive_finding_summary() 的說明。

    不像 llm_advice 是 use_llm=True 才呼叫——這裡跟 _with_cwe_remediation
    等 text_zh 產生邏輯一樣預設就會跑，因為它現在是待複核卡片的主要內容，
    不是附加的選用研判。任何失敗都回 None，呼叫端退回用既有欄位組卡片。
    """
    if derive_finding_summary is None:
        return None
    cwe = (suggestions.get("cwe") or [None])[0]
    iec = (suggestions.get("iec") or [None])[0]
    cra = (suggestions.get("cra") or [None])[0]
    try:
        return derive_finding_summary(finding, cwe, iec, cra)
    except Exception as e:
        print(f"[analysis] 待複核卡片摘要產生失敗，略過（{e}）")
        return None


def _weakness_name(finding: dict, recommendation: str | None, cra_reference: str | None) -> str | None:
    """
    不符合項目（matched）卡片標題用的弱點名稱，跟 _finding_summary() 一樣
    預設就會跑（不是 use_llm=True 才呼叫）——它現在是 Fail 卡片的主要標題，
    不是附加的選用研判。任何失敗都回 None，呼叫端退回顯示 finding.title。
    見 llm_advisor.derive_weakness_name() 的說明。
    """
    if derive_weakness_name is None:
        return None
    try:
        return derive_weakness_name(finding, recommendation, cra_reference)
    except Exception as e:
        print(f"[analysis] 弱點名稱產生失敗，略過（{e}）")
        return None


def _rule_remediation(finding: dict, result: dict) -> str | None:
    """
    matched 項目的修補建議，依卡片上「未合規法規」實際列出的那幾條產生
    （見 llm_advisor.derive_rule_remediation()）。跟 _weakness_name() 一樣
    預設就會跑。任何失敗都回 None，呼叫端退回規則表／CVE 判定原本寫死的
    recommendation。
    """
    if derive_rule_remediation is None:
        return None
    try:
        return derive_rule_remediation(
            finding,
            result.get("weakness_reason"),
            result.get("recommendation"),
            result.get("iec_reference"),
            result.get("cra_reference"),
        )
    except Exception as e:
        print(f"[analysis] 規則修補建議產生失敗，略過（{e}）")
        return None


def _finalize_matched(finding: dict, result: dict) -> dict:
    """
    兩條 matched 路徑（規則比對／CVE 比對）共用的收尾：補上卡片標題用的
    弱點名稱，並把修補建議換成依「未合規法規」列出的條款生成的版本。

    recommendation_source 記錄這句話最後是誰寫的（"llm"／"rule"），讓呈現層
    可以標示出來。這個欄位不是裝飾——規則表那句是人工維護、每次掃描都一樣的
    固定文字，LLM 生成的那句則是每次可能不同、且依賴外部服務的產物，兩者
    可信度不同，讀報告的人有權知道自己看的是哪一種。

    weakness_name 一律拿「規則表原本的 recommendation」去生，不是換過的那句：
    弱點名稱要的是穩定（同一種弱點跨掃描應該叫同一個名字），拿一段每次
    都可能不同的文字當輸入會讓名稱跟著漂。
    """
    llm_remediation = _rule_remediation(finding, result)
    return {
        **result,
        "recommendation": llm_remediation or result.get("recommendation"),
        "recommendation_source": "llm" if llm_remediation else "rule",
        "cwe_id": None,
        "confidence": None,
        "rag_suggestions": None,
        "llm_advice": None,
        "weakness_name": _weakness_name(
            finding, result.get("recommendation"), result.get("cra_reference")),
    }


def _fallback_risk_level(finding: dict) -> str:
    """
    規則沒比對到、也沒有比對到已知 CVE 時（見 _cve_match()），needs_review
    項目要顯示的風險等級。

    大部分掃描器在收集層都統一給 severity="info"（開放的 port、韌體裡的
    字串都只是「事實」，嚴重程度留給這一層判斷），但兩種來源例外，各自
    有自己可信賴的風險判斷，這裡直接沿用，不該被壓成統一的 info：
    - ZAP 對每個 alert 有自己規則庫判斷出來的風險（High/Medium/Low/
      Informational），正規化存在 detail.zap_risk。
    - nmap 的 vuln 類 NSE script 對已確認的 CVE 有 CVSS 分數依據，直接
      寫進收集層的 finding['severity']（見 nmap_scan.parse_nmap_vuln_findings）。
      這兩種都不是向量相似度那種「無法區分訊號跟雜訊」的分數（見本檔案
      開頭的說明），是外部、可驗證的判斷，可以直接當顯示用的風險等級。
    """
    severity = finding.get("severity")
    if severity in ("critical", "high", "medium", "low"):
        return severity

    zap_risk = (finding.get("detail") or {}).get("zap_risk")
    return zap_risk if zap_risk in ("critical", "high", "medium", "low", "info") else "info"


# CRA 對 vulnerability handling 的義務規定在 Annex I Part II，這裡引用第 (1)
# 條——「識別並記錄產品所含元件與已知弱點」——是 cra_kb/cra_data/cra_articles.json
# 裡實際存在、對應到這個情境最直接的一條（原文：identify and document
# vulnerabilities and components contained in products with digital elements,
# including by drawing up a software bill of materials...），不是憑印象
# 編出來的條號。
_CVE_CRA_REFERENCE = "CRA Annex I Part II(1) — 製造商應識別並記錄產品所含元件與已知弱點（含軟體物料清單 SBOM）"

# 已知弱點在 62443-4-2 這一側對應到「元件能不能被更新」這個能力要求：
# CVE 的處置手段幾乎都是「更新到已修補版本」，而元件如果根本不具備安全的
# 更新機制，這個弱點在產品生命週期內就無法收斂。條號與標題查證自
# iec_kb/iec_data/iec_4_2.json（CR 3.10 Support for updates）。
_CVE_IEC_REFERENCE = "IEC 62443-4-2 CR 3.10 — Support for updates（元件應具備支援安全更新的能力，使已知弱點能被修補）"


def _cve_match(finding: dict) -> dict | None:
    """
    nmap 的 vuln 類 NSE script 已經用公開、可驗證的 CVE/CVSS 資料判定這筆
    finding 確實是個已知弱點（見 nmap_scan.parse_nmap_vuln_findings()），
    不是語意相似度那種需要人工複核的猜測。地位比照規則比對，直接判定
    status="matched"，不需要再送進 RAG 候選流程——RAG 候選是給「規則沒有
    答案、只能用語意檢索找方向」的情況用的，這裡已經有明確答案（CVE 編號）。

    沒有 cve_ids 就代表這不是一筆已比對到 CVE 的 finding，回傳 None，
    交給呼叫端走原本的 RAG needs_review 路徑。
    """
    detail = finding.get("detail") or {}
    cve_ids = detail.get("cve_ids") or []
    if not cve_ids:
        return None

    severity = finding.get("severity", "info")
    if severity not in ("critical", "high", "medium", "low"):
        severity = "medium"  # 保守預設：理論上不該發生（見 parse_nmap_vuln_findings），防禦性處理

    cve_list = "、".join(cve_ids)
    return {
        "finding_id": finding["finding_id"],
        "target": finding["target"],
        "title": finding["title"],
        "status": "matched",
        "risk_level": severity,
        "weakness_reason": (
            f"掃描比對到此服務對應已公開的弱點編號 {cve_list}，"
            "代表目前運行的版本存在已被記錄、且攻擊手法多半已公開的安全問題。"
        ),
        "recommendation": f"已知弱點 {cve_list}，建議儘速更新到已修補版本或套用廠商公告的緩解措施，並確認實際影響範圍。",
        "cra_reference": _CVE_CRA_REFERENCE,
        "iec_reference": _CVE_IEC_REFERENCE,
    }


def analyze_finding(finding: dict, use_llm: bool = False) -> dict:
    """
    分析單一 finding：
    1. 規則比對（keyword_rules）成功 → 直接採用
    2. 沒比對到規則，但 nmap vuln script 已比對到已知 CVE → 直接採用
       （見 _cve_match()），這兩條路徑都會自動判定 status="matched"，
       依據都是外部、可驗證的來源（人工寫死的規則表／公開 CVE 資料庫），
       不是需要人工複核的猜測
    3. 兩者都沒有 → 維持 status="needs_review"，附上 rag_suggestions
       （CWE / IEC 62443-4-2 / CRA 各信心最高的 1 筆候選 + 一句話修補
       建議），供人工複核時參考，不自動判定
    4. use_llm=True 時，額外把候選交給 LLM 產出一段文字研判
       （llm_advice），一樣只是附加的參考意見，不影響 status

    use_llm 預設 False 的理由：這條路徑會對外送出請求（掃描結果含
    目標 IP 與服務清單）、需要 API 金鑰、而且逐筆呼叫是有成本的。
    這種有外部副作用又要花錢的行為應該由使用者明確開啟，不該是
    跑一次 analyze_findings() 就默默發生的預設行為。
    """
    rule_result = rule_analyze_finding(finding)
    if rule_result["status"] == "matched":
        return _finalize_matched(finding, rule_result)

    cve_result = _cve_match(finding)
    if cve_result is not None:
        return _finalize_matched(finding, cve_result)

    suggestions = {
        "cwe": _cwe_candidates(finding),
        "iec": _iec_candidates(finding),
        "cra": _cra_candidates(finding),
    }

    return {
        "finding_id": finding["finding_id"],
        "target": finding["target"],
        "title": finding["title"],
        "status": "needs_review",
        "risk_level": _fallback_risk_level(finding),
        "recommendation": None,
        "recommendation_source": None,
        "cra_reference": None,
        "cwe_id": None,
        "confidence": None,
        "rag_suggestions": suggestions,
        "finding_summary": _finding_summary(finding, suggestions),
        "llm_advice": _llm_advice(finding, suggestions) if use_llm else None,
    }


def analyze_findings(findings: list[dict], use_llm: bool = False) -> list[dict]:
    """對一批 findings 逐一分析，回傳合併後的分析結果清單。"""
    return [analyze_finding(f, use_llm=use_llm) for f in findings]


# 整場掃描層級的 4-1 候選數。比逐筆的 RAG_SUGGESTION_TOP_K 多，是因為
# 這一份整份報告只出現一次，多列幾條的閱讀成本很低。
PROCESS_SUGGESTION_TOP_K = 8

# 掃描類別 → 一句描述性的查詢文字。刻意只描述「掃了什麼」，不摻入
# 「所以應該要做安全測試」這類推論——那等於先替 4-1 挑好答案再去
# 檢索，檢索結果就只是把預設立場再唸一次。
_CATEGORY_QUERY_PHRASES = {
    "network": "exposed network services and remote access interfaces of a product",
    "firmware": "firmware image contents, embedded binaries, keys and update packages",
    "webapp": "web application interfaces and their reported vulnerabilities",
}


def _build_process_query(findings: list[dict]) -> str:
    """
    整場掃描的輪廓描述，用來檢索 4-1。

    用「掃了哪些類別」加上「出現過哪些項目標題」組成，而不是逐筆查詢
    再合併：4-1 的顆粒度是整個開發流程，對「這個產品被掃出這些東西」
    這個整體現象回答一次才有意義，逐筆問只會讓同樣幾條 practice
    重複出現 N 次。
    """
    categories = []
    for f in findings:
        category = f.get("category")
        if category and category not in categories:
            categories.append(category)

    parts = [_CATEGORY_QUERY_PHRASES.get(c, c) for c in categories]

    # 標題帶入一部分具體字彙（telnet、outdated OpenSSL…），讓查詢不會
    # 只剩下三句通用描述而檢索到千篇一律的結果。上限是為了避免整段
    # 查詢被幾十筆標題稀釋掉。
    titles = []
    for f in findings:
        title = (f.get("title") or "").strip()
        if title and title not in titles:
            titles.append(title)
        if len(titles) >= 15:
            break

    return " ".join(parts + titles)


def scan_level_process_requirements(findings: list[dict]) -> dict | None:
    """
    整場掃描查一次 IEC 62443-4-1（開發流程要求），回傳供報告獨立一節使用。

    為什麼不跟 4-2 一樣逐筆查：掃描工具測的是「成品現在長什麼樣」，
    4-1 規範的是「這個成品是用什麼流程做出來的」。單一筆 finding
    （例如 "tcp/23 telnet"）跟 "SM-4 安全專業能力" 之間沒有語意相似性，
    硬要逐筆檢索，得到的只會是分數很低又每筆都一樣的候選。

    這一節的定位必須寫清楚（報告樣板裡也有標示）：它是**自評的起點**，
    不是符合性判定，更不是完整清單——4-1 全文共 47 條要求，這裡只列
    語意上跟本次掃描輪廓最接近的前幾條。掃描結果本來就無法證明或
    否證任何一條流程要求，能不能滿足只有開發流程的文件與紀錄說得算。

    回傳 None 代表這條路徑不可用（知識庫沒建、Qdrant 連不上），
    呼叫端照常繼續，跟其他 RAG 路徑一致的降級原則。
    """
    if retrieve_iec_hybrid is None or not findings:
        return None

    query = _build_process_query(findings)
    try:
        candidates = retrieve_iec_hybrid(query, part="4-1", top_k=PROCESS_SUGGESTION_TOP_K)
    except Exception as e:
        print(f"[analysis] IEC 62443-4-1 候選查詢失敗，略過（{e}）")
        return None

    if not candidates:
        return None

    return {"query": query, "candidates": candidates}


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