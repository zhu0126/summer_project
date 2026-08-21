#!/usr/bin/env python3
"""
分析層（MVP 版）：用寫死的關鍵字對照表，取代完整的 RAG 合規判讀。

跟完整版 RAG（向量資料庫 + 語意檢索 + LLM 判讀）的關係：
這支模組回傳的欄位（finding_id / status / weakness_reason / recommendation /
cra_reference / iec_reference）刻意跟 RAG 那條路徑產出的
finding_summary（weakness_name / weakness_reason / remediation）+
rag_suggestions（iec / cra 候選）對齊語意，差別只在於「怎麼找到對應的
法規」——這裡是查表，完整版是語意檢索。因此呈現層可以用同一套
「弱點原因／未合規法規／修補建議」三段式版面渲染兩種來源，不需要為
規則命中另外寫一套欄位對應。

比對依據：finding['detail']['service']（nmap 回報的服務名稱），
不是拿 title 做字串包含比對——title 的組字串格式（例如
"tcp/23 telnet (OpenSSH 8.9)"）之後可能會調整，用 service 欄位
直接比對比較穩定，不受 title 格式影響。

為什麼 weakness_reason 寫死在表裡、不交給 LLM 產生：
規則這條路徑存在的價值就是「高信心、可稽核、離線可用、輸出穩定」
（見 core/analysis.py 開頭那段關於向量分數無法區分訊號與雜訊的說明）。
弱點原因如果改成每次呼叫 LLM 生成，這四個性質會同時失去——沒有金鑰或
斷網時卡片會開天窗，而且同一條規則每次掃描可能得到不同措辭。既然規則
本來就是人工維護的固定對照，原因敘述一起寫死才是一致的做法。

recommendation 這欄的角色則跟上面三欄不同：它是「這個服務該怎麼處理」的
通則，寫的時候並沒有對著哪一條條文。呈現層實際顯示的修補建議，是由
llm_advisor.derive_rule_remediation() 拿下面 iec_reference/cra_reference
列出的那幾條（連同條文全文）重寫成「這幾條各自要求你做什麼」的版本，
這裡這句退居基準與退路——LLM 不可用、或產出的引用沒通過查核時，顯示的
就是這句（見 analysis.py 的 _finalize_matched()）。所以這欄仍然要維持
「單獨拿出來看也成立」的品質，不能寫成只有配上條文才讀得懂的半句話。

法規對照的兩個來源，效力完全不同，不可混為一談：
- cra_reference：CRA（Regulation (EU) 2024/2847）是具強制力的歐盟法規。
- iec_reference：IEC 62443-4-2 是自願性標準，除非產業規範或客戶合約
  另有要求，對應到某條 CR 不代表存在法律義務。列出來是因為 CRA 條文
  講的是「要達成什麼目的」，62443 講的是「元件技術上該具備什麼能力」，
  後者對工程師才是可執行的驗收標準。

下面每一條 iec_reference 的條號與標題都是從 iec_kb/iec_data/iec_4_2.json
（標準原文解析結果）逐條查證過的，不是憑印象寫的。條文全文因授權限制
不進版控，這裡只引用編號與標題。cra_reference 同樣逐條核對過
cra_kb/cra_data/cra_articles.json 的原文，破折號後面那句中文是條文本身的
翻譯，不是條號的代稱——兩者對不上就是引錯條，這在合規報告裡是最嚴重的
一種錯誤（讀的人不會每條都回去查 EUR-Lex）。改動任何一條之前請先把
cra_articles.json 裡該條的原文讀過一次再寫。
"""
from core.common import SEVERITY_ORDER

# key：nmap 回報的 service 名稱（小寫）
# value：風險等級、弱點原因、修補建議、對應的 CRA 條文與 IEC 62443-4-2 條號
KEYWORD_RULES: dict[str, dict] = {
    "telnet": {
        "risk_level": "high",
        "weakness_reason": "Telnet 協定本身沒有任何加密機制，登入時的帳號密碼與後續所有指令、輸出都以明碼在網路上傳輸，同網段的攻擊者只要被動監聽即可取得管理權限。",
        "recommendation": "Telnet 以明碼傳輸帳號密碼與所有流量，建議停用並改用 SSH。",
        "cra_reference": "CRA Annex I Part I(2)(e) — 產品應保護儲存、傳輸或處理之資料的機密性，例如以當代技術對傳輸中或靜態的資料加密",
        "iec_reference": "IEC 62443-4-2 CR 4.1 — Information confidentiality（元件應具備保護傳輸中資訊機密性的能力）",
    },
    "ftp": {
        "risk_level": "high",
        "weakness_reason": "FTP 的控制通道與資料通道都未加密，帳號密碼及傳輸的檔案內容以明碼送出，可被網路上的第三方攔截或竄改。",
        "recommendation": "FTP 以明碼傳輸憑證與檔案內容，建議停用並改用 SFTP/FTPS。",
        "cra_reference": "CRA Annex I Part I(2)(e) — 產品應保護儲存、傳輸或處理之資料的機密性，例如以當代技術對傳輸中或靜態的資料加密",
        "iec_reference": "IEC 62443-4-2 CR 4.1 — Information confidentiality（元件應具備保護傳輸中資訊機密性的能力）",
    },
    "http": {
        "risk_level": "medium",
        "weakness_reason": "服務以未加密的 HTTP 提供，連線內容（含登入憑證、Session Cookie 與傳輸的資料）不具機密性與完整性保護，容易遭中間人攔截或竄改。",
        "recommendation": "服務僅提供未加密的 HTTP，建議強制導向 HTTPS 並停用明碼連線。",
        "cra_reference": "CRA Annex I Part I(2)(e) — 產品應保護儲存、傳輸或處理之資料的機密性，例如以當代技術對傳輸中或靜態的資料加密",
        "iec_reference": "IEC 62443-4-2 CR 4.1 — Information confidentiality（元件應具備保護傳輸中資訊機密性的能力）",
    },
    "snmp": {
        "risk_level": "medium",
        "weakness_reason": "SNMP v1/v2c 僅以 community string 作為驗證，且多數裝置沿用出廠預設值（public/private），等同於未更換的預設密碼；此協定亦以明碼傳輸，可被讀取甚至寫入裝置設定。",
        "recommendation": "SNMP（尤其 v1/v2c）常使用預設 community string，建議停用或改用 SNMPv3。",
        "cra_reference": "CRA Annex I Part I(2)(b) — 產品上市時應具備安全的預設組態（secure by default）",
        "iec_reference": "IEC 62443-4-2 CR 1.5 — Authenticator management（元件應能辨識安裝時預設驗證資訊是否已被變更，並保護驗證資訊不被未授權揭露）",
    },
    "rtsp": {
        "risk_level": "medium",
        "weakness_reason": "RTSP 串流服務在許多裝置上預設不啟用驗證，任何能連到此連接埠的人都可直接取得即時影音串流，造成未經授權的監看。",
        "recommendation": "RTSP 串流服務常見未驗證即可存取，建議確認存取控制與驗證機制已啟用。",
        "cra_reference": "CRA Annex I Part I(2)(d) — 產品應以適當的控制機制（含身分驗證、身分或存取管理）防止未經授權的存取",
        "iec_reference": "IEC 62443-4-2 CR 1.1 — Human user identification and authentication（元件應在所有可供人員存取的介面上強制識別與驗證使用者）",
    },
    "upnp": {
        "risk_level": "low",
        "weakness_reason": "UPnP 允許區網內的裝置自行要求路由器開通對外連接埠，等於繞過防火牆的人工審核；若非必要功能而仍對外開放，會擴大裝置的攻擊面。",
        "recommendation": "UPnP 對外開放可能被用於自動穿透防火牆，建議評估是否有必要對外暴露。",
        "cra_reference": "CRA Annex I Part I(2)(j) — 產品的設計、開發與生產應限縮攻擊面，包含對外介面",
        "iec_reference": "IEC 62443-4-2 CR 7.7 — Least functionality（元件應具備限制不必要的功能、連接埠、協定與服務的能力）",
    },
}


def match_finding(finding: dict) -> dict | None:
    """
    拿單一 finding 的 detail.service 去比對關鍵字表。
    回傳對照表裡的規則內容（risk_level / weakness_reason / recommendation /
    cra_reference / iec_reference），沒比對到回傳 None。
    """
    service = finding.get("detail", {}).get("service", "")
    return KEYWORD_RULES.get(service.lower().strip())


def analyze_finding(finding: dict) -> dict:
    """
    分析單一 finding，回傳分析結果（不修改原始 finding，維持
    收集層資料不被分析層覆寫的原則，兩者用 finding_id 對應）。
    """
    rule = match_finding(finding)

    if rule is None:
        return {
            "finding_id": finding["finding_id"],
            "target": finding["target"],
            "title": finding["title"],
            "status": "no_match",
            "risk_level": "info",
            "weakness_reason": None,
            "recommendation": None,
            "cra_reference": None,
            "iec_reference": None,
        }

    return {
        "finding_id": finding["finding_id"],
        "target": finding["target"],
        "title": finding["title"],
        "status": "matched",
        "risk_level": rule["risk_level"],
        "weakness_reason": rule["weakness_reason"],
        "recommendation": rule["recommendation"],
        "cra_reference": rule["cra_reference"],
        "iec_reference": rule["iec_reference"],
    }


def analyze_findings(findings: list[dict]) -> list[dict]:
    """對一批 findings 逐一分析，回傳分析結果清單。"""
    return [analyze_finding(f) for f in findings]


def print_analysis(analysis_results: list[dict]) -> None:
    if not analysis_results:
        print("No analysis results.")
        return

    results_sorted = sorted(
        analysis_results, key=lambda r: SEVERITY_ORDER.get(r["risk_level"], 9)
    )

    print("---- Analysis ----")
    for r in results_sorted:
        if r["status"] == "no_match":
            print(f'[  INFO] {r["title"]}  — {r["target"]}  (no matching rule)')
        else:
            print(f'[{r["risk_level"].upper():>6}] {r["title"]}  — {r["target"]}')
            print(f'         → {r["recommendation"]}')
            print(f'         → {r["cra_reference"]}')
            if r.get("iec_reference"):
                print(f'         → {r["iec_reference"]}')


if __name__ == "__main__":
    # 快速手動測試：用假的 finding 資料檢查比對邏輯是否正確
    from core.common import make_finding

    sample_findings = [
        make_finding("network", "nmap", "192.168.1.20", "info", "tcp/23 telnet",
                     detail={"service": "telnet", "state": "open"}),
        make_finding("network", "nmap", "192.168.1.20", "info", "tcp/22 ssh (OpenSSH 8.9)",
                     detail={"service": "ssh", "state": "open"}),
        make_finding("network", "nmap", "192.168.1.20", "info", "tcp/80 http",
                     detail={"service": "http", "state": "open"}),
    ]
    print_analysis(analyze_findings(sample_findings))