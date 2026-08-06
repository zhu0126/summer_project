#!/usr/bin/env python3
"""
分析層（MVP 版）：用寫死的關鍵字對照表，取代完整的 RAG 合規判讀。

跟完整版 RAG（向量資料庫 + 語意檢索 + LLM 判讀）的關係：
這支模組回傳的欄位（finding_id / status / recommendation / cra_reference）
刻意跟之前設計的完整版 RAG schema 對齊欄位命名，差別只在於「怎麼找到
對應的法規」——這裡是查表，完整版是語意檢索。之後要把這支模組換成
真正的 RAG，report.py 消費的介面不需要改。

比對依據：finding['detail']['service']（nmap 回報的服務名稱），
不是拿 title 做字串包含比對——title 的組字串格式（例如
"tcp/23 telnet (OpenSSH 8.9)"）之後可能會調整，用 service 欄位
直接比對比較穩定，不受 title 格式影響。

CRA 對照僅為佔位範例，不是正式法律意見，之後要換成真正查證過的
條文內容或串接完整版 RAG 的檢索結果。
"""
from module.common import SEVERITY_ORDER

# key：nmap 回報的 service 名稱（小寫）
# value：風險等級、建議、對應的 CRA 條文參考（佔位文字，待正式版替換）
KEYWORD_RULES: dict[str, dict] = {
    "telnet": {
        "risk_level": "high",
        "recommendation": "Telnet 以明碼傳輸帳號密碼與所有流量，建議停用並改用 SSH。",
        "cra_reference": "CRA Annex I Part I(2)(a) — 產品應以預設方式確保適當等級的機密性保護",
    },
    "ftp": {
        "risk_level": "high",
        "recommendation": "FTP 以明碼傳輸憑證與檔案內容，建議停用並改用 SFTP/FTPS。",
        "cra_reference": "CRA Annex I Part I(2)(a) — 產品應以預設方式確保適當等級的機密性保護",
    },
    "http": {
        "risk_level": "medium",
        "recommendation": "服務僅提供未加密的 HTTP，建議強制導向 HTTPS 並停用明碼連線。",
        "cra_reference": "CRA Annex I Part I(2)(a) — 產品應以預設方式確保適當等級的機密性保護",
    },
    "snmp": {
        "risk_level": "medium",
        "recommendation": "SNMP（尤其 v1/v2c）常使用預設 community string，建議停用或改用 SNMPv3。",
        "cra_reference": "CRA Annex I Part I(2)(c) — 產品應僅處理執行預期用途所必要的資料",
    },
    "rtsp": {
        "risk_level": "medium",
        "recommendation": "RTSP 串流服務常見未驗證即可存取，建議確認存取控制與驗證機制已啟用。",
        "cra_reference": "CRA Annex I Part I(2)(e) — 產品應保護儲存、傳輸或處理資料的機密性",
    },
    "upnp": {
        "risk_level": "low",
        "recommendation": "UPnP 對外開放可能被用於自動穿透防火牆，建議評估是否有必要對外暴露。",
        "cra_reference": "CRA Annex I Part I(1) — 產品應以適當等級的網路安全性設計、開發及生產",
    },
}


def match_finding(finding: dict) -> dict | None:
    """
    拿單一 finding 的 detail.service 去比對關鍵字表。
    回傳對照表裡的規則內容（risk_level/recommendation/cra_reference），
    沒比對到回傳 None。
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
            "recommendation": None,
            "cra_reference": None,
        }

    return {
        "finding_id": finding["finding_id"],
        "target": finding["target"],
        "title": finding["title"],
        "status": "matched",
        "risk_level": rule["risk_level"],
        "recommendation": rule["recommendation"],
        "cra_reference": rule["cra_reference"],
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


if __name__ == "__main__":
    # 快速手動測試：用假的 finding 資料檢查比對邏輯是否正確
    from module.common import make_finding

    sample_findings = [
        make_finding("network", "nmap", "192.168.1.20", "info", "tcp/23 telnet",
                     detail={"service": "telnet", "state": "open"}),
        make_finding("network", "nmap", "192.168.1.20", "info", "tcp/22 ssh (OpenSSH 8.9)",
                     detail={"service": "ssh", "state": "open"}),
        make_finding("network", "nmap", "192.168.1.20", "info", "tcp/80 http",
                     detail={"service": "http", "state": "open"}),
    ]
    print_analysis(analyze_findings(sample_findings))