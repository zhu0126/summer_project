#!/usr/bin/env python3
"""
純資料整理層：把「原始 findings」跟「分析層（keyword_rules + RAG）的結果」
合併、分組，不碰任何樣板引擎或報告產出邏輯。

從 report.py 拆出來的原因：report.py 為了 render Markdown 報告需要 import
jinja2，但這裡的兩個函式（merge_findings_and_analysis / group_by_target）
只是單純的 dict 合併與分組，沒有任何理由要因為「之後可能會拿去 render 報告」
就強迫呼叫端也一起載入 jinja2。webapp 後端跟 core/pentest_planner.py 都只需要
合併好的 merged_findings（給 Findings/Compliance 頁面、給測試計畫用要求對應），
完全不需要報告樣板——拆開後這些呼叫端可以在沒裝 jinja2 的環境（例如只裝了
pentestgpt 相依套件的獨立 venv）裡照常運作，不會因為一個用不到的 import
就 ModuleNotFoundError。

core/report.py 仍然從這裡 re-export 這兩個函式，維持既有呼叫端
（core/project.py 的 report.merge_findings_and_analysis(...)）不用改。
"""
from core.common import SEVERITY_ORDER


def sort_by_risk_level(merged_findings: list[dict]) -> list[dict]:
    """
    依 risk_level 由高到低（critical → high → medium → low → info）排序。

    排序鍵用 risk_level（分析層的判定）而不是 severity（收集層的原始值），
    因為報告與網頁上「風險等級」欄位顯示的就是 risk_level——排序依據跟
    畫面上看到的數值必須是同一個，否則使用者會看到「HIGH 排在 CRITICAL
    前面」這種看起來像壞掉的結果。

    sorted() 是穩定排序，同風險等級的項目維持原本的先後順序（也就是
    nmap XML 裡的連接埠遞增順序），所以這只是把高風險往前提，不會把
    同一級之間本來就合理的排列打散。
    """
    return sorted(merged_findings, key=lambda f: SEVERITY_ORDER.get(f.get("risk_level"), 9))


def merge_findings_and_analysis(findings: list[dict], analysis_results: list[dict]) -> list[dict]:
    """
    用 finding_id 把兩份各自獨立的資料合併成一份，讓下游（報告樣板、
    webapp API 回應、pentest_planner 的要求對應）可以直接逐筆迭代，
    不需要各自再寫一次查找比對的邏輯。

    已修正的 bug：這裡原本只複製 status/risk_level/recommendation/
    cra_reference 四個欄位，漏掉了 analysis.py 後來新增的
    rag_suggestions——樣板裡的「待複核項目」章節讀 item.rag_suggestions
    永遠是 undefined，於是每一筆都印成「語意檢索目前沒有回傳候選」，
    看起來像知識庫連不上，實際上是候選在合併這一步就被丟掉了。
    Jinja2 對未定義變數預設是靜默當成 falsy，不會報錯，所以這種
    「少複製一個欄位」的漏洞完全不會有任何錯誤訊息。

    回傳前依風險等級由高到低排序（見 sort_by_risk_level()）。排在這一層
    做而不是各呈現層各自排，是因為報告樣板、Web 前端的 Findings 頁面、
    pentest_planner 的要求對應全部都吃這同一份 merged_findings——在源頭
    排好，三邊的呈現順序自然一致，不需要（也不會忘記）在每個呼叫端
    各補一次排序。
    """
    analysis_by_id = {a["finding_id"]: a for a in analysis_results}

    merged = []
    for f in findings:
        analysis = analysis_by_id.get(f["finding_id"], {})
        merged.append({
            **f,
            "status": analysis.get("status", "no_match"),
            "risk_level": analysis.get("risk_level", "info"),
            "recommendation": analysis.get("recommendation"),
            "cra_reference": analysis.get("cra_reference"),
            "rag_suggestions": analysis.get("rag_suggestions"),
            "llm_advice": analysis.get("llm_advice"),
        })
    return sort_by_risk_level(merged)


def group_by_target(merged_findings: list[dict]) -> list[dict]:
    """
    把 findings 依 target 分組，讓 Findings 章節能用「target 當標題、
    底下列出該目標的所有項目」的方式呈現，不用在每一行都重複印一次
    target——三個掃描目標（IP/firmware/URL）各自可能產生好幾筆
    finding，攤平列表時 target 欄位會重複很多次，分組後可讀性更好。

    保留 target 第一次出現的順序（這裡不再自己排一次）。因為傳進來的
    merged_findings 已經是依風險由高到低排好的（見
    merge_findings_and_analysis()），dict 會記住插入順序，所以「第一次
    出現」自然就等於「該目標最高風險的那一筆出現的位置」——含 critical
    的目標會排在只有 info 的目標前面，群組內部也已經是高到低，不需要
    在這裡重複排序邏輯。
    """
    groups: dict[str, list[dict]] = {}
    for item in merged_findings:
        groups.setdefault(item["target"], []).append(item)

    return [{"target": target, "findings": items} for target, items in groups.items()]
