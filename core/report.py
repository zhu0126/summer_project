#!/usr/bin/env python3
"""
報告產生層（MVP 版）：把 nmap_scan 的 findings + keyword_rules 的分析結果
+ scan_metadata 一起餵給 Jinja2 樣板，render 成單一 Markdown 檔案。

分工原則：
- templates/report.md.j2 只管版面（表格、標題、迴圈），不做任何資料整理
- report.py 負責把「兩份各自獨立、靠 finding_id 關聯的資料」先合併成
  樣板可以直接逐筆迭代的單一 list，樣板裡不需要再寫查找比對的邏輯
"""
import argparse
import sys

from datetime import datetime
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from core.common import get_output_dir
from core.analysis import analyze_findings, scan_level_process_requirements
from core import llm_advisor

TEMPLATE_DIR = Path(__file__).resolve().parent.parent / "templates"
TEMPLATE_NAME = "report.md.j2"


def build_scan_metadata(operator: str = "unknown", ip: str = "", firmware: str = "", url: str = "") -> dict:
    """
    scope 拆成 ip/firmware/url 三個獨立欄位，而不是一個合併字串，
    對應樣板裡「掃描範圍要分行呈現」的需求——IP、韌體、URL 各自
    是完全不同性質的掃描對象，混在同一行閱讀時不容易分辨。
    """
    return {
        "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "operator": operator,
        "ip": ip,
        "firmware": firmware,
        "url": url,
    }


def merge_findings_and_analysis(findings: list[dict], analysis_results: list[dict]) -> list[dict]:
    """
    用 finding_id 把兩份各自獨立的資料合併成一份，讓樣板可以直接逐筆
    迭代印出，不需要在 Jinja2 樣板裡寫查找比對的邏輯。

    已修正的 bug：這裡原本只複製 status/risk_level/recommendation/
    cra_reference 四個欄位，漏掉了 analysis.py 後來新增的
    rag_suggestions——樣板裡的「待複核項目」章節讀 item.rag_suggestions
    永遠是 undefined，於是每一筆都印成「語意檢索目前沒有回傳候選」，
    看起來像知識庫連不上，實際上是候選在合併這一步就被丟掉了。
    Jinja2 對未定義變數預設是靜默當成 falsy，不會報錯，所以這種
    「少複製一個欄位」的漏洞完全不會有任何錯誤訊息。
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
    return merged


def group_by_target(merged_findings: list[dict]) -> list[dict]:
    """
    把 findings 依 target 分組，讓 Findings 章節能用「target 當標題、
    底下列出該目標的所有項目」的方式呈現，不用在每一行都重複印一次
    target——三個掃描目標（IP/firmware/URL）各自可能產生好幾筆
    finding，攤平列表時 target 欄位會重複很多次，分組後可讀性更好。
    保留 target 第一次出現的順序（不重新排序），對應原本 findings
    出現的先後。
    """
    groups: dict[str, list[dict]] = {}
    for item in merged_findings:
        groups.setdefault(item["target"], []).append(item)

    return [{"target": target, "findings": items} for target, items in groups.items()]


def render_report_from_merged(
    merged_findings: list[dict], process_requirements: dict | None, scan_metadata: dict
) -> str:
    """
    純粹的樣板 render 步驟，吃已經算好的 merged_findings/process_requirements。

    拆出這一層是因為 Web 後端（webapp/backend/main.py）需要把「規則比對 +
    RAG 檢索」這個法規 Mapping 階段的結果，同時餵給 Findings/Compliance
    頁面的 API 回應*跟*這裡的 Markdown 報告——如果 render_report() 內部
    自己重跑一次 analyze_findings()，等於同一批 finding 對 RAG 知識庫
    查兩次，白白多付一次檢索成本，兩邊結果理論上還可能因為外部服務
    狀態不同而兜不起來。
    """
    finding_groups = group_by_target(merged_findings)

    env = Environment(
        loader=FileSystemLoader(str(TEMPLATE_DIR)),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    template = env.get_template(TEMPLATE_NAME)

    return template.render(
        scan_metadata=scan_metadata,
        merged_findings=merged_findings,
        finding_groups=finding_groups,
        process_requirements=process_requirements,
    )


def render_report(findings: list[dict], scan_metadata: dict, use_llm: bool = False) -> str:
    """
    use_llm=True 時，待複核項目會額外附上一段 LLM 依檢索結果寫出的
    研判建議（需要 GEMINI_API_KEY，見 core/llm_advisor.py）。預設關閉，
    沒開的時候報告內容跟以前完全一樣。

    獨立執行時（CLI 的 report.py，或還沒算過 merged_findings 的呼叫端）
    才會走到這裡自己跑一次分析；project.py 的 pipeline 已經算好
    merged_findings，會直接呼叫 render_report_from_merged() 省掉重算。
    """
    analysis_results = analyze_findings(findings, use_llm=use_llm)
    merged_findings = merge_findings_and_analysis(findings, analysis_results)
    process_requirements = scan_level_process_requirements(findings)
    return render_report_from_merged(merged_findings, process_requirements, scan_metadata)


def save_report(content: str, base_name: str) -> str:
    report_path = get_output_dir() / f"{base_name}.md"
    report_path.write_text(content, encoding="utf-8")
    return str(report_path)


def infer_scope(findings: list[dict]) -> dict:
    """
    獨立執行 report.py 時（讀既有 json，沒有明確的 --ip/--firmware/--url
    參數可用），依 finding 的 category 分桶推導出各自的目標描述：
    network -> ip，firmware -> firmware，webapp -> url。
    同一類別若有多個目標，用逗號接起來。
    """
    buckets: dict[str, set] = {"ip": set(), "firmware": set(), "url": set()}
    category_to_bucket = {"network": "ip", "firmware": "firmware", "webapp": "url"}

    for f in findings:
        bucket = category_to_bucket.get(f.get("category"))
        if bucket and f.get("target"):
            buckets[bucket].add(f["target"])

    return {key: ", ".join(sorted(values)) for key, values in buckets.items()}


def main():
    """
    獨立執行時，report.py 只做「render」這件事：讀一份已經存在的
    findings json 檔案，加上 scan_metadata，產生報告。

    不在這裡觸發 nmap 掃描——避免跟 project.py（orchestrator）的職責重疊：
    「要不要掃描、掃哪些目標」是 orchestrator 該決定的事，report.py
    只負責「拿到 findings 之後怎麼把它變成一份報告」。
    要一鍵掃描+出報告，請用 project.py --report。
    """
    import json

    parser = argparse.ArgumentParser(
        description="Render a Markdown report from an existing findings json file"
    )
    parser.add_argument("findings_json", help="Path to a findings json file (from nmap_scan/firmware_scan/zap_scan/project.py)")
    parser.add_argument("--operator", default="unknown", help="Who ran this scan")
    parser.add_argument("--llm", action="store_true",
                         help="待複核項目附上 LLM 依檢索結果產生的研判建議"
                              f"（需設定環境變數 {llm_advisor.API_KEY_ENV}，"
                              "會把 finding 內容送給外部 API）")
    args = parser.parse_args()

    if args.llm and not llm_advisor.is_available():
        print(f"[report] 警告：--llm 已開啟，但 google-genai 未安裝或未設定 "
              f"{llm_advisor.API_KEY_ENV}，本次報告不會有 LLM 研判段落。")

    findings_path = Path(args.findings_json)
    if not findings_path.is_file():
        print(f"Error: findings json not found: {findings_path}")
        sys.exit(1)

    findings = json.loads(findings_path.read_text(encoding="utf-8"))
    scope = infer_scope(findings)
    scan_metadata = build_scan_metadata(operator=args.operator, **scope)
    content = render_report(findings, scan_metadata, use_llm=args.llm)

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    base_name = f"report_{ts}"
    report_path = save_report(content, base_name)

    print(f"Report saved to: {report_path}")


if __name__ == "__main__":
    main()