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

from common import OUTPUT_DIR
from keyword_rules import analyze_findings

TEMPLATE_DIR = Path(__file__).parent / "templates"
TEMPLATE_NAME = "report.md.j2"


def build_scan_metadata(scope: str, operator: str = "unknown") -> dict:
    return {
        "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "scope": scope,
        "operator": operator,
    }


def merge_findings_and_analysis(findings: list[dict], analysis_results: list[dict]) -> list[dict]:
    """
    用 finding_id 把兩份各自獨立的資料合併成一份，讓樣板可以直接逐筆
    迭代印出，不需要在 Jinja2 樣板裡寫查找比對的邏輯。
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
        })
    return merged


def render_report(findings: list[dict], scan_metadata: dict) -> str:
    analysis_results = analyze_findings(findings)
    merged_findings = merge_findings_and_analysis(findings, analysis_results)

    env = Environment(
        loader=FileSystemLoader(str(TEMPLATE_DIR)),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    template = env.get_template(TEMPLATE_NAME)

    return template.render(
        scan_metadata=scan_metadata,
        merged_findings=merged_findings,
    )


def save_report(content: str, base_name: str) -> str:
    report_path = OUTPUT_DIR / f"{base_name}.md"
    report_path.write_text(content, encoding="utf-8")
    return str(report_path)


def main():
    parser = argparse.ArgumentParser(description="Generate Markdown compliance report from nmap scan")
    parser.add_argument("ip", help="Target IP that was scanned")
    parser.add_argument("--operator", default="unknown", help="Who ran this scan")
    args = parser.parse_args()

    import nmap_scan  # 延遲匯入：report.py 單獨測試（用假資料）時不需要 nmap 環境
    try:
        findings = nmap_scan.run_scan(args.ip)
    except Exception as e:
        print(f"Error: nmap scan failed ({e})")
        sys.exit(1)

    scan_metadata = build_scan_metadata(scope=args.ip, operator=args.operator)
    content = render_report(findings, scan_metadata)

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    base_name = f"report_{args.ip}_{ts}"
    report_path = save_report(content, base_name)

    print(f"Report saved to: {report_path}")


if __name__ == "__main__":
    main()