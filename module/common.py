import json
from datetime import datetime, timezone
from pathlib import Path
 
OUTPUT_DIR = Path("output")
OUTPUT_DIR.mkdir(exist_ok=True)
 
# 統一分級順序，方便跨來源排序、篩選。數字越小代表風險越高。 
SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}
REPORT_SCHEMA_VERSION = "1.0"
 
 
def make_finding(category: str, source: str, target: str, severity: str, title: str, detail: dict | None = None,) -> dict:
    """
    - category / source：標示這筆資料的來源類型
    - target：被檢測的對象（IP、韌體檔名、URL），方便報告依對象分組
    - severity：統一四級 high/medium/low/info，方便跨來源排序、篩選
    - title：一行可直接印出的摘要
    - detail：該來源特有的詳細欄位，不因為統一格式而遺失細節
    """
    if severity not in SEVERITY_ORDER:
        raise ValueError(f"Unknown severity: {severity!r}, must be one of {list(SEVERITY_ORDER)}")
    return {
        "category": category,
        "source": source,
        "target": target,
        "severity": severity,
        "title": title,
        "detail": detail or {},
    }


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def severity_summary(findings: list[dict]) -> dict:
    summary = {severity: 0 for severity in SEVERITY_ORDER}
    for finding in findings:
        severity = finding.get("severity", "info")
        summary[severity] = summary.get(severity, 0) + 1
    summary["total"] = len(findings)
    return summary


def category_summary(findings: list[dict]) -> dict:
    summary: dict[str, int] = {}
    for finding in findings:
        category = finding.get("category", "unknown")
        summary[category] = summary.get(category, 0) + 1
    return dict(sorted(summary.items()))


def sorted_findings(findings: list[dict]) -> list[dict]:
    return sorted(
        findings,
        key=lambda f: (
            SEVERITY_ORDER.get(f.get("severity", "info"), 9),
            f.get("category", ""),
            f.get("target", ""),
            f.get("title", ""),
        ),
    )


def build_report(
    *,
    project_name: str,
    client_name: str,
    tester: str,
    targets: dict,
    scan_options: dict,
    findings: list[dict],
) -> dict:
    findings_sorted = sorted_findings(findings)
    return {
        "schema_version": REPORT_SCHEMA_VERSION,
        "report_type": "iot_security_assessment",
        "project": {
            "name": project_name,
            "client": client_name,
            "tester": tester,
            "generated_at": utc_now_iso(),
        },
        "scope": {
            "targets": targets,
            "scan_options": scan_options,
        },
        "summary": {
            "by_severity": severity_summary(findings_sorted),
            "by_category": category_summary(findings_sorted),
        },
        "findings": findings_sorted,
        "report_notes": [
            "Raw tool outputs are kept under the output directory and should be treated as evidence.",
            "Findings are collection-layer observations; final risk rating should be reviewed before issuing a client report.",
        ],
    }
 
 
def print_findings(findings: list[dict], empty_message: str = "No findings.") -> None:
    if not findings:
        print(empty_message)
        return
 
    print("---- Findings ----")
    for f in sorted_findings(findings):
        print(f'[{f["severity"].upper():>6}] ({f["category"]}/{f["source"]}) {f["title"]}  — {f["target"]}')
 
 
def print_file_status(label: str, file_path: str) -> None:
    if Path(file_path).exists():
        print(f"{label} saved to: {file_path}")
    else:
        print(f"{label} NOT created (expected at: {file_path})")
 
 
def save_findings_json(findings: list[dict], base_name: str) -> str:
    json_path = OUTPUT_DIR / f"{base_name}.json"
    json_path.write_text(
        json.dumps(findings, indent=2, ensure_ascii=False),
        encoding="utf-8"
    )
    return str(json_path)


def save_report_json(report: dict, base_name: str) -> str:
    json_path = OUTPUT_DIR / f"{base_name}.json"
    json_path.write_text(
        json.dumps(report, indent=2, ensure_ascii=False),
        encoding="utf-8"
    )
    return str(json_path)
