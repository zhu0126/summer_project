#!/usr/bin/env python3
"""
共用模組：被 project.py（nmap）、firmware_scan.py（binwalk）、
zap_scan.py（OWASP ZAP）三個掃描模組共用的邏輯。

抽出這個模組的原因：三個掃描模組都遵循「存原始證據 + 存結構化 JSON +
印檔案狀態」這套固定模式（對應架構圖裡的收集層 + 原始證據層），
避免同一段邏輯在三個檔案裡各寫一份。
"""
import json
import uuid
from pathlib import Path

OUTPUT_DIR = Path("output")
OUTPUT_DIR.mkdir(exist_ok=True)

# 三個掃描模組（nmap/binwalk/zap）共用同一套 severity 分級與排序，
# 讓合規判讀層能用同一套邏輯處理不同來源的 finding，不需要為每個
# source 各寫一套判斷規則。
SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}


def make_finding(
    category: str,
    source: str,
    target: str,
    severity: str,
    title: str,
    detail: dict | None = None,
) -> dict:
    """
    建立統一格式的 finding。所有掃描模組的 parse_* 函式都應該回傳
    這個結構組成的 list，而不是各自定義不同的欄位。

    - finding_id：每筆 finding 唯一識別碼，讓分析層（keyword_rules.py 等）
      的判讀結果能穩定對應回這一筆原始資料，不需要靠 title/target 這種
      容易重複或格式會變動的欄位去比對
    - category / source：標示這筆資料的來源類型
    - target：被檢測的對象（IP、韌體檔名、URL），方便報告依對象分組
    - severity：統一四級 high/medium/low/info，方便跨來源排序、篩選
    - title：一行可直接印出的摘要
    - detail：該來源特有的詳細欄位，不因為統一格式而遺失細節
    """
    if severity not in SEVERITY_ORDER:
        raise ValueError(f"Unknown severity: {severity!r}, must be one of {list(SEVERITY_ORDER)}")
    return {
        "finding_id": uuid.uuid4().hex[:12],
        "category": category,
        "source": source,
        "target": target,
        "severity": severity,
        "title": title,
        "detail": detail or {},
    }


def print_findings(findings: list[dict], empty_message: str = "No findings.") -> None:
    if not findings:
        print(empty_message)
        return

    findings_sorted = sorted(findings, key=lambda f: SEVERITY_ORDER.get(f["severity"], 9))

    print("---- Findings ----")
    for f in findings_sorted:
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