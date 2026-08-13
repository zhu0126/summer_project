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

# 用函式而不是固定常數的原因：如果只是 OUTPUT_DIR = Path("output") 這種
# 模組層級常數，其他檔案用 `from common import OUTPUT_DIR` 匯入時，
# 會把當下的值複製一份到自己的命名空間。之後就算在別的地方改了
# common.OUTPUT_DIR，其他模組手上那份「舊的」參照不會跟著變——
# 這是 Python import 綁定的經典陷阱。改成函式呼叫時才決定路徑，
# project.py 才能在執行掃描前，讓所有模組真正寫進同一個指定資料夾。
_output_dir = Path("output")
_output_dir.mkdir(exist_ok=True)


def get_output_dir() -> Path:
    return _output_dir


def set_output_dir(path) -> Path:
    """
    切換所有模組接下來要寫入的輸出資料夾。呼叫這個函式之後，
    任何模組呼叫 get_output_dir() 拿到的都會是新路徑，不需要
    重新 import，因為讀取的是函式呼叫當下的值，不是匯入當下的值。
    """
    global _output_dir
    path = Path(path)
    path.mkdir(parents=True, exist_ok=True)
    _output_dir = path
    return _output_dir


# 三個掃描模組（nmap/binwalk/zap）共用同一套 severity 分級與排序，
# 讓合規判讀層能用同一套邏輯處理不同來源的 finding，不需要為每個
# source 各寫一套判斷規則。
#
# critical 是額外加的第五級：一般收集層的 finding（開放的 port、韌體字串、
# ZAP alert）都只是「觀測到的事實」，嚴重程度留給合規判讀層依規則/RAG 判斷，
# 所以原本 high 就是頂級已經夠用。但 nmap 的 vuln 類 NSE script（見
# scanners/nmap_scan.py 的 parse_nmap_vuln_findings()）會回報已知 CVE 的
# CVSS 分數，這是外部、可驗證的評分，CVSS 9.0 以上依業界慣例是 critical
# 等級，收集層這裡就該有能力如實記錄，不該被四級分類硬壓成 high。
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


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
    json_path = get_output_dir() / f"{base_name}.json"
    json_path.write_text(
        json.dumps(findings, indent=2, ensure_ascii=False),
        encoding="utf-8"
    )
    return str(json_path)