import argparse
import re
import shutil
import subprocess
import sys
 
from datetime import datetime
from pathlib import Path
 
from common import OUTPUT_DIR, print_file_status, save_findings_json, make_finding, print_findings
 
# binwalk 輸出裡，出現這些關鍵字的訊號代表實質風險，會標記成 severity="high"。
SENSITIVE_KEYWORDS = [
    "private key",
    "rsa private",
    "certificate",
    "passwd",
    "shadow",
    "root filesystem",
    "squashfs",
    "webserver",
]
 
# 對應 binwalk 表格輸出的一行，例如：
#   41            0x29            gzip compressed data, ...
BINWALK_LINE_PATTERN = re.compile(r"^(\d+)\s+(0x[0-9A-Fa-f]+)\s+(.+)$")
 
 
def check_binwalk_installed():
    if shutil.which("binwalk") is None:
        raise FileNotFoundError(
            "binwalk not found in PATH "
            "(若用 pip 裝過殼套件，請改用系統套件管理員安裝，如 apt-get install binwalk)"
        )
 
 
def check_firmware_file(firmware_path: str) -> Path:
    path = Path(firmware_path)
    if not path.is_file():
        raise FileNotFoundError(f"firmware file not found: {firmware_path}")
    return path
 
 
def run_binwalk(firmware_path: Path, base_name: str) -> tuple[int, str, str]:
    txt_path = OUTPUT_DIR / f"{base_name}.txt"
    log_path = OUTPUT_DIR / f"{base_name}.log"
 
    # 只做訊號掃描（signature scan），不加 -e 做實際解壓縮。
    # 解壓縮會把韌體內容整批寫到磁碟，對「先盤點裡面有什麼」這個
    # 目的來說不是必要動作，之後如果要深入分析特定區塊，
    # 再針對那個 offset 另外跑 -e 會更可控。
    cmd = ["binwalk", str(firmware_path)]
 
    result = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False
    )
 
    # binwalk 的訊號表格是印在 stdout，這裡直接落地成 .txt，
    # 跟 nmap 模組用 -oN 讓工具自己寫檔的精神一致：保留原始輸出。
    txt_path.write_text(result.stdout, encoding="utf-8")
 
    log_content = []
    log_content.append(f"Command: {' '.join(cmd)}")
    log_content.append(f"Return code: {result.returncode}")
    if result.stderr.strip():
        log_content.append("---- stderr ----")
        log_content.append(result.stderr.strip())
    log_path.write_text("\n".join(log_content) + "\n", encoding="utf-8")
 
    return result.returncode, str(txt_path), str(log_path)
 
 
def parse_binwalk_output(raw_text: str, target: str) -> list[dict]:
    results = []
    for line in raw_text.splitlines():
        match = BINWALK_LINE_PATTERN.match(line.strip())
        if not match:
            continue  # 跳過表頭、分隔線等不是資料列的內容
 
        offset_decimal, offset_hex, description = match.groups()
        description = description.strip()
 
        # 出現私鑰、密碼檔、檔案系統這類訊號，代表真的有實質風險，
        # 不是「等等再看」的程度，所以直接給 high，而不是額外的
        # review 標記——跟 zap 的風險分級用同一套四級制，方便合併排序。
        severity = "high" if any(k in description.lower() for k in SENSITIVE_KEYWORDS) else "info"
 
        results.append(make_finding(
            category="firmware",
            source="binwalk",
            target=target,
            severity=severity,
            title=description,
            detail={
                "offset_decimal": int(offset_decimal),
                "offset_hex": offset_hex,
            },
        ))
 
    return results
 
 
def run_scan(firmware_path: str) -> list[dict]:
    """
    完整跑一次 binwalk 訊號掃描並回傳統一格式的 findings。
    設計理由跟 nmap_scan.run_scan 一致：失敗時直接丟出例外，
    讓呼叫端（CLI 的 main() 或 orchestrator）自行決定如何處理。
    """
    check_binwalk_installed()
    path = check_firmware_file(firmware_path)
 
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    base_name = f"firmware_{path.stem}_{ts}"
 
    code, txt_file, log_file = run_binwalk(path, base_name)
 
    print(f"[binwalk] Scan finished. Return code: {code}")
    print_file_status("TXT", txt_file)
    print_file_status("LOG", log_file)
 
    if not (code == 0 and Path(txt_file).exists()):
        return []
 
    raw_text = Path(txt_file).read_text(encoding="utf-8")
    findings = parse_binwalk_output(raw_text, target=path.name)
 
    json_file = save_findings_json(findings, base_name)
    print_file_status("JSON", json_file)
    print_findings(findings, empty_message="No signatures found in firmware.")
 
    return findings
 
 
def main():
    parser = argparse.ArgumentParser(description="Firmware signature scanner (binwalk wrapper)")
    parser.add_argument("firmware", help="Path to firmware file")
    args = parser.parse_args()
 
    try:
        run_scan(args.firmware)
    except FileNotFoundError as e:
        print(f"Error: {e}")
        sys.exit(1)
 
 
if __name__ == "__main__":
    main()