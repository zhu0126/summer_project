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
            "系統套件管理員安裝，sudo apt-get install binwalk)"
        )
 
 
def check_firmware_file(firmware_path: str) -> Path:
    path = Path(firmware_path)
    if not path.is_file():
        raise FileNotFoundError(f"firmware file not found: {firmware_path}")
    return path
 
 
def run_binwalk(firmware_path: Path, base_name: str) -> tuple[int, str, str]:
    txt_path = OUTPUT_DIR / f"{base_name}.txt"
    log_path = OUTPUT_DIR / f"{base_name}.log"
 
    cmd = ["binwalk", str(firmware_path)]
 
    result = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False
    )
 
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
            continue 
 
        offset_decimal, offset_hex, description = match.groups()
        description = description.strip()
 
        matched_keyword = next(
            (k for k in SENSITIVE_KEYWORDS if k in description.lower()), None
        )
 
        results.append(make_finding(
            category="firmware",
            source="binwalk",
            target=target,
            severity="info",
            title=description,
            detail={
                "offset_decimal": int(offset_decimal),
                "offset_hex": offset_hex,
                "matched_keyword": matched_keyword,
            },
        ))
 
    return results
 
 
def run_scan(firmware_path: str) -> list[dict]:
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