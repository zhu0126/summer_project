#!/usr/bin/env python3
"""
韌體掃描模組：用 binwalk 分析韌體檔案裡的內嵌檔案系統、壓縮資料、
憑證/金鑰等訊號，屬於架構圖裡「收集層」的第二個掃描模組。

注意：binwalk 不會幫你「拿到」韌體，這裡假設韌體檔案已經在本機
（使用者手動上傳、或從裝置韌體更新機制另外下載），這支模組只負責分析。

安裝注意：PyPI 上的 `binwalk` 套件（pip install binwalk）目前是一個
不完整的殼套件，import 會直接失敗。請改用系統套件管理員安裝，例如：
    sudo apt-get install binwalk
這樣裝出來的才是真正可執行的 binwalk CLI。
"""
import argparse
import re
import shutil
import subprocess
import sys

from datetime import datetime
from pathlib import Path

from core.common import get_output_dir, print_file_status, save_findings_json, make_finding, print_findings

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


def run_binwalk(
    firmware_path: Path,
    base_name: str,
    extract: bool = False,
    matryoshka: bool = False,
    run_as_root: bool = False,
) -> tuple[int, str, str]:
    txt_path = get_output_dir() / f"{base_name}.txt"
    log_path = get_output_dir() / f"{base_name}.log"

    # 預設只做訊號掃描（signature scan），不解壓縮。extract/matryoshka
    # 這兩個旗標開放使用者手動調整，但注意：目前 parse_binwalk_output()
    # 只讀取 stdout 印出的訊號表格，解壓縮出來的實際檔案內容不會被
    # 進一步分析（遞迴分析解壓縮內容是刻意先擱置的待辦事項，不是這次
    # 順便做掉），開 -e 只是讓檔案被解壓縮到磁碟上，供你之後手動查看。
    cmd = ["binwalk"]
    if matryoshka:
        cmd.append("-M")  # 遞迴掃描解壓縮出來的內容
    if extract:
        cmd.append("-e")  # 實際解壓縮
        cmd += ["-C", str(get_output_dir() / f"{base_name}_extracted")]
        if run_as_root:
            # binwalk 用 root 權限執行時，預設會拒絕跑第三方解壓縮工具
            # （這些工具處理的是攻擊者可控的韌體檔案，用 root 權限執行
            # 有安全風險），要明確加這個旗標才會放行。Kali 常見以 root
            # 登入，這是實際會撞到的情境，不是理論邊角案例；但這個旗標
            # 本身就是在關掉一層安全防護，預設不開啟，UI 端呈現這個選項
            # 時務必附上清楚的風險說明，不要預設勾選。
            cmd.append("--run-as=root")
    cmd.append(str(firmware_path))

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

        # 出現私鑰、密碼檔、檔案系統這類訊號代表有值得留意的東西，
        # 但這只是我們自己寫的粗略關鍵字比對，不是 binwalk 本身的專業判斷。
        # 收集層統一先給 info，跟 nmap/zap 站在同一個起跑點；
        # 這個關鍵字判斷結果放進 detail.matched_keyword，
        # 留給合規判讀層決定要不要據此判斷風險等級。
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


def run_scan(
    firmware_path: str,
    extract: bool = False,
    matryoshka: bool = False,
    run_as_root: bool = False,
) -> list[dict]:
    """
    完整跑一次 binwalk 訊號掃描並回傳統一格式的 findings。
    設計理由跟 nmap_scan.run_scan 一致：失敗時直接丟出例外，
    讓呼叫端（CLI 的 main() 或 orchestrator）自行決定如何處理。
    """
    check_binwalk_installed()
    path = check_firmware_file(firmware_path)

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    base_name = f"firmware_{path.stem}_{ts}"

    code, txt_file, log_file = run_binwalk(
        path, base_name, extract=extract, matryoshka=matryoshka, run_as_root=run_as_root
    )

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
    parser.add_argument("--extract", action="store_true",
                         help="加上 -e 實際解壓縮（注意：目前只會把檔案解壓縮到磁碟，"
                              "不會自動進一步分析解壓縮出來的內容）")
    parser.add_argument("--matryoshka", action="store_true",
                         help="加上 -M 遞迴掃描解壓縮出來的內容（通常跟 --extract 搭配使用）")
    parser.add_argument("--run-as-root", action="store_true",
                         help="若以 root 身分執行本程式，binwalk 預設會拒絕跑第三方解壓縮工具"
                              "（處理攻擊者可控的韌體檔案有風險），加這個旗標明確放行"
                              "（僅在搭配 --extract 時有意義；等於降低一層安全防護，請謹慎使用）")
    args = parser.parse_args()

    try:
        run_scan(
            args.firmware,
            extract=args.extract,
            matryoshka=args.matryoshka,
            run_as_root=args.run_as_root,
        )
    except FileNotFoundError as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()