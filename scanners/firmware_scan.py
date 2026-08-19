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

解壓縮內容分析：勾選 --extract（-e）之後，binwalk 只負責把內嵌的
檔案系統/封存檔解壓縮到磁碟，本身不會告訴你解壓縮出來的東西裡有沒有
私鑰、密碼檔這類問題——這一段原本是刻意擱置的待辦事項（只把檔案解壓
出來，剩下的靠人工翻）。現在補上 scan_extracted_files()：解壓縮完成後
自動走訪整棵目錄樹，用檔名樣式（id_rsa、shadow、*.pem…）加上輕量內容
比對（私鑰標頭）找出值得標記的檔案，一樣包成 finding 併入回傳結果，
跟其他掃描器一致地流入下游的合規判讀與報告產出，不需要人工再回頭
翻找解壓縮資料夾。
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

# 解壓縮出來的檔案系統裡，「檔名」符合這些樣式的視為值得標記——跟
# SENSITIVE_KEYWORDS 同樣的精神，但作用對象是實際解壓縮出來的檔案，
# 不是 binwalk 訊號表格裡的一行描述文字。severity 直接給值（不是留給
# 分析層猜）：檔案是否存在、檔名是什麼，是可以直接驗證的事實，跟
# nmap 已確認 CVE 的處理原則一致（見 nmap_scan.parse_nmap_vuln_findings）。
SENSITIVE_FILENAME_PATTERNS: list[tuple[re.Pattern, str, str]] = [
    (re.compile(r"^id_(rsa|dsa|ecdsa|ed25519)$"), "SSH 私鑰檔案", "high"),
    (re.compile(r"^ssh_host_.*_key$"), "SSH host 私鑰檔案", "high"),
    (re.compile(r".*\.(pem|key|p12|pfx)$", re.IGNORECASE), "疑似私鑰／憑證檔案", "high"),
    (re.compile(r"^shadow$"), "Unix shadow 密碼雜湊檔", "high"),
    (re.compile(r"^passwd$"), "Unix passwd 帳號檔", "medium"),
    (re.compile(r"^\.htpasswd$"), "Web htpasswd 憑證檔", "medium"),
    (re.compile(r"^wpa_supplicant\.conf$"), "Wi-Fi 設定檔（可能含明碼密碼）", "medium"),
]

# 檔案內容裡出現這些標頭代表確定是私鑰，用來補檔名比對的盲點——
# 私鑰被改成看不出來的檔名時（例如 "backup.dat"），光比對檔名會漏掉。
PRIVATE_KEY_CONTENT_MARKERS = [
    b"-----BEGIN RSA PRIVATE KEY-----",
    b"-----BEGIN DSA PRIVATE KEY-----",
    b"-----BEGIN EC PRIVATE KEY-----",
    b"-----BEGIN OPENSSH PRIVATE KEY-----",
    b"-----BEGIN PRIVATE KEY-----",
]

# 內容比對只讀取檔案大小在此上限以下的檔案，避免把解壓縮出來的巨大
# 二進位檔（例如整個 squashfs 映像）整個讀進記憶體只為了做字串搜尋。
CONTENT_SCAN_MAX_BYTES = 2 * 1024 * 1024  # 2MB

# 走訪解壓縮目錄時最多檢查的檔案數。-M（matryoshka）遞迴解壓縮可能
# 產生非常龐大的檔案樹，這個上限避免內容分析這一步時間失控；超過上限
# 會印出警告並提早停止，不是靜默漏掃。
MAX_EXTRACTED_FILES_SCANNED = 20000


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
    # 這兩個旗標開放使用者手動調整；開 -e 之後，run_scan() 會在 binwalk
    # 執行完再呼叫 scan_extracted_files() 走訪解壓縮出來的目錄樹，找出
    # 私鑰、密碼檔等值得標記的內容（見該函式說明），不是只把檔案丟到
    # 磁碟上就結束。
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


def _classify_extracted_file(path: Path) -> tuple[str, str] | None:
    """
    判斷一個解壓縮出來的檔案值不值得標記，回傳 (說明, severity)；
    不值得標記回傳 None。檔名比對優先（快、涵蓋大多數常見情況），
    檔名沒對到但檔案不大時再讀內容比對私鑰標頭，抓檔名被改過的私鑰。
    """
    name = path.name
    for pattern, label, severity in SENSITIVE_FILENAME_PATTERNS:
        if pattern.match(name):
            return label, severity

    try:
        if path.stat().st_size <= CONTENT_SCAN_MAX_BYTES:
            head = path.read_bytes()
            for marker in PRIVATE_KEY_CONTENT_MARKERS:
                if marker in head:
                    return "檔案內容含私鑰標頭", "high"
    except OSError:
        pass  # 權限問題、特殊檔案（device/socket）等，跳過不當成錯誤

    return None


def scan_extracted_files(extracted_root: Path, target: str) -> list[dict]:
    """
    走訪 binwalk -e 解壓縮出來的檔案樹，找出私鑰、密碼檔等值得標記的
    項目——這是原本 run_binwalk() 註解裡提到、刻意先擱置的待辦事項：
    -e 只負責把檔案解壓縮到磁碟，之前完全沒有任何自動分析。

    刻意的範圍限制：只用檔名樣式 + 輕量內容比對（私鑰標頭），不做通用
    機密掃描（例如 truffleHog 那種對整個檔案做熵值分析找疑似密鑰）——
    那需要專門工具，超出這支模組的角色；這裡要補的是「解壓縮出來的
    東西完全沒人看過」這個明顯缺口，不是取代專業機密掃描工具。

    extracted_root 不存在（例如 binwalk 沒有實際解壓出任何內容）回傳
    空 list，不當成錯誤——沒解出東西本身就是合理結果。
    """
    if not extracted_root.is_dir():
        return []

    findings = []
    scanned = 0
    truncated = False

    for path in extracted_root.rglob("*"):
        if scanned >= MAX_EXTRACTED_FILES_SCANNED:
            truncated = True
            break

        try:
            if path.is_symlink() or not path.is_file():
                continue
        except OSError:
            continue  # 壞掉的連結、無法 stat 的特殊檔案，跳過不中斷整個掃描

        scanned += 1

        classified = _classify_extracted_file(path)
        if classified is None:
            continue

        label, severity = classified
        rel_path = path.relative_to(extracted_root)
        try:
            size_bytes = path.stat().st_size
        except OSError:
            size_bytes = None

        findings.append(make_finding(
            category="firmware",
            source="binwalk",
            target=target,
            severity=severity,
            title=f"{label}：{rel_path}",
            detail={
                "extracted_path": str(rel_path),
                "size_bytes": size_bytes,
                "origin": "extracted_content",
            },
        ))

    if truncated:
        print(f"[binwalk] 警告：解壓縮檔案數超過上限（{MAX_EXTRACTED_FILES_SCANNED}），"
              "內容分析已提早停止，未掃描完整棵目錄樹。")

    return findings


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

    if extract:
        extracted_root = get_output_dir() / f"{base_name}_extracted"
        extracted_findings = scan_extracted_files(extracted_root, target=path.name)
        if extracted_findings:
            print(f"[binwalk] 解壓縮內容分析：找到 {len(extracted_findings)} 項值得留意的檔案。")
        findings += extracted_findings

    json_file = save_findings_json(findings, base_name)
    print_file_status("JSON", json_file)
    print_findings(findings, empty_message="No signatures found in firmware.")

    return findings


def main():
    parser = argparse.ArgumentParser(description="Firmware signature scanner (binwalk wrapper)")
    parser.add_argument("firmware", help="Path to firmware file")
    parser.add_argument("--extract", action="store_true",
                         help="加上 -e 實際解壓縮，並自動分析解壓縮出來的檔案"
                              "（找出私鑰、密碼檔等值得留意的內容）")
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