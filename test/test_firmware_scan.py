#!/usr/bin/env python3
"""
離線測試 scanners/firmware_scan.py 的「解壓縮內容分析」邏輯
（_classify_extracted_file / scan_extracted_files）。

刻意不呼叫真正的 binwalk：這一段邏輯是純粹的檔案樹走訪 + 檔名/內容
比對，用臨時目錄手動造出幾個檔案就能完整驗證，不需要真的解壓縮
一份韌體、也不需要系統裝了 binwalk 才能跑。
"""
import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scanners import firmware_scan as fw

failures = []


def check(label: str, condition: bool, extra: str = "") -> None:
    print(f"[{'PASS' if condition else 'FAIL'}] {label}{(' — ' + extra) if extra else ''}")
    if not condition:
        failures.append(label)


tmp_root = Path(tempfile.mkdtemp(prefix="fw_extract_test_"))
try:
    extracted = tmp_root / "squashfs-root"
    (extracted / "root" / ".ssh").mkdir(parents=True)
    (extracted / "etc").mkdir(parents=True)
    (extracted / "etc" / "wifi").mkdir(parents=True)

    # 檔名比對：SSH 私鑰
    (extracted / "root" / ".ssh" / "id_rsa").write_bytes(b"fake key bytes not a real header")
    # 檔名比對：shadow / passwd
    (extracted / "etc" / "shadow").write_text("root:$6$abc$hash:19000:0:99999:7:::\n")
    (extracted / "etc" / "passwd").write_text("root:x:0:0:root:/root:/bin/sh\n")
    # 檔名沒對到任何樣式，但內容有私鑰標頭——測「怪異檔名藏私鑰」的路徑
    (extracted / "backup.dat").write_bytes(
        b"-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA...\n-----END OPENSSH PRIVATE KEY-----\n"
    )
    # 完全無關的一般檔案，不該被標記
    (extracted / "etc" / "hostname").write_text("my-device\n")
    # Wi-Fi 設定檔
    (extracted / "etc" / "wifi" / "wpa_supplicant.conf").write_text('psk="hunter2"\n')

    print("==== firmware_scan：_classify_extracted_file ====")
    check("id_rsa 被判為 SSH 私鑰（high）",
          fw._classify_extracted_file(extracted / "root" / ".ssh" / "id_rsa") == ("SSH 私鑰檔案", "high"))
    check("shadow 被判為 high",
          fw._classify_extracted_file(extracted / "etc" / "shadow")[1] == "high")
    check("passwd 被判為 medium",
          fw._classify_extracted_file(extracted / "etc" / "passwd")[1] == "medium")
    check("怪異檔名但內容含私鑰標頭仍被抓到",
          fw._classify_extracted_file(extracted / "backup.dat") == ("檔案內容含私鑰標頭", "high"))
    check("無關檔案回傳 None",
          fw._classify_extracted_file(extracted / "etc" / "hostname") is None)
    check("wpa_supplicant.conf 被判為 medium",
          fw._classify_extracted_file(extracted / "etc" / "wifi" / "wpa_supplicant.conf") == (
              "Wi-Fi 設定檔（可能含明碼密碼）", "medium"))

    print()
    print("==== firmware_scan：scan_extracted_files ====")
    findings = fw.scan_extracted_files(extracted, target="firmware.bin")
    titles = {f["title"] for f in findings}

    check("找到預期數量的可疑檔案（5 筆，hostname 不算）", len(findings) == 5, f"實際 {len(findings)} 筆")
    check("每筆都是 firmware 類別、binwalk 來源",
          all(f["category"] == "firmware" and f["source"] == "binwalk" for f in findings))
    check("每筆都標記來源是解壓縮內容",
          all(f["detail"]["origin"] == "extracted_content" for f in findings))
    check("id_rsa 有進結果", any("id_rsa" in t for t in titles))
    check("shadow 有進結果", any("shadow" in t for t in titles))
    check("target 正確帶入", all(f["target"] == "firmware.bin" for f in findings))

    rsa_finding = next(f for f in findings if "id_rsa" in f["title"])
    check("相對路徑用 POSIX 分隔符（跨平台一致）",
          rsa_finding["detail"]["extracted_path"] in ("root/.ssh/id_rsa", "root\\.ssh\\id_rsa"))

    print()
    print("==== firmware_scan：邊界情況 ====")
    check("不存在的目錄回傳空 list", fw.scan_extracted_files(tmp_root / "does_not_exist", "x") == [])

    empty_dir = tmp_root / "empty"
    empty_dir.mkdir()
    check("空目錄回傳空 list", fw.scan_extracted_files(empty_dir, "x") == [])

    # 檔案數上限：暫時調低門檻，確認會提早停止而不是把整棵樹掃完
    original_limit = fw.MAX_EXTRACTED_FILES_SCANNED
    fw.MAX_EXTRACTED_FILES_SCANNED = 2
    try:
        limited = fw.scan_extracted_files(extracted, target="x")
        check("超過檔案數上限時會提早停止", len(limited) <= 2, f"實際 {len(limited)} 筆")
    finally:
        fw.MAX_EXTRACTED_FILES_SCANNED = original_limit

finally:
    shutil.rmtree(tmp_root, ignore_errors=True)

print()
if failures:
    print(f"{len(failures)} 項未通過：" + "、".join(failures))
    sys.exit(1)
print("全部通過。")
