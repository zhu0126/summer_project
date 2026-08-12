#!/usr/bin/env python3
"""
測試腳本：不執行 nmap，直接對 output/ 資料夾裡「既有的」xml/txt/log 檔案
跑 nmap_scan.py 裡跟解析相關的函式，快速驗證邏輯是否正確。

用法：
    python3 test_scanner.py                  # 自動抓 output/ 裡最新一組檔案
    python3 test_scanner.py nmap_192.168.1.1_20260716_153000  # 指定 base_name
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# get_output_dir/print_file_status/save_findings_json/print_findings 是三個掃描
# 模組共用的邏輯，統一放在 common.py；parse_nmap_xml 是 nmap 特有的解析邏輯，
# 放在 nmap_scan.py。故意不呼叫 nmap_scan.run_scan()，因為那個函式會重新執行
# 一次 nmap，不符合這支測試腳本「不重跑 nmap，只驗證既有檔案」的目的。
from core.common import get_output_dir, print_file_status, save_findings_json, print_findings
from scanners.nmap_scan import parse_nmap_xml


def find_latest_base_name() -> str:
    """從 output/ 資料夾裡找最新的一組 nmap_*.xml，回傳去掉副檔名的 base_name"""
    xml_files = sorted(get_output_dir().glob("nmap_*.xml"))
    if not xml_files:
        print(f"Error: 在 {get_output_dir()} 裡找不到任何 nmap_*.xml 檔案。")
        print("請確認 output/ 資料夾底下有先前執行留下的檔案，")
        print("或手動指定 base_name，例如：python3 test_scanner.py nmap_192.168.1.1_20260716_153000")
        sys.exit(1)
    latest = max(xml_files, key=lambda p: p.stat().st_mtime)
    return latest.stem  # 檔名去掉 .xml 後的部分，就是 base_name


def main():
    # 決定要測試哪一組檔案：指定 base_name 或自動抓最新的
    if len(sys.argv) > 1:
        base_name = sys.argv[1]
    else:
        base_name = find_latest_base_name()

    xml_file = str(get_output_dir() / f"{base_name}.xml")
    txt_file = str(get_output_dir() / f"{base_name}.txt")
    log_file = str(get_output_dir() / f"{base_name}.log")

    print(f"Testing with base_name: {base_name}")
    print("=" * 50)

    # 1. 測試 print_file_status：確認三個原始檔案是否存在
    print_file_status("XML", xml_file)
    print_file_status("TXT", txt_file)
    print_file_status("LOG", log_file)

    print("-" * 50)

    # 2. 測試解析流程：解析 XML → 存 JSON → 印出摘要
    #    這一步不需要 nmap，只需要既有的 .xml 檔案就能測試
    if Path(xml_file).exists():
        findings = parse_nmap_xml(xml_file)
        json_file = save_findings_json(findings, base_name)
        print_file_status("JSON", json_file)
        print_findings(findings, empty_message="No open ports found in XML.")
    else:
        print(f"Skip: {xml_file} 不存在，無法測試解析流程")


if __name__ == "__main__":
    main()