#!/usr/bin/env python3
"""
Orchestrator：依序呼叫 nmap_scan / firmware_scan / zap_scan 三個掃描模組，
把各自回傳的 findings 彙整成一份合併報告。

對應架構圖：這支程式站在「收集層」之上，本身不做任何掃描邏輯，
只負責「決定要跑哪些模組」跟「把結果串起來」。三個模組各自仍然可以
單獨當 CLI 執行（python3 nmap_scan.py <ip>），這裡只是多一種串接用法。

設計取捨：任一模組失敗（工具沒裝、連線失敗、目標格式錯誤...）不會讓
整支程式中斷，會印出警告後跳過該模組、繼續跑其他有提供目標的模組，
最後彙整「有成功跑完的部分」。這是因為使用者可能只有部分目標可測
（例如只有 IP，還沒有韌體檔案），不該因為缺一項就整個失敗。
"""
import argparse
import sys

from datetime import datetime
from pathlib import Path

from common import save_findings_json, print_findings, set_output_dir, get_output_dir

import nmap_scan
import firmware_scan
import zap_scan
import report

try:
    # md_to_pdf 是子資料夾（package）的情況
    from md_to_pdf.md_to_pdf import convert as convert_md_to_pdf
except ImportError:
    try:
        # md_to_pdf.py 跟其他模組攤平在同一層的情況
        from md_to_pdf import convert as convert_md_to_pdf
    except ImportError:
        convert_md_to_pdf = None


def run_network_scan(
    ip: str,
    ports: str | None = None,
    timing: str = "T3",
    os_detection: bool = False,
    vuln_scripts: bool = False,
    scan_technique: str | None = None,
    host_discovery: bool = False,
    script_category: str | None = None,
) -> list[dict]:
    try:
        return nmap_scan.run_scan(
            ip, ports=ports, timing=timing, os_detection=os_detection, vuln_scripts=vuln_scripts,
            scan_technique=scan_technique, host_discovery=host_discovery, script_category=script_category,
        )
    except FileNotFoundError as e:
        print(f"[nmap] Error: {e}")
    except ValueError as e:
        print(f"[nmap] Error: {e}")
    return []


def run_firmware_scan(
    firmware_path: str,
    extract: bool = False,
    matryoshka: bool = False,
    run_as_root: bool = False,
) -> list[dict]:
    try:
        return firmware_scan.run_scan(
            firmware_path, extract=extract, matryoshka=matryoshka, run_as_root=run_as_root
        )
    except FileNotFoundError as e:
        print(f"[firmware] Error: {e}")
    return []


def run_webapp_scan(url: str, zap_api_url: str, active_scan: bool, auto_start: bool) -> list[dict]:
    try:
        return zap_scan.run_scan(
            url, zap_api_url=zap_api_url, active_scan=active_scan, auto_start=auto_start
        )
    except ImportError as e:
        print(f"[zap] Error: {e}")
    except ValueError as e:
        print(f"[zap] Error: {e}")
    except FileNotFoundError as e:
        print(f"[zap] Error: {e}")
    except zap_scan.ZapConnectionError as e:
        print(f"[zap] Error: {e}")
        print("[zap] 請確認 ZAP daemon 已啟動，例如：zaproxy -daemon -port 8080 -config api.disablekey=true")
        print("[zap] 或加上 --zap-auto-start 讓程式自動幫你啟動。")
    return []


def main():
    parser = argparse.ArgumentParser(
        description="IoT compliance scanner orchestrator (nmap + binwalk + ZAP)"
    )
    parser.add_argument("--ip", help="Target: single IP, CIDR range, or comma-separated list "
                                      "for network scan (nmap)")
    parser.add_argument("--ports", default=None,
                         help="nmap port 範圍，如 '1-1000' 或 '22,80,443'（搭配 --ip 使用）")
    parser.add_argument("--timing", default="T3", choices=sorted(nmap_scan.VALID_TIMING_TEMPLATES),
                         help="nmap timing template T0(最慢)~T5(最快)，預設 T3")
    parser.add_argument("--os-detection", action="store_true",
                         help="nmap 加上 -O 做作業系統指紋辨識")
    parser.add_argument("--vuln-scripts", action="store_true",
                         help="nmap 加上 --script vuln 執行已知漏洞探測腳本")
    parser.add_argument("--script-category", default=None, choices=sorted(nmap_scan.VALID_SCRIPT_CATEGORIES),
                         help="nmap 執行指定分類的 NSE script（vuln/default/discovery/safe）")
    parser.add_argument("--scan-technique", default=None, choices=sorted(nmap_scan.SCAN_TECHNIQUES),
                         help="nmap 掃描技巧：syn/connect/udp")
    parser.add_argument("--host-discovery", action="store_true",
                         help="nmap 先做主機存活探測（ping），預設關閉")
    parser.add_argument("--firmware", help="Path to firmware file for firmware scan (binwalk)")
    parser.add_argument("--extract", action="store_true",
                         help="binwalk 加上 -e 實際解壓縮（搭配 --firmware 使用）")
    parser.add_argument("--matryoshka", action="store_true",
                         help="binwalk 加上 -M 遞迴掃描解壓縮出來的內容")
    parser.add_argument("--run-as-root", action="store_true",
                         help="binwalk 以 root 執行時，明確放行第三方解壓縮工具"
                              "（降低一層安全防護，僅在 --extract 且以 root 執行時需要）")
    parser.add_argument("--url", help="Target URL for web app scan (ZAP)")
    parser.add_argument("--zap-api-url", default=zap_scan.DEFAULT_ZAP_API_URL,
                         help=f"ZAP daemon API URL (default: {zap_scan.DEFAULT_ZAP_API_URL})")
    parser.add_argument("--no-active-scan", action="store_true",
                         help="ZAP 只做 spider，不送出攻擊性請求")
    parser.add_argument("--zap-auto-start", action="store_true",
                         help="偵測不到 ZAP daemon 時自動啟動，掃描結束後自動關閉")
    parser.add_argument("--report", action="store_true",
                         help="掃描完成後一併產生 Markdown 合規報告")
    parser.add_argument("--operator", default="unknown",
                         help="操作者名稱，寫入報告的 Scan Information（搭配 --report 使用）")
    parser.add_argument("--pdf", action="store_true",
                         help="在 Markdown 報告之外，另外產生 PDF 版本（需搭配 --report）")
    parser.add_argument("--org", default="",
                         help="單位/系統名稱，顯示於 PDF 頁首頁尾（搭配 --pdf 使用）")
    parser.add_argument("--title", default=None,
                         help="PDF 報告標題，預設取自報告內文第一個標題（搭配 --pdf 使用）")
    args = parser.parse_args()

    if not (args.ip or args.firmware or args.url):
        parser.error("至少要提供 --ip、--firmware、--url 其中一個目標")

    # 在任何模組開始寫檔之前，先建立本次執行專屬的資料夾，並切換
    # common.get_output_dir()，讓 nmap_scan/firmware_scan/zap_scan/report
    # 這些模組接下來呼叫 get_output_dir() 拿到的都是這個新路徑——
    # 不需要逐一傳參數給每個模組，因為它們都是在「呼叫的當下」才去
    # 讀取路徑，而不是在 import 當下就把路徑寫死。
    run_ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    run_dir = set_output_dir(Path("output") / run_ts)
    print(f"本次執行輸出資料夾：{run_dir}")
    print()

    all_findings: list[dict] = []

    if args.ip:
        print("==== [1/3] Network scan (nmap) ====")
        all_findings += run_network_scan(
            args.ip, ports=args.ports, timing=args.timing,
            os_detection=args.os_detection, vuln_scripts=args.vuln_scripts,
            scan_technique=args.scan_technique, host_discovery=args.host_discovery,
            script_category=args.script_category,
        )
        print()

    if args.firmware:
        print("==== [2/3] Firmware scan (binwalk) ====")
        all_findings += run_firmware_scan(
            args.firmware, extract=args.extract, matryoshka=args.matryoshka,
            run_as_root=args.run_as_root,
        )
        print()

    if args.url:
        print("==== [3/3] Web app scan (ZAP) ====")
        all_findings += run_webapp_scan(args.url, args.zap_api_url, not args.no_active_scan, args.zap_auto_start)
        print()

    combined_json = save_findings_json(all_findings, f"combined_{run_ts}")

    print("==== Combined report ====")
    print(f"Combined JSON saved to: {combined_json}")
    print_findings(all_findings, empty_message="No findings from any module.")

    if args.report:
        scan_metadata = report.build_scan_metadata(
            operator=args.operator,
            ip=args.ip or "",
            firmware=args.firmware or "",
            url=args.url or "",
        )
        content = report.render_report(all_findings, scan_metadata)
        # 沿用跟 combined json 相同的時間戳記，方便從報告回溯到是哪次
        # orchestrator 執行產生的（跟 combined_{run_ts}.json 對應）
        report_path = report.save_report(content, f"report_{run_ts}")

        print()
        print("==== Report ====")
        print(f"Report saved to: {report_path}")

        if args.pdf:
            # PDF 轉換失敗不該讓已經產出的 Markdown 報告白費，
            # 只印警告並跳過，跟其他選用依賴（ZAP daemon、CWE 知識庫）
            # 一致的優雅降級原則。
            if convert_md_to_pdf is None:
                print("[pdf] Error: md_to_pdf 模組無法載入，略過 PDF 產生。")
                print("[pdf] 請確認 md_to_pdf/ 資料夾存在，且已安裝 markdown/beautifulsoup4/weasyprint。")
            else:
                pdf_path = report_path.replace(".md", ".pdf")
                try:
                    convert_md_to_pdf(report_path, pdf_path, title=args.title, org=args.org)
                except Exception as e:
                    print(f"[pdf] Error: PDF 轉換失敗（{e}），Markdown 報告仍可正常使用。")


if __name__ == "__main__":
    main()