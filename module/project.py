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

from common import save_findings_json, print_findings

import nmap_scan
import firmware_scan
import zap_scan
import report


def run_network_scan(ip: str) -> list[dict]:
    try:
        return nmap_scan.run_scan(ip)
    except FileNotFoundError as e:
        print(f"[nmap] Error: {e}")
    except ValueError:
        print(f"[nmap] Error: '{ip}' is not a valid IP address.")
    return []


def run_firmware_scan(firmware_path: str) -> list[dict]:
    try:
        return firmware_scan.run_scan(firmware_path)
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
    parser.add_argument("--ip", help="Target IP for network scan (nmap)")
    parser.add_argument("--firmware", help="Path to firmware file for firmware scan (binwalk)")
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
    args = parser.parse_args()

    if not (args.ip or args.firmware or args.url):
        parser.error("至少要提供 --ip、--firmware、--url 其中一個目標")

    all_findings: list[dict] = []

    if args.ip:
        print("==== [1/3] Network scan (nmap) ====")
        all_findings += run_network_scan(args.ip)
        print()

    if args.firmware:
        print("==== [2/3] Firmware scan (binwalk) ====")
        all_findings += run_firmware_scan(args.firmware)
        print()

    if args.url:
        print("==== [3/3] Web app scan (ZAP) ====")
        all_findings += run_webapp_scan(args.url, args.zap_api_url, not args.no_active_scan, args.zap_auto_start)
        print()

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    combined_json = save_findings_json(all_findings, f"combined_{ts}")

    print("==== Combined report ====")
    print(f"Combined JSON saved to: {combined_json}")
    print_findings(all_findings, empty_message="No findings from any module.")

    if args.report:
        # scope 依實際有提供的目標動態組成，讓報告的 Scan Information
        # 清楚交代這次掃描涵蓋了哪些對象，而不是只寫一個籠統的字串
        scope_parts = []
        if args.ip:
            scope_parts.append(f"IP: {args.ip}")
        if args.firmware:
            scope_parts.append(f"Firmware: {args.firmware}")
        if args.url:
            scope_parts.append(f"URL: {args.url}")
        scope = "; ".join(scope_parts)

        scan_metadata = report.build_scan_metadata(scope=scope, operator=args.operator)
        content = report.render_report(all_findings, scan_metadata)
        # 沿用跟 combined json 相同的時間戳記，方便從報告回溯到是哪次
        # orchestrator 執行產生的（跟 combined_{ts}.json 對應）
        report_path = report.save_report(content, f"report_{ts}")

        print()
        print("==== Report ====")
        print(f"Report saved to: {report_path}")


if __name__ == "__main__":
    main()