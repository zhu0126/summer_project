#!/usr/bin/env python3

import argparse
import sys

from datetime import datetime

from common import save_findings_json, print_findings

import nmap_scan
import fw_scan
import zap_scan


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
        return fw_scan.run_scan(firmware_path)
    except FileNotFoundError as e:
        print(f"[firmware] Error: {e}")
    return []


def run_webapp_scan(url: str, zap_api_url: str, active_scan: bool) -> list[dict]:
    try:
        return zap_scan.run_scan(url, zap_api_url=zap_api_url, active_scan=active_scan)
    except ImportError as e:
        print(f"[zap] Error: {e}")
    except ValueError as e:
        print(f"[zap] Error: {e}")
    except zap_scan.ZapConnectionError as e:
        print(f"[zap] Error: {e}")
        print("[zap] 請確認 ZAP daemon 已啟動，例如：zap.sh -daemon -port 8080 -config api.disablekey=true")
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
        all_findings += run_webapp_scan(args.url, args.zap_api_url, not args.no_active_scan)
        print()

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    combined_json = save_findings_json(all_findings, f"combined_{ts}")

    print("==== Combined report ====")
    print(f"Combined JSON saved to: {combined_json}")
    print_findings(all_findings, empty_message="No findings from any module.")


if __name__ == "__main__":
    main()