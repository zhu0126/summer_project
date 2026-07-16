#!/usr/bin/env python3

import argparse
import ipaddress
import json
import subprocess
import shutil
import sys
import xml.etree.ElementTree as ET

from pathlib import Path
from datetime import datetime


OUTPUT_DIR = Path("output")
OUTPUT_DIR.mkdir(exist_ok=True)


def validate_ip(ip: str) -> str:
    return str(ipaddress.ip_address(ip))


def check_nmap_installed():
    if shutil.which("nmap") is None:
        raise FileNotFoundError("nmap not found in PATH")


def run_nmap(ip: str, base_name: str) -> tuple[int, str, str, str]:
    # 統一輸出檔案路徑
    xml_path = OUTPUT_DIR / f"{base_name}.xml"
    txt_path = OUTPUT_DIR / f"{base_name}.txt"
    log_path = OUTPUT_DIR / f"{base_name}.log"

    # 組合 nmap 指令
    cmd = [
        "nmap",
        "-sV",
        "-Pn",
        "-T3",
        "--open",
        "-oX", str(xml_path),
        "-oN", str(txt_path),
        ip,
    ]

    result = subprocess.run(
        cmd,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
        check=False
    )

    log_content = []
    log_content.append(f"Command: {' '.join(cmd)}")
    log_content.append(f"Return code: {result.returncode}")
    if result.stderr.strip():
        log_content.append("---- stderr ----")
        log_content.append(result.stderr.strip())

    log_path.write_text("\n".join(log_content) + "\n", encoding="utf-8")

    return result.returncode, str(xml_path), str(txt_path), str(log_path)


def parse_nmap_xml(xml_file: str) -> list[dict]:
    results = []
    tree = ET.parse(xml_file)
    root = tree.getroot()

    for host in root.findall("host"):
        addr_el = host.find("address")
        if addr_el is None:
            continue

        ip_addr = addr_el.get("addr", "")

        ports_el = host.find("ports")
        if ports_el is None:
            continue

        for port in ports_el.findall("port"):
            state_el = port.find("state")
            service_el = port.find("service")

            state = state_el.get("state", "") if state_el is not None else ""
            if state != "open":
                continue

            results.append({
                "ip": ip_addr,
                "protocol": port.get("protocol", ""),
                "port": port.get("portid", ""),
                "service": service_el.get("name", "") if service_el is not None else "",
                "product": service_el.get("product", "") if service_el is not None else "",
                "version": service_el.get("version", "") if service_el is not None else "",
            })

    return results


def save_findings_json(findings: list[dict], base_name: str) -> str:
    json_path = OUTPUT_DIR / f"{base_name}.json"
    json_path.write_text(
        json.dumps(findings, indent=2, ensure_ascii=False),
        encoding="utf-8"
    )
    return str(json_path)

# 輸出檔案狀態
def print_file_status(label: str, file_path: str) -> None:
    if Path(file_path).exists():
        print(f"{label} saved to: {file_path}")
    else:
        print(f"{label} NOT created (expected at: {file_path})")

# 輸出服務埠資訊
def print_open_ports(findings: list[dict]) -> None:
    if not findings:
        print("No open ports found in XML.")
        return

    print("---- Open ports ----")
    for item in findings:
        service_desc = item["service"]
        if item["product"] or item["version"]:
            service_desc = f'{service_desc} {item["product"]} {item["version"]}'.strip()
        print(f'{item["ip"]} {item["protocol"]}/{item["port"]} {service_desc}')


def handle_xml_findings(xml_file: str, base_name: str) -> None:
    try:
        findings = parse_nmap_xml(xml_file)
    except ET.ParseError as e:
        print(f"Warning: failed to parse XML output ({e}). See TXT/LOG for details.")
        return

    json_file = save_findings_json(findings, base_name)
    print_file_status("JSON", json_file)
    print_open_ports(findings)


def main():
    # 解析參數，取得IP
    parser = argparse.ArgumentParser(description="Simple IoT initial scanner")
    parser.add_argument("ip", help="Target IP address")
    args = parser.parse_args()

    # 檢查 nmap 是否安裝
    try:
        check_nmap_installed()
    except FileNotFoundError as e:
        print(f"Error: {e}")
        print("Please install nmap and make sure it is available in PATH.")
        sys.exit(1)

    # 檢查 IP 格式 (目前為IPv4，未來擴充CIDR)
    try:
        ip = validate_ip(args.ip)
    except ValueError:
        print(f"Error: '{args.ip}' is not a valid IP address.")
        sys.exit(1)

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    base_name = f"nmap_{ip}_{ts}"

    code, xml_file, txt_file, log_file = run_nmap(ip, base_name)

    print(f"Scan finished. Return code: {code}")

    print_file_status("XML", xml_file)
    print_file_status("TXT", txt_file)
    print_file_status("LOG", log_file)

    if code == 0 and Path(xml_file).exists():
        handle_xml_findings(xml_file, base_name)


if __name__ == "__main__":
    main()