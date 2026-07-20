#!/usr/bin/env python3

import argparse
import ipaddress
import subprocess
import shutil
import sys
import xml.etree.ElementTree as ET


from pathlib import Path
from datetime import datetime
from common import OUTPUT_DIR, print_file_status, save_findings_json, make_finding, print_findings

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
 
            protocol = port.get("protocol", "")
            port_id = port.get("portid", "")
            service = service_el.get("name", "") if service_el is not None else ""
            product = service_el.get("product", "") if service_el is not None else ""
            version = service_el.get("version", "") if service_el is not None else ""
 
            title = f"{protocol}/{port_id} {service}".strip()
            if product or version:
                title = f"{title} ({product} {version})".strip().replace("( ", "(").replace(" )", ")")
                
            results.append(make_finding(
                category="network",
                source="nmap",
                target=ip_addr,
                severity="info",
                title=title,
                detail={
                    "protocol": protocol,
                    "port": port_id,
                    "service": service,
                    "product": product,
                    "version": version,
                },
            ))
 
    return results


def run_scan(ip: str) -> list[dict]:
    check_nmap_installed()
    ip = validate_ip(ip)
 
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    base_name = f"nmap_{ip}_{ts}"
 
    code, xml_file, txt_file, log_file = run_nmap(ip, base_name)
 
    print(f"[nmap] Scan finished. Return code: {code}")
    print_file_status("XML", xml_file)
    print_file_status("TXT", txt_file)
    print_file_status("LOG", log_file)
 
    if not (code == 0 and Path(xml_file).exists()):
        return []
 
    findings = parse_nmap_xml(xml_file)  # 若 XML 損毀，ET.ParseError 交給呼叫端處理
    json_file = save_findings_json(findings, base_name)
    print_file_status("JSON", json_file)
    print_findings(findings, empty_message="No open ports found in XML.")
 
    return findings

def main():
    parser = argparse.ArgumentParser(description="Simple IoT initial scanner")
    parser.add_argument("ip", help="Target IP address")
    args = parser.parse_args()

    try:
        run_scan(args.ip)
    except FileNotFoundError as e:
        print(f"Error: {e}")
        print("Please install nmap and make sure it is available in PATH.")
        sys.exit(1)
    except ValueError:
        print(f"Error: '{args.ip}' is not a valid IP address.")
        sys.exit(1)
    except ET.ParseError as e:
        print(f"Warning: failed to parse XML output ({e}). See TXT/LOG for details.")


if __name__ == "__main__":
    main()