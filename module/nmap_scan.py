#!/usr/bin/env python3
"""
網路掃描模組：用 nmap 掃描單一 IP 的開放連接埠與服務版本，
屬於架構圖裡「收集層」的第一個掃描模組。

從原本的 project.py 搬過來，跟 firmware_scan.py / zap_scan.py 同一輩分：
三個模組各自可以獨立當 CLI 執行，也各自提供 run_scan() 給 project.py
（orchestrator）呼叫、串接使用。
"""
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
    xml_path = OUTPUT_DIR / f"{base_name}.xml"
    txt_path = OUTPUT_DIR / f"{base_name}.txt"
    log_path = OUTPUT_DIR / f"{base_name}.log"

    # 用 list 組合每個參數，而不是把整個指令拼成一串字串（例如 f"nmap -sV ... {ip}"）。
    # 因為 subprocess.run 傳入 list 時不會經過 shell 解析，每個元素都被當成獨立的
    # 單一參數直接交給 nmap，即使 ip 或路徑裡混入空白、分號、& 等特殊字元，
    # 也不會被當成 shell 指令的一部分執行，能避免 shell injection 風險。
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
                    "state": state,
                },
            ))

    return results


def run_scan(ip: str) -> list[dict]:
    """
    完整跑一次 nmap 掃描並回傳統一格式的 findings。

    跟 main() 的差異：這個函式不處理「怎麼跟使用者報錯」，失敗時直接
    把例外往外丟（FileNotFoundError／ValueError／ET.ParseError），
    由呼叫端（CLI 的 main() 或 orchestrator）自己決定要 sys.exit
    還是跳過這個模組、繼續跑其他掃描。這樣同一段核心邏輯才能同時被
    「單獨執行」和「被 project.py 串接呼叫」兩種情境共用。
    """
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
    parser = argparse.ArgumentParser(description="Simple IoT network scanner (nmap wrapper)")
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