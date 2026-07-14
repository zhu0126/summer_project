#!/usr/bin/env python3

import argparse
import ipaddress
import subprocess

from pathlib import Path
from datetime import datetime

OUTPUT_DIR = Path("output")
OUTPUT_DIR.mkdir(exist_ok=True)

def validate_ip(ip: str) -> str:
    return str(ipaddress.ip_address(ip))

def run_nmap(ip: str, base_name) -> tuple[int, str, str]:
    xml_path = OUTPUT_DIR / f"{base_name}.xml"
    txt_path = OUTPUT_DIR / f"{base_name}.txt"
    
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
        capture_output=True,
        text=True,
        check=False
    )

    return result.returncode, str(xml_path), str(txt_path), result.stderr

def main():

    parser = argparse.ArgumentParser(description="Simple IoT initial scanner")
    parser.add_argument("ip", help="Target IP address")
    args = parser.parse_args()

    ip = validate_ip(args.ip)
    time = datetime.now().strftime("%Y%m%d_%H%M%S")
    base_name = f"nmap_{ip}_{time}"

    code, xml_file, txt_file, err_msg = run_nmap(ip, base_name)

    print(f"Scan finished. Return code: {code}")

    if Path(xml_file).exists():
        print(f"XML saved to: {xml_file}")
    else:
        print(f"XML NOT created (expected at: {xml_file})")

    if Path(txt_file).exists():
        print(f"TXT saved to: {txt_file}")
    else:
        print(f"TXT NOT created (expected at: {txt_file})")

    # print(f"Saved to: {saved_file}")

if __name__ == "__main__":
    main()