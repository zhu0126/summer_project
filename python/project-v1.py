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

def run_nmap(ip: str) -> tuple[int, str]:

    cmd = [

        "nmap",

        "-sV",

        "-Pn",

        "-T3",

        "--open",

        ip,

    ]

    result = subprocess.run(

        cmd,

        capture_output=True,

        text=True,

        check=False

    )

    return result.returncode, result.stdout + "\n" + result.stderr

def save_result(ip: str, content: str) -> Path:

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")

    filename = OUTPUT_DIR / f"nmap_{ip}_{ts}.txt"

    filename.write_text(content, encoding="utf-8")

    return filename

def main():

    parser = argparse.ArgumentParser(description="Simple IoT initial scanner")

    parser.add_argument("ip", help="Target IP address")

    args = parser.parse_args()

    ip = validate_ip(args.ip)

    code, output = run_nmap(ip)

    saved_file = save_result(ip, output)

    print(f"Scan finished. Return code: {code}")

    print(f"Saved to: {saved_file}")

if __name__ == "__main__":

    main()