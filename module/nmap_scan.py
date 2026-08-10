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

from common import get_output_dir, print_file_status, save_findings_json, make_finding, print_findings

# 合法的 nmap timing template，只有這幾個值。UI 端的下拉選單應該只能選
# 這幾種，不開放自由輸入——跟不用自由文字讓使用者輸入任意 nmap 參數
# 是同一個安全設計原則：把使用者能輸入的範圍限制在「事先定義好的選項」。
VALID_TIMING_TEMPLATES = {"T0", "T1", "T2", "T3", "T4", "T5"}


def validate_ip(ip: str) -> str:
    return str(ipaddress.ip_address(ip))


def check_nmap_installed():
    if shutil.which("nmap") is None:
        raise FileNotFoundError("nmap not found in PATH")


def run_nmap(
    ip: str,
    base_name: str,
    ports: str | None = None,
    timing: str = "T3",
    os_detection: bool = False,
    vuln_scripts: bool = False,
) -> tuple[int, str, str, str]:
    xml_path = get_output_dir() / f"{base_name}.xml"
    txt_path = get_output_dir() / f"{base_name}.txt"
    log_path = get_output_dir() / f"{base_name}.log"

    if timing not in VALID_TIMING_TEMPLATES:
        raise ValueError(f"Invalid timing template: {timing!r}, must be one of {sorted(VALID_TIMING_TEMPLATES)}")

    # 用 list 組合每個參數，而不是把整個指令拼成一串字串（例如 f"nmap -sV ... {ip}"）。
    # 因為 subprocess.run 傳入 list 時不會經過 shell 解析，每個元素都被當成獨立的
    # 單一參數直接交給 nmap，即使 ip 或路徑裡混入空白、分號、& 等特殊字元，
    # 也不會被當成 shell 指令的一部分執行，能避免 shell injection 風險。
    # 即使之後接上 UI，可調整的參數也都是這種「事先定義好選項」的形式
    # （timing 限定 T0~T5、port 範圍另外驗證格式），不會讓使用者輸入的
    # 內容直接原封不動塞進 cmd list 裡。
    cmd = [
        "nmap",
        "-sV",
        "-Pn",
        f"-{timing}",
        "--open",
    ]

    if ports:
        cmd += ["-p", ports]
    if os_detection:
        cmd.append("-O")
    if vuln_scripts:
        cmd += ["--script", "vuln"]

    cmd += ["-oX", str(xml_path), "-oN", str(txt_path), ip]

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


def run_scan(
    ip: str,
    ports: str | None = None,
    timing: str = "T3",
    os_detection: bool = False,
    vuln_scripts: bool = False,
) -> list[dict]:
    """
    完整跑一次 nmap 掃描並回傳統一格式的 findings。

    跟 main() 的差異：這個函式不處理「怎麼跟使用者報錯」，失敗時直接
    把例外往外丟（FileNotFoundError／ValueError／ET.ParseError），
    由呼叫端（CLI 的 main() 或 orchestrator）自己決定要 sys.exit
    還是跳過這個模組、繼續跑其他掃描。這樣同一段核心邏輯才能同時被
    「單獨執行」和「被 project.py 串接呼叫」兩種情境共用。

    ports/timing/os_detection/vuln_scripts 都給了預設值，維持沒有
    UI、只用 CLI 呼叫時的行為不變（等同於原本寫死的 -T3 --open）。
    """
    check_nmap_installed()
    ip = validate_ip(ip)

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    base_name = f"nmap_{ip}_{ts}"

    code, xml_file, txt_file, log_file = run_nmap(
        ip, base_name,
        ports=ports, timing=timing, os_detection=os_detection, vuln_scripts=vuln_scripts,
    )

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
    parser.add_argument("--ports", default=None,
                         help="Port range, e.g. '1-1000' or '22,80,443' (預設: nmap 預設的常見連接埠)")
    parser.add_argument("--timing", default="T3", choices=sorted(VALID_TIMING_TEMPLATES),
                         help="nmap timing template T0(最慢/最隱蔽)~T5(最快)，預設 T3")
    parser.add_argument("--os-detection", action="store_true",
                         help="加上 -O 做作業系統指紋辨識（需要較高權限，且會延長掃描時間）")
    parser.add_argument("--vuln-scripts", action="store_true",
                         help="加上 --script vuln 執行已知漏洞探測腳本（會顯著延長掃描時間）")
    args = parser.parse_args()

    try:
        run_scan(
            args.ip,
            ports=args.ports,
            timing=args.timing,
            os_detection=args.os_detection,
            vuln_scripts=args.vuln_scripts,
        )
    except FileNotFoundError as e:
        print(f"Error: {e}")
        print("Please install nmap and make sure it is available in PATH.")
        sys.exit(1)
    except ValueError as e:
        print(f"Error: {e}")
        sys.exit(1)
    except ET.ParseError as e:
        print(f"Warning: failed to parse XML output ({e}). See TXT/LOG for details.")


if __name__ == "__main__":
    main()