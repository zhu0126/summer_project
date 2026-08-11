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

# 掃描技巧：key 是使用者選的結構化選項名稱，value 是實際的 nmap 旗標。
# 讓使用者選「syn/connect/udp」這種名稱，而不是直接輸入 "-sS" 這種
# 旗標字串，跟其他參數一致的設計——選項來自固定清單，不是自由輸入。
SCAN_TECHNIQUES = {
    "syn": "-sS",      # 預設，SYN 半開放掃描，通常需要 root/管理員權限
    "connect": "-sT",  # TCP 三向交握，不需要特殊權限，但較容易被偵測到
    "udp": "-sU",       # UDP 掃描，許多 IoT 服務（CoAP、mDNS、SNMP）跑在 UDP
}

# NSE script 分類，對應 nmap --script 後面可接的類別名稱
VALID_SCRIPT_CATEGORIES = {"vuln", "default", "discovery", "safe"}


# 網段大小的警告門檻：CIDR /24 以下（含）是 256 台以內，一般認為合理；
# 超過這個範圍（例如整個 /16 有 65536 個位址）掃描時間會大幅拉長，且更
# 容易誤掃到非預期範圍內的裝置，只印警告提醒，不強制擋下——跟專案裡
# 其他風險性操作（例如 ZAP active scan）一致的原則：提醒但不代為決定。
LARGE_NETWORK_WARNING_THRESHOLD = 256


def validate_targets(target_input: str) -> tuple[list[str], bool]:
    """
    支援以逗號分隔多個獨立目標，每個各自可以是單一 IP 或 CIDR，例如：
        "192.168.0.1,192.168.0.5"
        "192.168.0.0/24,10.0.0.5"
    不要求同一子網段——跟 nmap 自己的 "192.168.0.1,5" 這種同網段縮寫
    語法不同，這裡每個逗號分隔的片段都各自完整驗證，可以是完全不相關
    的網段。回傳 (正規化後的目標清單, 是否含有網段)。
    """
    raw_parts = [p.strip() for p in target_input.split(",") if p.strip()]
    if not raw_parts:
        raise ValueError("No target specified")

    targets = []
    any_range = False
    for part in raw_parts:
        normalized, is_range = validate_target(part)
        targets.append(normalized)
        any_range = any_range or is_range

    return targets, any_range


def validate_target(target: str) -> tuple[str, bool]:
    """
    同時接受單一 IP（如 192.168.1.1）跟 CIDR 網段（如 192.168.1.0/24）。
    回傳 (正規化後的字串, 是否為網段)。

    先試單一 IP，成功就直接回傳（維持原本行為不變，不會被硬加 /32
    這種後綴，避免既有的檔名/顯示格式跟著改變）；失敗才試 CIDR 格式。
    """
    try:
        return str(ipaddress.ip_address(target)), False
    except ValueError:
        pass

    try:
        network = ipaddress.ip_network(target, strict=False)
    except ValueError:
        raise ValueError(f"'{target}' is not a valid IP address or CIDR range")

    if network.num_addresses > LARGE_NETWORK_WARNING_THRESHOLD:
        print(f"[nmap] 警告：{network} 涵蓋 {network.num_addresses} 個位址，"
              f"掃描時間會顯著拉長，請確認範圍正確且你有權限掃描這整段網路。")

    return str(network), True


def validate_ip(ip: str) -> str:
    """保留舊名稱相容既有呼叫端，內部改呼叫 validate_target。"""
    target, _ = validate_target(ip)
    return target


def check_nmap_installed():
    if shutil.which("nmap") is None:
        raise FileNotFoundError("nmap not found in PATH")


def run_nmap(
    targets: list[str],
    base_name: str,
    ports: str | None = None,
    timing: str = "T3",
    os_detection: bool = False,
    vuln_scripts: bool = False,
    scan_technique: str | None = None,
    host_discovery: bool = False,
    script_category: str | None = None,
) -> tuple[int, str, str, str]:
    xml_path = get_output_dir() / f"{base_name}.xml"
    txt_path = get_output_dir() / f"{base_name}.txt"
    log_path = get_output_dir() / f"{base_name}.log"

    if timing not in VALID_TIMING_TEMPLATES:
        raise ValueError(f"Invalid timing template: {timing!r}, must be one of {sorted(VALID_TIMING_TEMPLATES)}")
    if scan_technique is not None and scan_technique not in SCAN_TECHNIQUES:
        raise ValueError(f"Invalid scan technique: {scan_technique!r}, must be one of {sorted(SCAN_TECHNIQUES)}")
    if script_category is not None and script_category not in VALID_SCRIPT_CATEGORIES:
        raise ValueError(f"Invalid script category: {script_category!r}, must be one of {sorted(VALID_SCRIPT_CATEGORIES)}")

    # vuln_scripts 是舊參數，保留相容：沒有明確指定 script_category 時，
    # 開了 vuln_scripts 就等同於 script_category="vuln"。
    effective_script_category = script_category or ("vuln" if vuln_scripts else None)

    # 用 list 組合每個參數，而不是把整個指令拼成一串字串（例如 f"nmap -sV ... {ip}"）。
    # 因為 subprocess.run 傳入 list 時不會經過 shell 解析，每個元素都被當成獨立的
    # 單一參數直接交給 nmap，即使 ip 或路徑裡混入空白、分號、& 等特殊字元，
    # 也不會被當成 shell 指令的一部分執行，能避免 shell injection 風險。
    # 即使之後接上 UI，可調整的參數也都是這種「事先定義好選項」的形式
    # （timing 限定 T0~T5、scan_technique/script_category 限定固定集合），
    # 不會讓使用者輸入的內容直接原封不動塞進 cmd list 裡。
    cmd = ["nmap", "-sV"]

    if scan_technique:
        cmd.append(SCAN_TECHNIQUES[scan_technique])

    if not host_discovery:
        cmd.append("-Pn")  # 跳過存活探測，假設主機都在線（維持原本預設行為）

    cmd += [f"-{timing}", "--open"]

    if ports:
        cmd += ["-p", ports]
    if os_detection:
        cmd.append("-O")
    if effective_script_category:
        cmd += ["--script", effective_script_category]

    cmd += ["-oX", str(xml_path), "-oN", str(txt_path)]
    cmd += targets  # 多個目標各自是獨立的 cmd 元素，不是合併成一個字串

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
    scan_technique: str | None = None,
    host_discovery: bool = False,
    script_category: str | None = None,
) -> list[dict]:
    """
    完整跑一次 nmap 掃描並回傳統一格式的 findings。

    ip 參數同時接受：單一 IP、CIDR 網段（例如 "192.168.1.0/24"）、
    或用逗號分隔的多個獨立目標（例如 "192.168.0.1,192.168.0.5"，
    甚至可以混用 "192.168.0.1,10.0.0.0/24"）。nmap 本身能一次接受
    多個目標，parse_nmap_xml() 本來就是逐一走過 XML 裡每個 <host>
    區塊，所以不管掃一台、一個網段、還是好幾個獨立目標，解析邏輯
    完全不用改，結果自然就是多筆 finding。

    跟 main() 的差異：這個函式不處理「怎麼跟使用者報錯」，失敗時直接
    把例外往外丟（FileNotFoundError／ValueError／ET.ParseError），
    由呼叫端（CLI 的 main() 或 orchestrator）自己決定要 sys.exit
    還是跳過這個模組、繼續跑其他掃描。這樣同一段核心邏輯才能同時被
    「單獨執行」和「被 project.py 串接呼叫」兩種情境共用。

    所有可調參數都給了預設值，維持沒有 UI、只用 CLI 呼叫時的行為
    不變（等同於原本寫死的 -sS -Pn -T3 --open）。
    """
    check_nmap_installed()
    targets, is_range = validate_targets(ip)

    # CIDR 裡的 "/" 不能直接放進檔名（會被當成路徑分隔符號，意外
    # 建出子資料夾）。單一目標維持原本的檔名格式；多個目標則用數量
    # 摘要命名，避免目標一多，檔名跟著沒完沒了地長。
    if len(targets) == 1:
        safe_name = targets[0].replace("/", "_")
    else:
        safe_name = f"multi_{len(targets)}targets"

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    base_name = f"nmap_{safe_name}_{ts}"

    if is_range:
        print(f"[nmap] 掃描網段：{', '.join(targets)}")
    elif len(targets) > 1:
        print(f"[nmap] 掃描 {len(targets)} 個目標：{', '.join(targets)}")

    code, xml_file, txt_file, log_file = run_nmap(
        targets, base_name,
        ports=ports, timing=timing, os_detection=os_detection, vuln_scripts=vuln_scripts,
        scan_technique=scan_technique, host_discovery=host_discovery, script_category=script_category,
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
    parser.add_argument("ip", help="Target: single IP, CIDR range, or comma-separated list "
                                    "(e.g. 192.168.1.1 / 192.168.1.0/24 / 192.168.1.1,192.168.1.5)")
    parser.add_argument("--ports", default=None,
                         help="Port range, e.g. '1-1000' or '22,80,443' (預設: nmap 預設的常見連接埠)")
    parser.add_argument("--timing", default="T3", choices=sorted(VALID_TIMING_TEMPLATES),
                         help="nmap timing template T0(最慢/最隱蔽)~T5(最快)，預設 T3")
    parser.add_argument("--os-detection", action="store_true",
                         help="加上 -O 做作業系統指紋辨識（需要較高權限，且會延長掃描時間）")
    parser.add_argument("--vuln-scripts", action="store_true",
                         help="加上 --script vuln 執行已知漏洞探測腳本（會顯著延長掃描時間，"
                              "等同於 --script-category vuln）")
    parser.add_argument("--script-category", default=None, choices=sorted(VALID_SCRIPT_CATEGORIES),
                         help="執行指定分類的 NSE script（vuln/default/discovery/safe）")
    parser.add_argument("--scan-technique", default=None, choices=sorted(SCAN_TECHNIQUES),
                         help="掃描技巧：syn(-sS，預設，需要權限) / connect(-sT，不需要權限) / "
                              "udp(-sU，UDP 掃描，適合 CoAP/mDNS/SNMP 等 IoT 常見服務)")
    parser.add_argument("--host-discovery", action="store_true",
                         help="先做主機存活探測（ping），預設關閉、假設所有目標都在線"
                              "（適合對方可能擋 ping 的情境，例如很多 IoT 裝置）")
    args = parser.parse_args()

    try:
        run_scan(
            args.ip,
            ports=args.ports,
            timing=args.timing,
            os_detection=args.os_detection,
            vuln_scripts=args.vuln_scripts,
            scan_technique=args.scan_technique,
            host_discovery=args.host_discovery,
            script_category=args.script_category,
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