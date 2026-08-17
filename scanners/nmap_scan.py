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
import re
import subprocess
import shutil
import sys
import xml.etree.ElementTree as ET

from pathlib import Path
from datetime import datetime

from core.common import get_output_dir, print_file_status, save_findings_json, make_finding, print_findings

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


# ---- NSE vuln script 輸出解析 --------------------------------------------
#
# parse_nmap_xml() 只讀 <port> 的 state/service/product/version，對 <script>
# 元素（不管是掛在 port 底下、還是 host 層級的 <hostscript>）完全不碰——這代表
# 就算使用者在 UI 上選了「NSE Script 類別」= vuln，nmap 實際上跑出來的已知
# CVE/CVSS 資訊也完全不會進到 findings 裡，等於「有掃到、卻被程式碼丟掉」。
# 以下這組函式補上這一段，只解析、不改變 parse_nmap_xml() 既有行為。
#
# 只處理遵循 nmap 官方 vulns.lua library 慣例輸出的 script（現行內建
# --script vuln 分類底下絕大多數腳本，以及第三方的 vulners.nse／
# vulscan.nse 都是這個格式）：每筆已確認的弱點是一個 <table>，底下有
# <elem key="state">VULNERABLE</elem>，以及選填的 ids / scores 子表。
# 沒有用這套 library 的腳本（純文字輸出）不在處理範圍內——與其亂猜文字
# 格式誤判，不如保守地只吃資料已經結構化、可信賴解析的部分。

_CVE_ID_PATTERN = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)

# CVSS 分數轉四級風險，門檻採業界慣例（NVD 的 CVSS v3 定性分級一致）。
_CVSS_CRITICAL_THRESHOLD = 9.0
_CVSS_HIGH_THRESHOLD = 7.0
_CVSS_MEDIUM_THRESHOLD = 4.0

_RISK_FACTOR_TO_SEVERITY = {"critical": "critical", "high": "high", "medium": "medium", "low": "low"}

# vulns.lua 的 state 字串不是只有 "VULNERABLE" 一種，實際輸出還包含帶括號
# 補充說明的版本（見 nmap 官方 vulns.lua 的 STATE_MSG 對照表）：
#     VULNERABLE / VULNERABLE (Exploitable) / VULNERABLE (DoS)
#     LIKELY VULNERABLE / NOT VULNERABLE / UNKNOWN (unable to test)
# 原本用集合做「完全相等」比對，只認得沒有括號的那兩種，結果
# "VULNERABLE (Exploitable)" 這種**風險最高**的判定反而整筆被丟掉，連
# finding 都不會產生。改用前綴比對涵蓋所有變體；"NOT VULNERABLE" 不會
# 誤中，因為它是以 "NOT " 開頭。
_VULN_STATE_PREFIXES = ("VULNERABLE", "LIKELY VULNERABLE")

# CVSS 分數欄位的開頭數字。nmap 各腳本寫進 scores 子表的格式並不統一，
# 除了乾淨的 "9.8" 之外，很多腳本（例如 smb-vuln-cve2009-3103）寫的是
#     "10.0 (HIGH) (AV:N/AC:L/Au:N/C:C/I:C/A:C)"
# 這種「分數 + 定性等級 + 向量字串」的組合。直接 float() 會 ValueError，
# 分數就被當成沒有，最後只能退回 risk_factor——而 nmap 內建腳本的
# risk_factor 幾乎都只寫到 "High"，於是 CVSS 10.0 的弱點永遠顯示成 HIGH，
# critical 這一級實際上不可能出現。這裡只取開頭的數值部分。
_LEADING_SCORE_PATTERN = re.compile(r"^\s*(\d+(?:\.\d+)?)")


def _is_vulnerable_state(state: str) -> bool:
    return state.startswith(_VULN_STATE_PREFIXES)


def _parse_score(text: str) -> float | None:
    """從 scores 子表的一個 elem 文字裡取出 CVSS 數值，取不到回 None。"""
    m = _LEADING_SCORE_PATTERN.match(text or "")
    if m is None:
        return None
    try:
        return float(m.group(1))
    except ValueError:  # 理論上不會發生（regex 已保證格式），防禦性處理
        return None


def _score_to_severity(score: float | None) -> str | None:
    if score is None:
        return None
    if score >= _CVSS_CRITICAL_THRESHOLD:
        return "critical"
    if score >= _CVSS_HIGH_THRESHOLD:
        return "high"
    if score >= _CVSS_MEDIUM_THRESHOLD:
        return "medium"
    return "low"


def _parse_vuln_table(table_el: ET.Element) -> dict | None:
    """
    解析單一 <table> 節點，判斷它是不是一筆「已確認的弱點」（vulns.lua
    的 state 是 VULNERABLE 或 LIKELY VULNERABLE），是的話回傳結構化資訊，
    不是（例如這其實是 ids/scores 這種子表，或腳本判定 NOT VULNERABLE）
    就回傳 None，讓呼叫端跳過。
    """
    direct_elems = {}
    for elem in table_el.findall("elem"):
        key = elem.get("key")
        if key:
            direct_elems[key] = (elem.text or "").strip()

    state = direct_elems.get("state", "")
    if not _is_vulnerable_state(state):
        return None

    # CVE 編號：外層 table 的 key 屬性通常就是 "CVE-xxxx-xxxx" 本身；
    # 找不到的話再去 ids 子表（<table key="ids"><elem>CVE:CVE-xxxx-xxxx</elem>）撈。
    # 實際 nmap 輸出還可能在主 table 底下直接有 <elem>CVE:CVE-xxxx-xxxx</elem>（無 key）。
    cve_ids: list[str] = []
    table_key = table_el.get("key", "")
    if _CVE_ID_PATTERN.fullmatch(table_key):
        cve_ids.append(table_key.upper())

    # 直接在 table 底下的 elem（無 key 屬性）裡搜 CVE 編號
    for elem in table_el.findall("elem"):
        if elem.get("key") is not None:  # 跳過有 key 屬性的（已經在 direct_elems 了）
            continue
        m = _CVE_ID_PATTERN.search(elem.text or "")
        if m and m.group(0).upper() not in cve_ids:
            cve_ids.append(m.group(0).upper())

    ids_table = table_el.find('table[@key="ids"]')
    if ids_table is not None:
        for elem in ids_table.findall("elem"):
            m = _CVE_ID_PATTERN.search(elem.text or "")
            if m and m.group(0).upper() not in cve_ids:
                cve_ids.append(m.group(0).upper())

    # CVSS 分數：scores 子表可能同時有 CVSS2／CVSS3 兩個版本，取數值較高
    # （較新版本的評分）的一個當代表分數。各腳本的寫法不一致，交給
    # _parse_score() 處理（見該函式說明）。
    score = None
    scores_table = table_el.find('table[@key="scores"]')
    if scores_table is not None:
        for elem in scores_table.findall("elem"):
            v = _parse_score(elem.text or "")
            if v is None:
                continue
            if score is None or v > score:
                score = v

    return {
        "title": direct_elems.get("title", ""),
        "state": state,
        "cve_ids": cve_ids,
        "score": score,
        "risk_factor": direct_elems.get("risk_factor", ""),
    }


def _iter_script_elements(root: ET.Element):
    """
    走遍每個 host 的 script 輸出：host 層級（<hostscript>，例如
    smb-vuln-* 這類不依附特定 port 的檢測）跟每個開放 port 底下的
    <script>。刻意不處理 <prescript>/<postscript>（broadcast/探索類
    腳本，例如 broadcast-ping），那些不是針對「這個目標」的弱點判定。

    yield (ip_addr, port_label, script_element)，port_label 是
    host 層級腳本時為 None。
    """
    for host in root.findall("host"):
        addr_el = host.find("address")
        ip_addr = addr_el.get("addr", "") if addr_el is not None else ""

        hostscript = host.find("hostscript")
        if hostscript is not None:
            for script in hostscript.findall("script"):
                yield ip_addr, None, script

        ports_el = host.find("ports")
        if ports_el is not None:
            for port in ports_el.findall("port"):
                port_id = port.get("portid", "")
                protocol = port.get("protocol", "")
                port_label = f"{protocol}/{port_id}" if port_id else None
                for script in port.findall("script"):
                    yield ip_addr, port_label, script


def parse_nmap_vuln_findings(xml_file: str) -> list[dict]:
    """
    從 nmap XML 裡解析出 NSE vuln script 回報的已確認弱點，回傳統一格式的
    findings。跟 parse_nmap_xml() 是互補而非取代——這支只處理 <script>
    輸出，port 清單本身仍然由 parse_nmap_xml() 負責，run_scan() 會把兩邊
    結果合併。

    沒有跑 vuln 類 script、或跑了但沒有東西被判定 VULNERABLE 時，回傳
    空 list，不影響既有行為。
    """
    tree = ET.parse(xml_file)
    root = tree.getroot()

    results = []
    for ip_addr, port_label, script in _iter_script_elements(root):
        script_id = script.get("id", "")
        for table in script.findall(".//table"):
            vuln = _parse_vuln_table(table)
            if vuln is None:
                continue

            # 判定風險等級優先順序：CVSS 分數 > risk_factor > state 內容 > 保守預設
            severity = _score_to_severity(vuln["score"])
            if severity is None:
                severity = _RISK_FACTOR_TO_SEVERITY.get(vuln["risk_factor"].strip().lower())
            if severity is None:
                # 即使沒有分數/risk_factor，"(Exploitable)" 也表示已可利用，判為 critical
                if "(Exploitable)" in vuln["state"]:
                    severity = "critical"
                elif "(DoS)" in vuln["state"]:
                    severity = "high"
                else:
                    severity = "medium"  # 已確認 VULNERABLE，但沒有更多資訊時的保守預設

            title = vuln["title"] or (", ".join(vuln["cve_ids"]) if vuln["cve_ids"] else script_id)
            if port_label:
                title = f"{title}（{port_label}）"

            results.append(make_finding(
                category="network",
                source="nmap",
                target=ip_addr,
                severity=severity,
                title=title,
                detail={
                    "script_id": script_id,
                    "port": port_label,
                    "cve_ids": vuln["cve_ids"],
                    "cvss_score": vuln["score"],
                    "risk_factor": vuln["risk_factor"],
                    "state": vuln["state"],
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
    # 額外解析 NSE vuln script 的輸出（見 parse_nmap_vuln_findings() 說明）。
    # 沒有跑 vuln 類 script、或跑了但沒有東西被判定 VULNERABLE 時是空 list，
    # 不影響既有的 port 清單行為。
    findings += parse_nmap_vuln_findings(xml_file)
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