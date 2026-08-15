#!/usr/bin/env python3
"""
離線測試「nmap NSE vuln script 輸出解析」跟「CVE 比對結果如何流進分析層」
這兩段新邏輯：

1. scanners/nmap_scan.py 的 _parse_vuln_table / _iter_script_elements /
   parse_nmap_vuln_findings：用手寫的合成 XML（照 nmap 官方 vulns.lua
   library 的輸出慣例）驗證解析邏輯，不需要真的跑 nmap。
2. core/analysis.py 的 _cve_match / 一般化後的 _fallback_risk_level：
   驗證比對到 CVE 的 finding 會直接判定 matched，且風險等級不會被壓成 info。

寫死的合成 XML 片段是根據 nmap 官方文件與實際掃描結果裡常見的
vulns.lua 輸出格式手動組出來的（<table key="CVE-xxxx-xxxx"> 底下有
state/title elem，以及 ids/scores 子表），不是憑空亂猜的格式。
"""
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scanners import nmap_scan
from core.common import make_finding
from core import analysis

failures = []


def check(label: str, condition: bool, extra: str = "") -> None:
    print(f"[{'PASS' if condition else 'FAIL'}] {label}{(' — ' + extra) if extra else ''}")
    if not condition:
        failures.append(label)


print("==== nmap_scan：CVSS 分數轉風險等級 ====")
check("9.8 -> critical", nmap_scan._score_to_severity(9.8) == "critical")
check("9.0 邊界值 -> critical", nmap_scan._score_to_severity(9.0) == "critical")
check("8.9 -> high", nmap_scan._score_to_severity(8.9) == "high")
check("7.0 邊界值 -> high", nmap_scan._score_to_severity(7.0) == "high")
check("6.9 -> medium", nmap_scan._score_to_severity(6.9) == "medium")
check("4.0 邊界值 -> medium", nmap_scan._score_to_severity(4.0) == "medium")
check("3.9 -> low", nmap_scan._score_to_severity(3.9) == "low")
check("None -> None（沒有分數）", nmap_scan._score_to_severity(None) is None)

print()
print("==== nmap_scan：單一 <table> 解析（_parse_vuln_table）====")

VULN_TABLE_XML = """<table key="CVE-2017-5638">
  <elem key="title">Apache Struts Jakarta Multipart Parser OGNL Injection</elem>
  <elem key="state">VULNERABLE</elem>
  <table key="ids">
    <elem>CVE:CVE-2017-5638</elem>
  </table>
  <table key="scores">
    <elem key="CVSS:2.0">7.5</elem>
    <elem key="CVSS:3.0">10.0</elem>
  </table>
</table>"""
vuln = nmap_scan._parse_vuln_table(ET.fromstring(VULN_TABLE_XML))
check("解出 title", vuln is not None and vuln["title"] == "Apache Struts Jakarta Multipart Parser OGNL Injection")
check("state 是 VULNERABLE", vuln["state"] == "VULNERABLE")
check("table key 本身是 CVE 編號時被抓到", "CVE-2017-5638" in vuln["cve_ids"])
check("CVE 編號不重複", vuln["cve_ids"].count("CVE-2017-5638") == 1)
check("scores 取兩個版本中較高分（10.0，不是 7.5）", vuln["score"] == 10.0)

LIKELY_VULN_XML = """<table>
  <elem key="title">Some check</elem>
  <elem key="state">LIKELY VULNERABLE</elem>
  <table key="ids"><elem>CVE:CVE-2020-9999</elem></table>
</table>"""
likely = nmap_scan._parse_vuln_table(ET.fromstring(LIKELY_VULN_XML))
check("LIKELY VULNERABLE 也算已確認", likely is not None and likely["state"] == "LIKELY VULNERABLE")
check("沒有 table key 時從 ids 子表撈 CVE", "CVE-2020-9999" in likely["cve_ids"])

NOT_VULN_XML = """<table key="CVE-2019-0001">
  <elem key="title">Something checked but fine</elem>
  <elem key="state">NOT VULNERABLE</elem>
</table>"""
check("NOT VULNERABLE 回 None（不產生 finding）",
      nmap_scan._parse_vuln_table(ET.fromstring(NOT_VULN_XML)) is None)

NO_STATE_XML = '<table key="ids"><elem>CVE:CVE-2017-5638</elem></table>'
check("沒有 state 欄位的子表（如 ids/scores 本身）回 None",
      nmap_scan._parse_vuln_table(ET.fromstring(NO_STATE_XML)) is None)

RISK_FACTOR_ONLY_XML = """<table key="CVE-2021-1111">
  <elem key="title">No CVSS, only risk_factor</elem>
  <elem key="state">VULNERABLE</elem>
  <elem key="risk_factor">Critical</elem>
</table>"""
rf_only = nmap_scan._parse_vuln_table(ET.fromstring(RISK_FACTOR_ONLY_XML))
check("沒有 CVSS 分數時 risk_factor 欄位有被讀到", rf_only["risk_factor"] == "Critical" and rf_only["score"] is None)

# --- 以下兩組對應「選了 vuln 類 script，報告卻永遠不出現 Critical」的兩個成因 ---

# 成因 1：vulns.lua 的 state 還有帶括號的變體（VULNERABLE (Exploitable) /
# VULNERABLE (DoS)），原本用完全相等比對，這些風險最高的判定整筆被丟掉。
EXPLOITABLE_XML = """<table key="CVE-2019-0708">
  <elem key="title">BlueKeep RDP RCE</elem>
  <elem key="state">VULNERABLE (Exploitable)</elem>
  <table key="scores"><elem key="CVSSv2">10.0</elem></table>
</table>"""
exploitable = nmap_scan._parse_vuln_table(ET.fromstring(EXPLOITABLE_XML))
check("VULNERABLE (Exploitable) 有被視為已確認弱點",
      exploitable is not None and exploitable["score"] == 10.0)

DOS_XML = """<table key="CVE-2018-0001">
  <elem key="title">Some DoS</elem>
  <elem key="state">VULNERABLE (DoS)</elem>
</table>"""
check("VULNERABLE (DoS) 有被視為已確認弱點",
      nmap_scan._parse_vuln_table(ET.fromstring(DOS_XML)) is not None)

UNKNOWN_STATE_XML = """<table key="CVE-2018-0002">
  <elem key="title">Could not test</elem>
  <elem key="state">UNKNOWN (unable to test)</elem>
</table>"""
check("UNKNOWN (unable to test) 仍然不算弱點",
      nmap_scan._parse_vuln_table(ET.fromstring(UNKNOWN_STATE_XML)) is None)
check("NOT VULNERABLE 不會被前綴比對誤中",
      nmap_scan._parse_vuln_table(ET.fromstring(NOT_VULN_XML)) is None)

# 成因 2：很多 nmap 腳本的 scores 欄位不是乾淨的數字，而是
# "10.0 (HIGH) (AV:N/...)" 這種格式，原本 float() 直接失敗、分數被當成沒有，
# 於是退回 risk_factor（內建腳本最高只寫到 High）→ critical 永遠出不來。
check("scores 帶定性等級與向量字串時仍解得出分數",
      nmap_scan._parse_score("10.0 (HIGH) (AV:N/AC:L/Au:N/C:C/I:C/A:C)") == 10.0)
check("乾淨數字照常解析", nmap_scan._parse_score("9.8") == 9.8)
check("整數分數照常解析", nmap_scan._parse_score("10") == 10.0)
check("完全非數字回 None", nmap_scan._parse_score("N/A") is None)

MESSY_SCORE_XML = """<table key="CVE-2009-3103">
  <elem key="title">SMBv2 negotiation RCE</elem>
  <elem key="state">VULNERABLE</elem>
  <table key="scores">
    <elem key="CVSSv2">10.0 (HIGH) (AV:N/AC:L/Au:N/C:C/I:C/A:C)</elem>
  </table>
</table>"""
messy = nmap_scan._parse_vuln_table(ET.fromstring(MESSY_SCORE_XML))
check("實務格式的 scores 解出 10.0（不再退回 risk_factor）", messy["score"] == 10.0)
check("10.0 換算成 critical", nmap_scan._score_to_severity(messy["score"]) == "critical")

print()
print("==== nmap_scan：整份 XML 走查（parse_nmap_vuln_findings）====")

# 合成一份完整 nmap XML：
# - host 層級（hostscript）一筆 VULNERABLE，含 risk_factor（無 CVSS）
# - port 層級（tcp/443）一筆 VULNERABLE，含 CVSS 3.0 = 9.8（應判 critical）
# - port 層級另一筆 NOT VULNERABLE（不該產生 finding）
# - prescript（broadcast 類，不屬於這台主機本身）——不該被處理
SAMPLE_NMAP_XML = """<?xml version="1.0"?>
<nmaprun>
  <prescript>
    <script id="broadcast-ping" output="some broadcast noise"/>
  </prescript>
  <host>
    <address addr="192.168.100.1" addrtype="ipv4"/>
    <hostscript>
      <script id="smb-vuln-ms17-010" output="...">
        <table key="CVE-2017-0143">
          <elem key="title">MS17-010: Remote Code Execution</elem>
          <elem key="state">VULNERABLE</elem>
          <elem key="risk_factor">Critical</elem>
        </table>
      </script>
    </hostscript>
    <ports>
      <port protocol="tcp" portid="443">
        <state state="open"/>
        <service name="https"/>
        <script id="ssl-heartbleed" output="...">
          <table key="CVE-2014-0160">
            <elem key="title">OpenSSL Heartbleed</elem>
            <elem key="state">VULNERABLE</elem>
            <table key="scores">
              <elem key="CVSS:3.0">9.8</elem>
            </table>
          </table>
        </script>
        <script id="some-other-check" output="clean">
          <table key="CVE-2019-0001">
            <elem key="title">Checked but fine</elem>
            <elem key="state">NOT VULNERABLE</elem>
          </table>
        </script>
      </port>
    </ports>
  </host>
</nmaprun>"""

import tempfile
with tempfile.NamedTemporaryFile(mode="w", suffix=".xml", delete=False, encoding="utf-8") as f:
    f.write(SAMPLE_NMAP_XML)
    xml_path = f.name

try:
    vuln_findings = nmap_scan.parse_nmap_vuln_findings(xml_path)
    check("只產生 2 筆 finding（NOT VULNERABLE、broadcast 都被跳過）", len(vuln_findings) == 2)

    by_script = {f["detail"]["script_id"]: f for f in vuln_findings}
    check("host 層級（hostscript）的弱點有被抓到", "smb-vuln-ms17-010" in by_script)
    check("port 層級的弱點有被抓到", "ssl-heartbleed" in by_script)

    hostlevel = by_script.get("smb-vuln-ms17-010")
    check("host 層級 finding 沒有 port 標籤", hostlevel is not None and hostlevel["detail"]["port"] is None)
    check("host 層級 finding 用 risk_factor 判成 critical", hostlevel is not None and hostlevel["severity"] == "critical")
    check("host 層級 finding target 對到正確 IP", hostlevel is not None and hostlevel["target"] == "192.168.100.1")

    portlevel = by_script.get("ssl-heartbleed")
    check("port 層級 finding 有標出 tcp/443", portlevel is not None and portlevel["detail"]["port"] == "tcp/443")
    check("port 層級 finding 用 CVSS 9.8 判成 critical", portlevel is not None and portlevel["severity"] == "critical")
    check("port 層級 finding 帶出 CVE 編號", portlevel is not None and "CVE-2014-0160" in portlevel["detail"]["cve_ids"])
    # title 有值時優先顯示人看得懂的 title，CVE 編號留在 detail.cve_ids 裡即可，
    # 不需要在標題重複塞一次（title 只有沒有 vuln 名稱時才會退回顯示 CVE 編號）。
    check("port 層級 finding 標題優先用可讀的 title", portlevel is not None and portlevel["title"] == "OpenSSL Heartbleed（tcp/443）")
finally:
    Path(xml_path).unlink()

print()
print("==== analysis：CVE 比對結果直接判定 matched（_cve_match）====")

cve_finding = make_finding(
    "network", "nmap", "192.168.100.1", "critical", "OpenSSL Heartbleed（tcp/443）",
    detail={"script_id": "ssl-heartbleed", "port": "tcp/443",
            "cve_ids": ["CVE-2014-0160"], "cvss_score": 9.8, "risk_factor": "", "state": "VULNERABLE"},
)
result = analysis.analyze_finding(cve_finding, use_llm=False)
check("CVE finding 直接判定 matched", result["status"] == "matched")
check("風險等級採用 CVSS 換算出的 critical（沒被壓成 info）", result["risk_level"] == "critical")
check("recommendation 帶出 CVE 編號", "CVE-2014-0160" in result["recommendation"])
check("cra_reference 引用 Annex I Part II(1)", "Annex I Part II(1)" in result["cra_reference"])
check("沒有觸發 RAG 候選（有明確答案，不需要）", result["rag_suggestions"] is None)

no_cve_finding = make_finding("network", "nmap", "192.168.100.1", "info", "tcp/6379 redis",
                              detail={"service": "redis", "state": "open"})
check("沒有 cve_ids 時 _cve_match 回 None（不影響一般 finding 的既有流程）",
      analysis._cve_match(no_cve_finding) is None)

print()
print("==== analysis：一般化後的 _fallback_risk_level ====")
check("nmap CVE finding 的 severity=critical 會被沿用",
      analysis._fallback_risk_level(cve_finding) == "critical")

zap_finding = make_finding("webapp", "zap", "http://x", "info", "XSS", detail={"zap_risk": "high"})
check("ZAP 的 zap_risk 仍然照舊沿用（沒有因為改動而壞掉）",
      analysis._fallback_risk_level(zap_finding) == "high")

plain_finding = make_finding("network", "nmap", "192.168.100.1", "info", "tcp/6379 redis",
                             detail={"service": "redis", "state": "open"})
check("一般 nmap finding（severity=info、無 zap_risk）仍然是 info",
      analysis._fallback_risk_level(plain_finding) == "info")

print()
if failures:
    print(f"{len(failures)} 項未通過：" + "、".join(failures))
    sys.exit(1)
print("全部通過。")
