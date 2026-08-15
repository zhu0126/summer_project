#!/usr/bin/env python3
"""
離線測試 core/findings_merge.py 的風險等級排序：

報告的 Findings 章節原本是照 findings 進來的順序印，而 nmap 解析出來的
順序就是 XML 裡的連接埠遞增順序——結果 CRITICAL 的項目可能排在一堆
INFO 後面，要往下捲很久才看得到最該先處理的東西。改成由高到低排序後，
同一風險等級之間仍然要維持原本的連接埠順序（穩定排序）。

不需要 nmap / Qdrant / API 金鑰，純資料結構測試。
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.common import make_finding
from core.findings_merge import merge_findings_and_analysis, group_by_target, sort_by_risk_level

failures = []


def check(label: str, condition: bool, extra: str = "") -> None:
    print(f"[{'PASS' if condition else 'FAIL'}] {label}{(' — ' + extra) if extra else ''}")
    if not condition:
        failures.append(label)


print("==== sort_by_risk_level：五個等級由高到低 ====")

unsorted_items = [
    {"title": "info-1", "risk_level": "info"},
    {"title": "medium-1", "risk_level": "medium"},
    {"title": "critical-1", "risk_level": "critical"},
    {"title": "low-1", "risk_level": "low"},
    {"title": "high-1", "risk_level": "high"},
]
order = [f["risk_level"] for f in sort_by_risk_level(unsorted_items)]
check("排序結果是 critical→high→medium→low→info",
      order == ["critical", "high", "medium", "low", "info"], str(order))

print()
print("==== sort_by_risk_level：同等級維持原順序（穩定排序）====")

same_level = [
    {"title": "tcp/22", "risk_level": "info"},
    {"title": "tcp/80", "risk_level": "info"},
    {"title": "tcp/443", "risk_level": "critical"},
    {"title": "tcp/8080", "risk_level": "info"},
]
titles = [f["title"] for f in sort_by_risk_level(same_level)]
check("critical 提到最前面", titles[0] == "tcp/443", str(titles))
check("其餘 info 之間維持原本的連接埠順序",
      titles[1:] == ["tcp/22", "tcp/80", "tcp/8080"], str(titles))

print()
print("==== sort_by_risk_level：未知/缺漏的 risk_level 排在最後 ====")

with_unknown = [
    {"title": "weird", "risk_level": "bogus"},
    {"title": "missing"},
    {"title": "high-1", "risk_level": "high"},
]
titles = [f["title"] for f in sort_by_risk_level(with_unknown)]
check("認不得的等級不會擠到高風險前面", titles[0] == "high-1", str(titles))
check("不會因為缺 risk_level 就丟出例外", len(titles) == 3)

print()
print("==== merge_findings_and_analysis 回傳時已排好序 ====")

findings = [
    make_finding("network", "nmap", "10.0.0.1", "info", "tcp/22 ssh", detail={"service": "ssh"}),
    make_finding("network", "nmap", "10.0.0.1", "info", "tcp/23 telnet", detail={"service": "telnet"}),
    make_finding("network", "nmap", "10.0.0.1", "critical", "Heartbleed（tcp/443）",
                 detail={"cve_ids": ["CVE-2014-0160"]}),
]
analysis_results = [
    {"finding_id": findings[0]["finding_id"], "status": "no_match", "risk_level": "info"},
    {"finding_id": findings[1]["finding_id"], "status": "matched", "risk_level": "high"},
    {"finding_id": findings[2]["finding_id"], "status": "matched", "risk_level": "critical"},
]
merged = merge_findings_and_analysis(findings, analysis_results)
check("合併後即為 critical→high→info",
      [m["risk_level"] for m in merged] == ["critical", "high", "info"],
      str([m["risk_level"] for m in merged]))
check("合併的欄位沒有因為排序而遺失",
      merged[0]["title"] == "Heartbleed（tcp/443）" and merged[0]["status"] == "matched")

print()
print("==== group_by_target：高風險的目標排在前面 ====")

multi_target = [
    {"target": "10.0.0.2", "title": "quiet", "risk_level": "info"},
    {"target": "10.0.0.1", "title": "boom", "risk_level": "critical"},
    {"target": "10.0.0.2", "title": "also-bad", "risk_level": "high"},
]
groups = group_by_target(sort_by_risk_level(multi_target))
check("有 critical 的目標排在只有 info 的目標前面",
      groups[0]["target"] == "10.0.0.1", str([g["target"] for g in groups]))
check("同一目標底下也是高到低",
      [f["risk_level"] for f in groups[1]["findings"]] == ["high", "info"])

print()
if failures:
    print(f"{len(failures)} 項未通過：" + "、".join(failures))
    sys.exit(1)
print("全部通過。")
