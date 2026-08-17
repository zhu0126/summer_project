#!/usr/bin/env python3
"""
離線測試 core/llm_advisor.py 的 derive_cra_remediation()（CRA 條文 + finding
一起讀，產出一句修補建議）與 core/analysis.py 的 _with_cra_remediation()。

刻意不呼叫真正的 Claude：monkeypatch llm_advisor.ask_llm，只驗證「快取
key 有沒有正確納入 finding 特徵」「呼叫失敗會不會安靜降級」這兩件事——
這正是把 translate_cra_article 換成 derive_cra_remediation 要修的核心問題：
舊版快取只用 article_no 當 key，同一條文配上不同 finding 會被誤判成
「已經算過了」，回傳跟這筆 finding 完全不相關的建議。

用暫存檔案取代真正的快取路徑，測試跑完不會弄髒 cra_kb/cra_data/ 底下
真正的快取檔案，也不會被機器上既有的快取內容影響測試結果。
"""
import sys
import tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core import llm_advisor
from core.common import make_finding

failures = []


def check(label: str, condition: bool, extra: str = "") -> None:
    print(f"[{'PASS' if condition else 'FAIL'}] {label}{(' — ' + extra) if extra else ''}")
    if not condition:
        failures.append(label)


redis_finding = make_finding("network", "nmap", "192.168.1.20", "info", "tcp/6379 redis",
                             detail={"service": "redis", "state": "open"})
telnet_finding = make_finding("network", "nmap", "192.168.1.20", "info", "tcp/23 telnet",
                              detail={"service": "telnet", "state": "open"})

print("==== llm_advisor：_finding_signature ====")
check("同一種弱點（category/source/title 相同）簽章相同",
      llm_advisor._finding_signature(redis_finding) ==
      llm_advisor._finding_signature(make_finding("network", "nmap", "10.0.0.5", "info", "tcp/6379 redis")))
check("不同弱點簽章不同",
      llm_advisor._finding_signature(redis_finding) != llm_advisor._finding_signature(telnet_finding))

print()
print("==== llm_advisor：derive_cra_remediation 快取行為 ====")

with tempfile.TemporaryDirectory() as tmpdir:
    original_cache_path = llm_advisor.CRA_REMEDIATION_CACHE_PATH
    original_ask = llm_advisor.ask_llm
    llm_advisor.CRA_REMEDIATION_CACHE_PATH = Path(tmpdir) / "cache.json"

    call_log = []

    def fake_ask_llm(system_instruction, prompt):
        call_log.append(prompt)
        return f"回覆第 {len(call_log)} 次"

    llm_advisor.ask_llm = fake_ask_llm
    try:
        r1 = llm_advisor.derive_cra_remediation(
            redis_finding, "Article 13", "Obligations", "manufacturers shall ensure..."
        )
        check("第一次呼叫回傳 Claude 的答案", r1 == "回覆第 1 次")
        check("第一次呼叫真的打了一次 ask_llm", len(call_log) == 1)

        r2 = llm_advisor.derive_cra_remediation(
            redis_finding, "Article 13", "Obligations", "manufacturers shall ensure..."
        )
        check("同一個 finding + 同一條文，第二次吃快取（不再呼叫）",
              r2 == "回覆第 1 次" and len(call_log) == 1)

        r3 = llm_advisor.derive_cra_remediation(
            telnet_finding, "Article 13", "Obligations", "manufacturers shall ensure..."
        )
        check("不同 finding + 同一條文，不會誤用 redis 的快取結果",
              r3 == "回覆第 2 次" and len(call_log) == 2)

        r4 = llm_advisor.derive_cra_remediation(
            redis_finding, "Article 14", "Reporting", "manufacturers shall report..."
        )
        check("同一個 finding + 不同條文，也是各自獨立的快取",
              r4 == "回覆第 3 次" and len(call_log) == 3)

        # prompt 裡要有 finding 的資訊，不能只餵條文全文——這正是這次
        # 修改要解決的問題：讓 LLM 讀得到「這是哪筆 finding」才寫得出
        # 針對這筆 finding 的具體建議。
        check("prompt 裡帶入了 finding 的 title", "tcp/6379 redis" in call_log[0])
        check("prompt 裡帶入了條文全文", "manufacturers shall ensure" in call_log[0])

        cache_on_disk = llm_advisor._load_cra_remediation_cache()
        check("快取確實落地到檔案，且有三筆獨立紀錄", len(cache_on_disk) == 3)
    finally:
        llm_advisor.ask_llm = original_ask
        llm_advisor.CRA_REMEDIATION_CACHE_PATH = original_cache_path

print()
print("==== llm_advisor：derive_cra_remediation 降級行為 ====")

with tempfile.TemporaryDirectory() as tmpdir:
    original_cache_path = llm_advisor.CRA_REMEDIATION_CACHE_PATH
    original_ask = llm_advisor.ask_llm
    llm_advisor.CRA_REMEDIATION_CACHE_PATH = Path(tmpdir) / "cache.json"
    llm_advisor.ask_llm = lambda system_instruction, prompt: None
    try:
        result = llm_advisor.derive_cra_remediation(redis_finding, "Article 13", "t", "x")
        check("Claude 回 None 時，函式回 None（不炸掉）", result is None)
        check("失敗的結果不會被寫進快取", llm_advisor._load_cra_remediation_cache() == {})
    finally:
        llm_advisor.ask_llm = original_ask
        llm_advisor.CRA_REMEDIATION_CACHE_PATH = original_cache_path

check("沒有 article_no 時直接回 None，不呼叫 Claude",
      llm_advisor.derive_cra_remediation(redis_finding, "", "t", "x") is None)

print()
print("==== analysis：_with_cra_remediation 接線 ====")

from core import analysis

candidate = {"article_no": "Article 13", "title": "Obligations", "text": "manufacturers shall..."}

original_fn = analysis.derive_cra_remediation
analysis.derive_cra_remediation = lambda finding, article_no, title, text: f"給 {finding['title']} 的建議"
try:
    result = analysis._with_cra_remediation(redis_finding, candidate)
    check("text_zh 帶入了正確的 finding 資訊", result["text_zh"] == "給 tcp/6379 redis 的建議")
    check("原始候選欄位（article_no 等）仍然保留", result["article_no"] == "Article 13")

    def _boom(finding, article_no, title, text):
        raise RuntimeError("api down")
    analysis.derive_cra_remediation = _boom
    result2 = analysis._with_cra_remediation(redis_finding, candidate)
    check("呼叫失敗時 text_zh 退回 None，不整個拋例外", result2["text_zh"] is None)
finally:
    analysis.derive_cra_remediation = original_fn

analysis.derive_cra_remediation = None
try:
    result3 = analysis._with_cra_remediation(redis_finding, candidate)
    check("llm_advisor 不可用時 text_zh 是 None", result3["text_zh"] is None)
finally:
    analysis.derive_cra_remediation = original_fn

print()
if failures:
    print(f"{len(failures)} 項未通過：" + "、".join(failures))
    sys.exit(1)
print("全部通過。")
