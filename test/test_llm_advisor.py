#!/usr/bin/env python3
"""
離線測試 RAG 的 context 組裝層（core/rag_context.py）跟 LLM 研判層
（core/llm_advisor.py）的引用查核邏輯。

刻意不碰 Qdrant、不呼叫 Claude：這兩層的職責是「把檢索結果變成
prompt」跟「檢查回覆有沒有亂引用」，兩件事都是純字串處理，用寫死的
假資料就能完整驗證。真正需要外部服務的路徑（檢索、API 呼叫）另外
用 test_rag.py 跟 llm_advisor.py 的 __main__ 手動測。

這樣切的實際好處：知識庫沒建、沒有 API 金鑰的環境下（例如 CI 或
剛 clone 下來的機器），這支測試仍然跑得起來，能擋掉格式化跟引用
查核這兩塊最容易在改動中悄悄壞掉的邏輯。
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core import llm_advisor
from core.common import make_finding
from core.rag_context import (
    MAX_CHARS_PER_ENTRY,
    TRUNCATION_MARK,
    build_context,
    collect_source_ids,
    entry_kind,
)

FAKE_CWE = [{
    "cwe_id": "CWE-319",
    "name": "Cleartext Transmission of Sensitive Information",
    "description": "The product transmits sensitive or security-critical data in cleartext.",
    "mitigations": ["Encrypt the data with a reliable encryption scheme before transmitting."],
    "score": 0.71,
    "matched_by": ["dense", "sparse"],
}]

# article_no 刻意用 non-breaking space（\xa0），跟 fetch_cra.py 從
# EUR-Lex 實際解析出來的格式一致——正規化沒做好的話，這裡就會露餡。
FAKE_CRA = [{
    "article_no": "Annex I Part\xa0I (2)(a)",
    "title": "Part\xa0I Essential cybersecurity requirements",
    "text": "protect the confidentiality of stored, transmitted or otherwise processed data.",
    "score": 0.66,
    "matched_by": ["dense"],
}]

# IEC 的 article_no 自帶標準名稱前綴，這是它跟 CRA 最大的格式差異——
# 下游要嘛整串比對，要嘛剝掉前綴比對，兩種都得成立。
FAKE_IEC = [{
    "article_no": "IEC 62443-4-2 CR 1.7",
    "clause_id": "CR 1.7",
    "standard": "IEC 62443-4-2",
    "title": "Strength of password-based authentication",
    "group": "FR 1 – Identification and authentication control",
    "text": "Requirement:\nComponents shall provide the capability to enforce "
            "configurable password strength.",
    "score": 0.58,
    "matched_by": ["sparse"],
}]

failures = []


def check(label: str, condition: bool, extra: str = "") -> None:
    print(f"[{'PASS' if condition else 'FAIL'}] {label}{(' — ' + extra) if extra else ''}")
    if not condition:
        failures.append(label)


print("==== rag_context ====")

check("Article 前綴判為 article", entry_kind("Article 13") == "article")
check("Annex 前綴判為 annex", entry_kind("Annex I Part\xa0I (2)(a)") == "annex")

context = build_context(FAKE_CWE, FAKE_CRA)
check("context 帶上 CWE 編號", "CWE-319" in context)
check("context 帶上 CRA 條號", "Annex I Part\xa0I (2)(a)" in context)
check("context 帶上官方緩解措施", "Encrypt the data" in context)
check("CWE 排在 CRA 前面",
      context.index("CWE-319") < context.index("Annex I"))

long_entry = [{"article_no": "Article 13", "title": "Obligations of manufacturers",
               "text": "x" * (MAX_CHARS_PER_ENTRY + 500)}]
long_context = build_context(cra_entries=long_entry)
check("過長條文有被截斷", TRUNCATION_MARK in long_context)
check("截斷後長度收在上限附近",
      len(long_context) < MAX_CHARS_PER_ENTRY + len(TRUNCATION_MARK) + 200,
      f"實際 {len(long_context)} 字元")

check("空候選產生空 context", build_context([], []) == "")

check("來源白名單涵蓋兩個知識庫",
      collect_source_ids(FAKE_CWE, FAKE_CRA) == ["CWE-319", "Annex I Part\xa0I (2)(a)"])

print()
print("==== rag_context：IEC 62443 ====")

check("IEC 前綴判為 standard", entry_kind("IEC 62443-4-2 CR 1.7") == "standard")

iec_context = build_context(FAKE_CWE, FAKE_CRA, FAKE_IEC)
check("context 帶上 IEC 條號", "IEC 62443-4-2 CR 1.7" in iec_context)
check("context 帶上 IEC 的 FR 分類", "FR 1 – Identification" in iec_context)
check("IEC 標頭不重複標準名稱",
      "IEC 62443-4-2 IEC 62443-4-2" not in iec_context)
check("順序是 CWE → IEC → CRA",
      iec_context.index("CWE-319") < iec_context.index("CR 1.7") < iec_context.index("Annex I"))

check("來源白名單涵蓋三個知識庫",
      collect_source_ids(FAKE_CWE, FAKE_CRA, FAKE_IEC)
      == ["CWE-319", "Annex I Part\xa0I (2)(a)", "IEC 62443-4-2 CR 1.7"])

check("不傳 iec 時行為與舊版一致",
      build_context(FAKE_CWE, FAKE_CRA) == build_context(FAKE_CWE, FAKE_CRA, []))

print()
print("==== llm_advisor：引用查核 ====")

allowed = collect_source_ids(FAKE_CWE, FAKE_CRA)

check("正確引用不被誤報",
      llm_advisor.verify_citations("依 CWE-319 與 Annex I Part I (2)(a) 之要求…", allowed) == [])

check("只寫上層條號不算幻覺（前綴涵蓋）",
      llm_advisor.verify_citations("參見 Annex I Part I 的要求。", allowed) == [])

check("編造的條號會被抓出來",
      llm_advisor.verify_citations("本項違反 Article 54 之規定。", allowed) == ["Article 54"])

check("編造的 CWE 會被抓出來",
      llm_advisor.verify_citations("對應 CWE-89 SQL Injection。", allowed) == ["CWE-89"])

check("同一個錯誤引用只回報一次",
      llm_advisor.verify_citations("Article 54 又提到 Article 54。", allowed) == ["Article 54"])

check("沒有任何引用時回空清單",
      llm_advisor.verify_citations("檢索到的候選與本項無明確關聯。", allowed) == [])

# 前綴比對的邊界檢查。舊版用裸 startswith()，"article 13" 會被
# "article 1" 涵蓋，白名單有 Article 13 時模型編造的 Article 1
# 就被靜默放行——引用查核最該擋下來的那種錯誤反而漏掉。
check("數字前綴不算涵蓋（Article 1 vs Article 13）",
      llm_advisor.verify_citations("依 Article 1 規定。", ["Article 13"]) == ["Article 1"])

check("編號完全相同仍算涵蓋",
      llm_advisor.verify_citations("依 Article 13 規定。", ["Article 13"]) == [])

check("Annex 上層編號仍算涵蓋（斷在空白）",
      llm_advisor.verify_citations("參見 Annex I Part I。",
                                   ["Annex I Part\xa0I (2)(a)"]) == [])

print()
print("==== llm_advisor：IEC 62443 引用查核 ====")

iec_allowed = collect_source_ids(FAKE_CWE, FAKE_CRA, FAKE_IEC)

check("完整寫出 IEC 條號不被誤報",
      llm_advisor.verify_citations("依 IEC 62443-4-2 CR 1.7 要求。", iec_allowed) == [])

check("省略標準名稱前綴也不被誤報",
      llm_advisor.verify_citations("依 CR 1.7 要求。", iec_allowed) == [])

check("編造的 CR 編號會被抓出來",
      llm_advisor.verify_citations("另依 CR 3.9 之規定。", iec_allowed) == ["CR 3.9"])

# CR 1.1 是 CR 1.11~1.14 的字串前綴，58 條 CR 裡這種關係一大票，
# 邊界判斷沒做好會讓一整批編造的條號被放行。
check("CR 1.1 不涵蓋 CR 1.11",
      llm_advisor.verify_citations("依 CR 1.11 要求。",
                                   ["IEC 62443-4-2 CR 1.1"]) == ["CR 1.11"])

check("requirement enhancement 後綴算涵蓋",
      llm_advisor.verify_citations("依 CR 1.7 RE(1) 要求。", iec_allowed) == [])

check("編造的 4-1 流程要求會被抓出來",
      llm_advisor.verify_citations("另見 SVV-4 滲透測試。", iec_allowed) == ["SVV-4"])

check("4-1 條號在白名單內時不被誤報",
      llm_advisor.verify_citations("另見 IEC 62443-4-1 SVV-4。",
                                   ["IEC 62443-4-1 SVV-4"]) == [])

print()
print("==== llm_advisor：advise_finding 流程 ====")

finding = make_finding("network", "nmap", "192.168.1.20", "info", "tcp/23 telnet",
                       detail={"service": "telnet", "state": "open"})

# 沒有候選就不該送出請求——用一個會直接讓測試失敗的假函式頂替，
# 確認這個短路真的有生效，而不是靠「剛好沒設金鑰」才沒送出去。
def _must_not_be_called(system_instruction, prompt):
    raise AssertionError("沒有候選資料時不應該呼叫 LLM")


original_ask = llm_advisor.ask_llm
llm_advisor.ask_llm = _must_not_be_called
try:
    check("沒有候選時不呼叫 LLM 且回 None",
          llm_advisor.advise_finding(finding, {"cwe": [], "cra": [], "iec": []}) is None)
    check("suggestions 為 None 時也回 None",
          llm_advisor.advise_finding(finding, None) is None)
finally:
    llm_advisor.ask_llm = original_ask

captured = {}


def _fake_ask(system_instruction, prompt):
    captured["system"] = system_instruction
    captured["prompt"] = prompt
    return "【CRA 關聯】Annex I Part I (2)(a) 要求保護傳輸資料的機密性。另見 Article 54。"


llm_advisor.ask_llm = _fake_ask
try:
    advice = llm_advisor.advise_finding(finding, {"cwe": FAKE_CWE, "cra": FAKE_CRA})
finally:
    llm_advisor.ask_llm = original_ask

check("有候選時回傳研判結果", advice is not None)
if advice:
    check("prompt 帶入 finding 標題", "tcp/23 telnet" in captured["prompt"])
    check("prompt 帶入 detail 欄位", "service: telnet" in captured["prompt"])
    check("prompt 帶入檢索到的參考資料", "CWE-319" in captured["prompt"])
    check("system instruction 要求只用參考資料作答", "ONLY" in captured["system"])
    check("system instruction 涵蓋 62443 段落", "62443" in captured["system"])
    check("sources 記錄實際餵進去的來源", advice["sources"] == allowed)
    check("回覆裡編造的條號被標記出來",
          advice["unsupported_citations"] == ["Article 54"],
          str(advice["unsupported_citations"]))

# 只有 IEC 候選、CWE/CRA 都空的情況也要送得出請求——短路條件漏掉
# 任何一個知識庫，就會變成「明明檢索到東西卻不呼叫 LLM」。
iec_only_captured = {}


def _capture_iec_only(system_instruction, prompt):
    iec_only_captured["prompt"] = prompt
    return "【62443 對應】IEC 62443-4-2 CR 1.7 要求可設定的密碼強度。"


llm_advisor.ask_llm = _capture_iec_only
try:
    iec_advice = llm_advisor.advise_finding(finding, {"cwe": [], "cra": [], "iec": FAKE_IEC})
finally:
    llm_advisor.ask_llm = original_ask

check("只有 IEC 候選時仍會呼叫 LLM", iec_advice is not None)
if iec_advice:
    check("prompt 帶入 IEC 條文", "CR 1.7" in iec_only_captured["prompt"])
    check("IEC 來源進入白名單", iec_advice["sources"] == ["IEC 62443-4-2 CR 1.7"])
    check("正確引用 IEC 條號不被誤報",
          iec_advice["unsupported_citations"] == [],
          str(iec_advice["unsupported_citations"]))

# ask_llm 回 None（沒金鑰/API 掛掉）時，整條路徑要安靜降級成 None，
# 而不是丟例外把報告產生流程一起帶走。
llm_advisor.ask_llm = lambda system_instruction, prompt: None
try:
    check("LLM 呼叫失敗時降級為 None",
          llm_advisor.advise_finding(finding, {"cwe": FAKE_CWE, "cra": FAKE_CRA}) is None)
finally:
    llm_advisor.ask_llm = original_ask

print()
if failures:
    print(f"{len(failures)} 項未通過：" + "、".join(failures))
    sys.exit(1)
print("全部通過。")
