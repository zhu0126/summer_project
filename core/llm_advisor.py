#!/usr/bin/env python3
"""
RAG 的最後一段：把檢索到的 CWE/CRA 候選 + finding 本身交給 LLM，
產出一段人話的研判建議（Gemini，google-genai Interactions API）。

這支模組補上 keyword_rules.py 開頭那句註解裡一直寫著、但實際上還沒
做的「LLM 判讀」——在這之前，檢索結果是直接列成一串候選丟進報告，
使用者拿到的是「這五條可能有關」，而不是「這筆掃描結果跟這條的關係
是什麼」。

三個刻意的設計限制，都是延續 analysis.py 那個結論（向量分數無法區分
真訊號跟雜訊，所以 RAG 不該自己下判定）：

1. **只准引用給定的 context**：system instruction 明確禁止引用沒出現
   在參考資料裡的條號。LLM 內建知識裡的 CRA 條號記憶不可靠（會生出
   看起來很像、實際上編號錯位的條文），而錯的條號在合規報告裡比沒有
   條號更危險——讀的人不會每一條都回去查證。
2. **事後驗證引用**：光在 prompt 裡禁止是不夠的，回覆拿回來之後用
   verify_citations() 把答案裡出現的每個編號跟「這次真的餵進去的
   來源白名單」比對，對不上的列進 unsupported_citations，報告會把
   這件事直接印出來給人看。
3. **不改變 status**：LLM 的輸出只是附加在 needs_review 項目上的
   參考意見，不會讓任何一筆變成 matched。系統裡唯一會自動判定
   matched 的來源仍然只有規則比對。

依賴與金鑰都是選用的：沒裝 google-genai、沒設 GEMINI_API_KEY、
或 API 呼叫失敗，一律回傳 None 並印警告，讓分析流程照常跑完——
跟 CWE/CRA 知識庫連不上時的降級方式一致。
"""
import os
import re

from dotenv import load_dotenv
load_dotenv()

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# 環境變數名稱。不接受用參數傳明碼金鑰進來，也不從設定檔讀——
# 金鑰跟著程式碼或設定檔一起進版控是最常見的外洩途徑。
API_KEY_ENV = "GEMINI_API_KEY"

# 模型名稱允許用環境變數覆寫：模型版本汰換的速度比這個專案改版的速度快，
# 寫死在程式碼裡會變成每次換模型都要改一次原始碼。
MODEL_NAME = os.environ.get("GEMINI_MODEL", "gemini-2.5-flash")

SYSTEM_INSTRUCTION = """你是協助 IoT 產品資安合規盤點的分析助理。使用者會給你一筆掃描發現（finding），以及從 CWE 弱點資料庫與歐盟 CRA（Regulation (EU) 2024/2847）法規全文中，用語意檢索找出的候選參考資料。

嚴格規則：
1. 只能根據「參考資料」段落的內容作答。參考資料裡沒有的條號、CWE 編號、法規要求，一律不得寫出來，即使你認為自己知道。
2. 引用時必須完整寫出參考資料標頭裡的識別字串（例如 CWE-319、Article 13、Annex I Part I (2)(a)）。
3. 檢索結果不保證相關。如果候選資料跟這筆 finding 沒有實質關聯，就直接說明「檢索到的候選與本項無明確關聯」，不要勉強牽拖出一個對應。
4. 不要下最終合規判定，也不要寫「符合／不符合 CRA」這種結論。你的輸出是給人工複核的參考意見。

輸出格式（繁體中文，全文不超過 350 字）：
【風險研判】這筆發現實際代表什麼風險，一到兩句。
【對應弱點】最相關的 CWE 編號與理由；沒有相關的就寫「無明確對應」。
【CRA 關聯】最相關的條文編號與它要求了什麼；沒有相關的就寫「無明確對應」。
【修補建議】具體可執行的動作，優先採用參考資料中列出的緩解措施。
【不確定性】這份建議依據不足的地方，以及人工複核時該優先查證什麼。"""

# 從 LLM 回覆裡抓出「看起來像來源編號」的字串，用來跟白名單比對。
# 三種格式對應知識庫裡實際存在的編號樣式（見 cwe_entries.json 的
# cwe_id 與 cra_articles.json 的 article_no）。
CITATION_PATTERNS = [
    re.compile(r"CWE-\d+", re.IGNORECASE),
    re.compile(r"Article\s+\d+", re.IGNORECASE),
    re.compile(
        r"Annex\s+[IVX]+(?:\s+(?:Part|Class)\s+[IVX]+)?"
        r"(?:\s*(?:\([a-zA-Z0-9]+\)|\d+(?:\.\d+)*\.?))*",
        re.IGNORECASE,
    ),
]


def _normalize(text: str) -> str:
    """
    比對編號前先正規化：CRA 原文的 "Part I" 中間是 non-breaking space
    （\\xa0，EUR-Lex 排版產生的），LLM 回覆裡打的是一般空白，不處理的話
    同一個編號會比對不起來，把正確引用誤報成幻覺。
    """
    return re.sub(r"\s+", " ", text.replace("\xa0", " ")).strip().lower()


def is_available() -> bool:
    """LLM 這條路徑現在能不能用（套件裝了、金鑰設了）。"""
    if not os.environ.get(API_KEY_ENV):
        return False
    try:
        from google import genai  # noqa: F401
    except ImportError:
        return False
    return True


def ask_gemini(system_instruction: str, prompt: str) -> str | None:
    """
    送一次請求給 Gemini，回傳純文字回覆；任何失敗回傳 None。

    store=False：掃描結果含目標 IP、韌體檔名、內網服務清單，屬於客戶
    的資安現況資料，不該留存在服務端。這個參數沿用原始參考實作，
    在這個用途下更是必要而不只是預設值。
    """
    api_key = os.environ.get(API_KEY_ENV)
    if not api_key:
        print(f"[llm_advisor] 未設定環境變數 {API_KEY_ENV}，略過 LLM 研判。")
        return None

    try:
        from google import genai
    except ImportError:
        print("[llm_advisor] 未安裝 google-genai，略過 LLM 研判。"
              "安裝方式：pip install google-genai")
        return None

    try:
        client = genai.Client(api_key=api_key)
        interaction = client.interactions.create(
            model=MODEL_NAME,
            system_instruction=system_instruction,
            input=prompt,
            store=False,
        )
        return interaction.output_text
    except Exception as e:
        # 網路不通、金鑰無效、額度用完、模型名稱不存在——這些都不該
        # 讓整份報告產不出來，掃描結果本身仍然是有價值的產出。
        print(f"[llm_advisor] Gemini 呼叫失敗，略過 LLM 研判（{e}）")
        return None


def build_prompt(finding: dict, context: str) -> str:
    """
    組 user prompt：finding 摘要 + 參考資料。

    detail 用逐行 key: value 攤平，不用 json.dumps——detail 的欄位在
    不同掃描器之間差異很大（nmap 有 service/product/version，ZAP 有
    alert/risk/url），純文字的鍵值列表比 JSON 更省 token，LLM 讀起來
    也不會被括號跟引號干擾。
    """
    detail = finding.get("detail") or {}
    detail_lines = "\n".join(
        f"- {k}: {v}" for k, v in detail.items() if v not in (None, "", [], {})
    )

    return f"""# 掃描發現

- 標題：{finding.get('title', '')}
- 類別：{finding.get('category', '')}（來源工具：{finding.get('source', '')}）
- 目標：{finding.get('target', '')}
- 掃描器給定的嚴重度：{finding.get('severity', '')}
{detail_lines}

# 參考資料（語意檢索結果，可能不相關，僅能引用以下內容）

{context if context.strip() else '（本次沒有檢索到任何候選資料）'}
"""


def verify_citations(answer: str, allowed_ids: list[str]) -> list[str]:
    """
    檢查回覆裡出現的來源編號，有哪些不在這次餵進 context 的白名單裡。

    比對用「前綴關係」而不是完全相等：LLM 常常只寫到 "Annex I Part I"
    這種上層編號，白名單裡存的卻是更細的 "Annex I Part I (2)(a)"。
    這種情況不算幻覺（它引用的範圍確實涵蓋我們給的內容），只有雙向
    都對不上前綴的才列為可疑，避免誤報淹沒掉真正該注意的那幾筆。
    """
    allowed = [_normalize(i) for i in allowed_ids if i]

    found: list[str] = []
    for pattern in CITATION_PATTERNS:
        found.extend(m.group(0) for m in pattern.finditer(answer or ""))

    unsupported: list[str] = []
    for citation in found:
        norm = _normalize(citation)
        if any(norm.startswith(a) or a.startswith(norm) for a in allowed):
            continue
        if citation not in unsupported:
            unsupported.append(citation)

    return unsupported


def advise_finding(finding: dict, suggestions: dict | None) -> dict | None:
    """
    對單一 finding 產生 LLM 研判建議。

    suggestions 就是 analysis.py 放進 rag_suggestions 的那份
    {"cwe": [...], "cra": [...]}——刻意吃已經檢索好的結果，而不是自己
    再查一次，確保「報告裡列出的候選」跟「LLM 實際讀到的候選」是同一份，
    人工複核時看到的依據才跟 LLM 當時看到的一致。

    回傳 None 代表這條路徑不可用（沒金鑰/沒套件/呼叫失敗），
    呼叫端照常繼續，不要當成錯誤。
    """
    from core.rag_context import build_context, collect_source_ids

    cwe_entries = (suggestions or {}).get("cwe") or []
    cra_entries = (suggestions or {}).get("cra") or []

    # 兩邊都沒有候選時不送請求：沒有參考資料的情況下，LLM 只能靠內建
    # 知識回答，那正是這整套設計要避免的東西，而且還要花一次 API 呼叫。
    if not cwe_entries and not cra_entries:
        return None

    context = build_context(cwe_entries, cra_entries)
    answer = ask_gemini(SYSTEM_INSTRUCTION, build_prompt(finding, context))
    if answer is None:
        return None

    allowed_ids = collect_source_ids(cwe_entries, cra_entries)
    return {
        "answer": answer.strip(),
        "model": MODEL_NAME,
        "sources": allowed_ids,
        "unsupported_citations": verify_citations(answer, allowed_ids),
    }


if __name__ == "__main__":
    import sys
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

    from core.common import make_finding
    from core.analysis import analyze_finding

    if not is_available():
        print(f"LLM 尚未就緒：請確認已 pip install google-genai 並設定 {API_KEY_ENV}")
        sys.exit(1)

    sample = make_finding("network", "nmap", "192.168.1.20", "info", "tcp/23 telnet",
                          detail={"service": "telnet", "state": "open"})
    result = analyze_finding(sample, use_llm=True)
    advice = result.get("llm_advice")
    if advice is None:
        print("沒有取得 LLM 建議（可能是規則已比對到，或檢索沒有候選）。")
    else:
        print(advice["answer"])
        if advice["unsupported_citations"]:
            print("\n[警告] 以下引用不在提供的參考資料內：",
                  ", ".join(advice["unsupported_citations"]))
