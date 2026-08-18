#!/usr/bin/env python3
"""
RAG 的最後一段：把檢索到的 CWE / IEC 62443 / CRA 候選 + finding 本身交給 LLM，
產出一段人話的研判建議（Claude，Anthropic Messages API）。

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

依賴與金鑰都是選用的：沒裝 anthropic、沒設 ANTHROPIC_API_KEY、
或 API 呼叫失敗，一律回傳 None 並印警告，讓分析流程照常跑完——
跟 CWE/CRA 知識庫連不上時的降級方式一致。
"""
import json
import os
import re

from pathlib import Path

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# 環境變數名稱。不接受用參數傳明碼金鑰進來，也不從設定檔讀——
# 金鑰跟著程式碼或設定檔一起進版控是最常見的外洩途徑。
API_KEY_ENV = "ANTHROPIC_API_KEY"

# 模型名稱允許用環境變數覆寫：模型版本汰換的速度比這個專案改版的速度快，
# 寫死在程式碼裡會變成每次換模型都要改一次原始碼。預設用 Haiku（快、便宜）
# 而不是 Sonnet/Opus——這裡每次呼叫的輸出都很短（一句話的修補建議、一段
# 研判摘要），不需要最頂級的推理能力，換成 Haiku 對「同一批 finding 逐筆
# 呼叫」這種用量模式比較省成本。要換更高階的模型，設環境變數 CLAUDE_MODEL
# 即可，不需要改程式碼。
MODEL_NAME = os.environ.get("CLAUDE_MODEL", "claude-haiku-4-5-20251001")

SYSTEM_INSTRUCTION = """You are an assistant supporting IoT product cybersecurity compliance review. You will be given one scan finding, plus candidate reference material retrieved via semantic search from three sources: a CWE weakness database, the technical component requirements of IEC 62443-4-2, and the full text of the EU CRA (Regulation (EU) 2024/2847).

Strict rules:
1. Answer using ONLY the content in the "Reference Material" section. Do not state any article number, clause number, CWE ID, or requirement that does not appear there, even if you believe you know it.
2. When citing, reproduce the exact identifier string as it appears in the reference material header (e.g. CWE-319, Article 13, Annex I Part I (2)(a), IEC 62443-4-2 CR 1.7). For IEC 62443 clauses always include the standard number prefix; do not shorten "IEC 62443-4-2 CR 1.7" to "CR 1.7". Do not abbreviate, renumber, or paraphrase identifiers.
3. Retrieved results are not guaranteed to be relevant. If none of the candidates have a substantive connection to this finding, say so plainly instead of forcing a match.
4. Do not issue a final compliance verdict. Never write that something "complies" or "does not comply" with the CRA or IEC 62443. Note also that the CRA is binding EU law while IEC 62443 is a voluntary standard, so an IEC clause match does not by itself imply any legal obligation. Your output is advisory input for a human reviewer only.
5. Output ONLY the six labeled sections below, in this exact order, with no text before the first label or after the last section. No markdown, no bullet points, no headings other than the labels themselves.

Output format — write the content in Traditional Chinese (zh-TW); total length must not exceed 450 characters; use exactly these six labels, each on its own line, each followed by its content on the same line:
【風險研判】這筆發現實際代表什麼風險，限一到兩句話。
【對應弱點】最相關的 CWE 編號與理由；若無相關候選，僅寫「無明確對應」。
【62443 對應】最相關的 IEC 62443-4-2 條號與它要求元件具備什麼能力；若無相關候選，僅寫「無明確對應」。
【CRA 關聯】最相關的條文編號與它要求了什麼；若無相關候選，僅寫「無明確對應」。
【修補建議】具體可執行的動作，優先採用參考資料中列出的緩解措施與 62443 要求。
【不確定性】這份建議依據不足的地方，以及人工複核時該優先查證什麼。

Do not add any section beyond these six. Do not skip a section even when the answer is "無明確對應"."""

# 從 LLM 回覆裡抓出「看起來像來源編號」的字串，用來跟白名單比對。
# 每一種格式都對應知識庫裡實際存在的編號樣式（見 cwe_entries.json 的
# cwe_id、cra_articles.json 與 iec_4_*.json 的 article_no）。
#
# 新增知識庫時這份清單一定要跟著補，否則那個來源的編號完全不會被
# 掃到——結果不是「誤報」而是「漏報」：模型編出一條不存在的
# CR 3.9，verify_citations() 根本不認得這個樣式，會安靜地當作沒有
# 引用而放行。漏報比誤報危險得多，因為報告上不會有任何提示。
CITATION_PATTERNS = [
    re.compile(r"CWE-\d+", re.IGNORECASE),
    re.compile(r"Article\s+\d+", re.IGNORECASE),
    re.compile(
        r"Annex\s+[IVX]+(?:\s+(?:Part|Class)\s+[IVX]+)?"
        r"(?:\s*(?:\([a-zA-Z0-9]+\)|\d+(?:\.\d+)*\.?))*",
        re.IGNORECASE,
    ),
    # IEC 62443-4-2 的技術要求：CR 1.7、EDR 3.12、NDR 5.2，可能帶
    # requirement enhancement 後綴 RE(1)。標準名稱前綴可有可無——
    # system instruction 要求一律寫全，但模型不見得每次都照做，
    # 兩種寫法都要抓得到（比對邏輯見 _matches()）。
    re.compile(
        r"(?:IEC\s*62443-\d-\d\s+)?(?:CR|EDR|HDR|NDR|SAR)\s*\d+\.\d+"
        r"(?:\s*RE\s*\(\d+\))?",
        re.IGNORECASE,
    ),
    # IEC 62443-4-1 的流程要求：SM-6、SVV-4、SUM-3。
    # 4-1 的 SI-（Secure implementation）跟 4-2 的 FR 3 System integrity
    # 不會撞號，後者的編號是 CR 3.x，不用 SI- 開頭。
    re.compile(
        r"(?:IEC\s*62443-\d-\d\s+)?(?:SM|SR|SD|SVV|SUM|SG|DM|SI)-\d+",
        re.IGNORECASE,
    ),
]

# 標準名稱前綴，比對前用來把 "IEC 62443-4-2 CR 1.7" 正規化成 "cr 1.7"
STANDARD_PREFIX_PATTERN = re.compile(r"^iec\s*62443-\d-\d\s+")


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
        from anthropic import Anthropic  # noqa: F401
    except ImportError:
        return False
    return True


# 每次呼叫的輸出上限（token 數，不是字元數）。這裡所有 system instruction
# 要求的輸出都很短（一句話的修補建議、一段最多 450 字的研判摘要），
# 1024 token 遠遠夠用，設上限主要是防止模型異常（例如沒有照指示停下來）
# 時一次呼叫的花費跟等待時間失控，不是預期會被用到的天花板。
MAX_OUTPUT_TOKENS = 1024


def ask_llm(system_instruction: str, prompt: str) -> str | None:
    """
    送一次請求給 Claude，回傳純文字回覆；任何失敗回傳 None。

    沒有對應 Gemini 那邊 store=False 的參數：Anthropic 的 Messages API
    本來就是無狀態的單次請求（不像某些平台的 Assistants/Threads API
    會把對話存在伺服器端），這裡本來就不會有任何一次呼叫的內容被留存
    在 Anthropic 那一側的對話紀錄裡，不需要額外關掉什麼。
    """
    api_key = os.environ.get(API_KEY_ENV)
    if not api_key:
        print(f"[llm_advisor] 未設定環境變數 {API_KEY_ENV}，略過 LLM 研判。")
        return None

    try:
        from anthropic import Anthropic
    except ImportError:
        print("[llm_advisor] 未安裝 anthropic，略過 LLM 研判。"
              "安裝方式：pip install anthropic")
        return None

    try:
        client = Anthropic(api_key=api_key)
        message = client.messages.create(
            model=MODEL_NAME,
            max_tokens=MAX_OUTPUT_TOKENS,
            system=system_instruction,
            messages=[{"role": "user", "content": prompt}],
        )
        return "".join(block.text for block in message.content if block.type == "text")
    except Exception as e:
        # 網路不通、金鑰無效、額度用完、模型名稱不存在——這些都不該
        # 讓整份報告產不出來，掃描結果本身仍然是有價值的產出。
        print(f"[llm_advisor] Claude 呼叫失敗，略過 LLM 研判（{e}）")
        return None


# CRA 條文＋finding 一起讀，產出一句話的修補建議，用的快取。
#
# 已修正的設計問題：這裡原本（translate_cra_article）只翻譯條文本身，
# 快取 key 只用 article_no——結果同一條文不管配上哪筆 finding，顯示的都是
# 同一段「產品應具備適當的存取控制機制」這種法規原文的抽象paraphrase，
# 使用者看了還是不知道「所以我該做什麼」。條文內容本來就寫給所有產品類型
# 通用，不可能天生具體；要「一眼看出怎麼修補」，答案必須是「這條要求
# 用在這筆 finding 上，具體該做的事」，離不開 finding 本身的資訊
# （service、port、alert 內容…），不能只餵條文全文。
#
# 因此快取 key 改成 article_no + finding 的「特徵」（category/source/title，
# 不是 finding_id——finding_id 是每次掃描隨機產生的 uuid，同一台裝置在不同
# 次掃描間不會相同，但同一種弱點的 category/source/title 通常是穩定的字串，
# 例如同一個 "tcp/6379 redis"）。這樣同一種弱點跨掃描仍然吃得到快取，
# 不用每次都重新呼叫一次 Claude，但不同 finding 不會再共用同一句不相干的
# 修補建議。
CRA_REMEDIATION_CACHE_PATH = (
    Path(__file__).resolve().parent.parent / "cra_kb" / "cra_data" / "cra_remediation_cache.json"
)

CRA_REMEDIATION_SYSTEM_INSTRUCTION = """You are helping a product security engineer understand, for ONE specific scan finding, what a cited article of the EU Cyber Resilience Act (Regulation (EU) 2024/2847) means they should actually do about it.

You are given: (1) one scan finding (title, category, and technical detail), and (2) the official English text of a CRA article that semantic search matched to this finding. The article text is general — it applies to all kinds of products, not just this one — so do not just paraphrase it in the abstract.

Rules:
1. Write EXACTLY ONE sentence in Traditional Chinese (zh-TW), at most 80 characters, telling the reader concretely how to remediate or address THIS finding, grounded in what the cited article requires.
2. Do not restate the finding's title verbatim, and do not quote the legal text. Translate the requirement into a concrete action for this specific finding — for example, instead of "產品應確保機密性", write "此服務目前以明碼傳輸帳密，應停用明碼協定並改用加密連線（如 SSH/TLS）"。
3. Semantic search is not guaranteed to be accurate — if the article's connection to this finding looks weak or indirect, phrase the sentence as something to verify rather than a certain conclusion (e.g. "建議確認...是否..." 而不是斷言).
4. Output the sentence only. No markdown, no bullet points, no headings, no leading label, no trailing explanation."""

# 條文全文送進 prompt 前的字元上限，理由跟 rag_context.py 的
# MAX_CHARS_PER_ENTRY 一致：CRA 少數條文（如 Article 13）有好幾千字，
# 而且真正決定「這條在講什麼」的通常是開頭幾段。
CRA_REMEDIATION_INPUT_MAX_CHARS = 4000


def _finding_signature(finding: dict) -> str:
    """穩定的 finding 識別字串，理由見上面 CRA_REMEDIATION_CACHE_PATH 的說明。"""
    return f"{finding.get('category', '')}|{finding.get('source', '')}|{finding.get('title', '')}"


def _load_json_cache(path: Path) -> dict:
    if not path.is_file():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        print(f"[llm_advisor] 警告：修補建議快取讀取失敗，視為空快取（{path.name}：{e}）")
        return {}


def _save_json_cache(path: Path, cache: dict) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(cache, ensure_ascii=False, indent=2), encoding="utf-8")
    except OSError as e:
        # 寫檔失敗（例如唯讀檔案系統）不該讓這次已經拿到的結果作廢，
        # 只是下次沒辦法吃到快取、要重新呼叫一次 Claude。
        print(f"[llm_advisor] 警告：修補建議快取寫入失敗，本次結果不會保留（{path.name}：{e}）")


def _load_cra_remediation_cache() -> dict:
    return _load_json_cache(CRA_REMEDIATION_CACHE_PATH)


def _save_cra_remediation_cache(cache: dict) -> None:
    _save_json_cache(CRA_REMEDIATION_CACHE_PATH, cache)


def _derive_kb_remediation(
    finding: dict,
    ref_id: str,
    load_cache_fn,
    save_cache_fn,
    system_instruction: str,
    reference_block: str,
) -> str | None:
    """
    共用的「finding + 單一知識庫候選」→ 一句話修補建議產生邏輯，CWE/IEC/CRA
    三個 derive_*_remediation() 都是這支函式套不同的 system prompt 跟快取檔案。
    每個知識庫獨立一份快取檔（cache_key 只含 ref_id + finding 特徵），不會
    因為共用這支函式就互相污染彼此的快取內容。
    """
    if not ref_id:
        return None

    cache = load_cache_fn()
    cache_key = f"{ref_id}::{_finding_signature(finding)}"
    if cache_key in cache:
        return cache[cache_key]

    detail = finding.get("detail") or {}
    detail_lines = "\n".join(
        f"- {k}: {v}" for k, v in detail.items() if v not in (None, "", [], {})
    )

    prompt = f"""# Scan Finding

- Title: {finding.get('title', '')}
- Category: {finding.get('category', '')} (source tool: {finding.get('source', '')})
- Target: {finding.get('target', '')}
{detail_lines}

{reference_block}
"""
    answer = ask_llm(system_instruction, prompt)
    if answer is None:
        return None

    result = answer.strip()
    cache[cache_key] = result
    save_cache_fn(cache)
    return result


def derive_cra_remediation(finding: dict, article_no: str, title: str, text: str) -> str | None:
    """
    把「一筆 finding」+「語意檢索配對到的 CRA 條文全文」一起交給 Claude，
    產出一句具體可執行的繁體中文修補建議——取代直接顯示條文 title
    （常常只是像 "Reporting obligations" 這種抽象標題）或整段法規原文的
    paraphrase（讀完還是不知道「所以我該做什麼」）。

    回傳 None 代表這條路徑不可用（沒金鑰/沒套件/呼叫失敗），呼叫端應該
    退回顯示條文原文（text）或 title，不能讓整筆候選因此消失——跟
    llm_advisor 其他函式一致的降級原則。
    """
    truncated_article = (text or "").strip()
    if len(truncated_article) > CRA_REMEDIATION_INPUT_MAX_CHARS:
        truncated_article = truncated_article[:CRA_REMEDIATION_INPUT_MAX_CHARS].rstrip() + "……"

    reference_block = f"""# Cited CRA Article (matched by semantic search, may be a loose match)

{article_no} — {title}

{truncated_article}
"""
    return _derive_kb_remediation(
        finding, article_no,
        _load_cra_remediation_cache, _save_cra_remediation_cache,
        CRA_REMEDIATION_SYSTEM_INSTRUCTION, reference_block,
    )


# CWE 候選＋finding 一起讀，產出一句話修補建議，跟 derive_cra_remediation
# 同一套設計：CWE 的 description 也是描述一整類弱點的通用文字（例如
# CWE-319「明碼傳輸敏感資訊」），不是針對這筆 finding 寫的，直接顯示
# description 一樣看不出「所以我該做什麼」。
CWE_REMEDIATION_CACHE_PATH = (
    Path(__file__).resolve().parent.parent / "cwe_kb" / "cwe_data" / "cwe_remediation_cache.json"
)

CWE_REMEDIATION_SYSTEM_INSTRUCTION = """You are helping a product security engineer understand, for ONE specific scan finding, what a cited CWE (Common Weakness Enumeration) entry means they should actually do about it.

You are given: (1) one scan finding (title, category, and technical detail), and (2) a CWE entry (ID, name, and description) that semantic search matched to this finding. The CWE description describes a general class of weakness — it applies to many kinds of products, not just this one — so do not just paraphrase it in the abstract.

Rules:
1. Write EXACTLY ONE sentence in Traditional Chinese (zh-TW), at most 80 characters, telling the reader concretely how to remediate or address THIS finding, grounded in what the cited CWE describes.
2. Do not restate the finding's title verbatim, and do not quote the CWE description. Translate the weakness into a concrete action for this specific finding.
3. Semantic search is not guaranteed to be accurate — if the CWE's connection to this finding looks weak or indirect, phrase the sentence as something to verify rather than a certain conclusion.
4. Output the sentence only. No markdown, no bullet points, no headings, no leading label, no trailing explanation."""


def _load_cwe_remediation_cache() -> dict:
    return _load_json_cache(CWE_REMEDIATION_CACHE_PATH)


def _save_cwe_remediation_cache(cache: dict) -> None:
    _save_json_cache(CWE_REMEDIATION_CACHE_PATH, cache)


def derive_cwe_remediation(finding: dict, cwe_id: str, name: str, description: str = "") -> str | None:
    """跟 derive_cra_remediation 同一套邏輯，套用在 CWE 候選上。"""
    reference_block = f"""# Cited CWE Entry (matched by semantic search, may be a loose match)

{cwe_id} — {name}

{description}
"""
    return _derive_kb_remediation(
        finding, cwe_id,
        _load_cwe_remediation_cache, _save_cwe_remediation_cache,
        CWE_REMEDIATION_SYSTEM_INSTRUCTION, reference_block,
    )


# IEC 62443-4-2 候選＋finding 一起讀，產出一句話修補建議，同一套設計。
IEC_REMEDIATION_CACHE_PATH = (
    Path(__file__).resolve().parent.parent / "iec_kb" / "iec_data" / "iec_remediation_cache.json"
)

IEC_REMEDIATION_SYSTEM_INSTRUCTION = """You are helping a product security engineer understand, for ONE specific scan finding, what a cited IEC 62443-4-2 component technical requirement means they should actually do about it.

You are given: (1) one scan finding (title, category, and technical detail), and (2) an IEC 62443-4-2 requirement (clause ID, title, and text) that semantic search matched to this finding. The requirement text is general — it applies to all kinds of components, not just this one — so do not just paraphrase it in the abstract.

Rules:
1. Write EXACTLY ONE sentence in Traditional Chinese (zh-TW), at most 80 characters, telling the reader concretely how to remediate or address THIS finding, grounded in what the cited requirement demands.
2. Do not restate the finding's title verbatim, and do not quote the requirement text. Translate the requirement into a concrete action for this specific finding.
3. Semantic search is not guaranteed to be accurate — if the requirement's connection to this finding looks weak or indirect, phrase the sentence as something to verify rather than a certain conclusion.
4. Output the sentence only. No markdown, no bullet points, no headings, no leading label, no trailing explanation."""


def _load_iec_remediation_cache() -> dict:
    return _load_json_cache(IEC_REMEDIATION_CACHE_PATH)


def _save_iec_remediation_cache(cache: dict) -> None:
    _save_json_cache(IEC_REMEDIATION_CACHE_PATH, cache)


def derive_iec_remediation(finding: dict, article_no: str, title: str, group: str = "", text: str = "") -> str | None:
    """跟 derive_cra_remediation 同一套邏輯，套用在 IEC 62443-4-2 候選上。"""
    truncated_text = (text or "").strip()
    if len(truncated_text) > CRA_REMEDIATION_INPUT_MAX_CHARS:
        truncated_text = truncated_text[:CRA_REMEDIATION_INPUT_MAX_CHARS].rstrip() + "……"

    reference_block = f"""# Cited IEC 62443-4-2 Requirement (matched by semantic search, may be a loose match)

{article_no} — {title}{f"（{group}）" if group else ""}

{truncated_text}
"""
    return _derive_kb_remediation(
        finding, article_no,
        _load_iec_remediation_cache, _save_iec_remediation_cache,
        IEC_REMEDIATION_SYSTEM_INSTRUCTION, reference_block,
    )


PENTEST_OBJECTIVE_SYSTEM_INSTRUCTION = """You are helping plan an AUTHORIZED penetration test of an IoT product, on targets the operator is explicitly permitted to test. You are given one scan finding and, optionally, a security requirement (from IEC 62443-4-2 or the EU CRA) that the finding may relate to.

Your job: produce ONE concrete, testable objective — what a penetration tester, or an autonomous pentest agent, should attempt or verify against the LIVE target in order to determine whether the requirement is actually satisfied.

Rules:
1. Output a test OBJECTIVE, not a restatement of the requirement and not a specific exploit payload or command. Describe what to verify or attempt (for example: confirm whether the Telnet service on port 23 allows access without authentication and whether default or weak credentials are accepted), and leave the exact commands for the pentest tool to decide.
2. Ground the objective in the given finding — its service, port, and target — and, when a requirement is provided, tie the objective to what that requirement demands.
3. Keep it to one or two sentences, written in Traditional Chinese (zh-TW).
4. Do not invent services, ports, or findings that are not given. Do not output multiple objectives, a numbered list, or any headings.
5. Output plain text only — no markdown, no labels, no preamble."""


def derive_test_objective(finding: dict, requirement: dict | None) -> str | None:
    """
    把一筆 finding（可選地加上它對應到的法規要求）交給 Claude，推導出
    一句「該對這個活目標驗證/嘗試什麼」的測試目標，作為
    scanners/claude_pentest_scan.py 的 --objective 注入點。

    為什麼需要這一步：法規知識庫存的是「要求」（元件該具備什麼能力），
    不是「測試步驟」。這個函式做的是 requirement → 可測試目標 的轉換，
    真正的滲透手法（how）交給 pentest agent 自己決定，不在這裡也不在法規裡。

    回傳 None 代表 LLM 這條路徑不可用（沒金鑰/沒套件/呼叫失敗），呼叫端
    應退回用 finding 本身資訊組出的通用目標，不能因此讓整份測試計畫產不出來。
    """
    detail = finding.get("detail") or {}
    detail_lines = "\n".join(
        f"- {k}: {v}" for k, v in detail.items() if v not in (None, "", [], {})
    )
    requirement_block = ""
    if requirement and (requirement.get("id") or requirement.get("text")):
        requirement_block = (
            f"\n\n# Related requirement (the objective should test whether this holds)\n"
            f"- {requirement.get('id', '')}: {requirement.get('text', '')}"
        )

    prompt = f"""# Scan Finding

- Title: {finding.get('title', '')}
- Category: {finding.get('category', '')} (source tool: {finding.get('source', '')})
- Target: {finding.get('target', '')}
{detail_lines}{requirement_block}
"""
    answer = ask_llm(PENTEST_OBJECTIVE_SYSTEM_INSTRUCTION, prompt)
    return answer.strip() if answer else None


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

    return f"""# Scan Finding

- Title: {finding.get('title', '')}
- Category: {finding.get('category', '')} (source tool: {finding.get('source', '')})
- Target: {finding.get('target', '')}
- Severity reported by scanner: {finding.get('severity', '')}
{detail_lines}

# Reference Material (semantic search results, may be irrelevant, cite ONLY the content below)

{context if context.strip() else '(No candidate reference material was retrieved for this finding.)'}
"""


def _covers(longer: str, shorter: str) -> bool:
    """
    longer 是不是以 shorter 為前綴，而且斷在「編號的邊界」上。

    已修正的 bug：原本只用 str.startswith() 判斷前綴涵蓋關係，但編號是
    數字結尾的，"article 13".startswith("article 1") 會是 True——白名單
    裡有 Article 13 時，模型編造的 Article 1 會被靜默放行，正好是引用
    查核最該擋下來的那種錯誤。加進 IEC 之後這個坑更深：CR 1.1 是
    CR 1.11 到 CR 1.14 的前綴，58 條 CR 裡有一大票會互相誤放行。

    修法是要求前綴後面接的不能是英數字（也就是必須斷在空白、括號、
    句點這類分隔符上）。"Annex I Part I" 涵蓋 "Annex I Part I (2)(a)"
    仍然成立（下一個字元是空白），但 "Article 1" 不再涵蓋 "Article 13"。
    """
    if longer == shorter:
        return True
    if not longer.startswith(shorter) or not shorter:
        return False
    return not longer[len(shorter)].isalnum()


def _matches(citation: str, allowed_id: str) -> bool:
    """
    單一引用跟單一白名單編號是否算對得上。

    雙向都試，是因為兩種方向都是合理的引用方式：LLM 只寫上層編號
    （"Annex I Part I"，白名單是更細的 "Annex I Part I (2)(a)"），或是
    寫得比白名單更細。兩種都不算幻覺，它引用的範圍確實涵蓋我們給的內容。

    另外把標準名稱前綴剝掉再比一次：system instruction 要求 IEC 條號
    一律寫成 "IEC 62443-4-2 CR 1.7"，但模型常常只寫 "CR 1.7"。這種
    省略不是幻覺，不該被標成引用錯誤。剝掉前綴不會放寬檢查強度——
    編造的 "CR 3.9" 剝完還是對不上任何一條白名單編號。
    """
    for a, c in ((allowed_id, citation),
                 (STANDARD_PREFIX_PATTERN.sub("", allowed_id),
                  STANDARD_PREFIX_PATTERN.sub("", citation))):
        if _covers(c, a) or _covers(a, c):
            return True
    return False


def verify_citations(answer: str, allowed_ids: list[str]) -> list[str]:
    """
    檢查回覆裡出現的來源編號，有哪些不在這次餵進 context 的白名單裡。
    比對規則見 _matches()／_covers()。
    """
    allowed = [_normalize(i) for i in allowed_ids if i]

    found: list[str] = []
    for pattern in CITATION_PATTERNS:
        found.extend(m.group(0) for m in pattern.finditer(answer or ""))

    unsupported: list[str] = []
    for citation in found:
        norm = _normalize(citation)
        if any(_matches(norm, a) for a in allowed):
            continue
        if citation not in unsupported:
            unsupported.append(citation)

    return unsupported


def advise_finding(finding: dict, suggestions: dict | None) -> dict | None:
    """
    對單一 finding 產生 LLM 研判建議。

    suggestions 就是 analysis.py 放進 rag_suggestions 的那份
    {"cwe": [...], "cra": [...], "iec": [...]}——刻意吃已經檢索好的結果，
    而不是自己再查一次，確保「報告裡列出的候選」跟「LLM 實際讀到的候選」
    是同一份，人工複核時看到的依據才跟 LLM 當時看到的一致。

    回傳 None 代表這條路徑不可用（沒金鑰/沒套件/呼叫失敗），
    呼叫端照常繼續，不要當成錯誤。
    """
    from core.rag_context import build_context, collect_source_ids

    cwe_entries = (suggestions or {}).get("cwe") or []
    cra_entries = (suggestions or {}).get("cra") or []
    iec_entries = (suggestions or {}).get("iec") or []

    # 三邊都沒有候選時不送請求：沒有參考資料的情況下，LLM 只能靠內建
    # 知識回答，那正是這整套設計要避免的東西，而且還要花一次 API 呼叫。
    if not cwe_entries and not cra_entries and not iec_entries:
        return None

    context = build_context(cwe_entries, cra_entries, iec_entries)
    answer = ask_llm(SYSTEM_INSTRUCTION, build_prompt(finding, context))
    if answer is None:
        return None

    allowed_ids = collect_source_ids(cwe_entries, cra_entries, iec_entries)
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
        print(f"LLM 尚未就緒：請確認已 pip install anthropic 並設定 {API_KEY_ENV}")
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
