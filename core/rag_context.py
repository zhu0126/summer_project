#!/usr/bin/env python3
"""
RAG 的「context 組裝層」：把 retrieve_cwe_hybrid() / retrieve_iec_hybrid() /
retrieve_cra_hybrid() 回傳的候選清單，整理成一段可以直接餵給 LLM 的
參考資料字串。

為什麼要獨立出這一層：檢索層（cwe_kb/cra_kb）回傳的是結構化 dict，
報告樣板（report.md.j2）消費的也是結構化 dict，兩邊都不需要「一整段
文字」。但 LLM 需要——它讀的是純文字，而且需要每一段都清楚標示來源
編號，才有辦法在回答時引用「Article 13」而不是含糊地說「法規要求」。
把這段格式化邏輯抽出來的好處是它完全沒有外部依賴（不碰 Qdrant、
不碰 LLM API），可以離線單獨測試，不用等整條 pipeline 都跑得起來。

跟原始參考實作（ChromaDB 版 retrieve_context）的差異：
1. 不自己查資料庫。原版把「查詢」跟「格式化」綁在同一個函式裡，
   這裡只吃已經檢索好的結果——專案的檢索是 hybrid（dense + BM25 用
   RRF 合併），查詢邏輯已經在 retrieve_*.py 裡，不該再複製一份。
2. 不依賴 metadata 裡的 type/subtitle 欄位。專案的 cra_articles.json
   只存 article_no/title/text，而 article_no 本身已經帶了 "Article 13"
   或 "Annex I Part I (2)(a)" 這種前綴，type 直接從前綴判斷就好，
   不需要為了這個用途回頭改 fetch_cra.py 的輸出格式再重建整個索引。
3. 加上長度上限。CRA 有些條文（例如 Article 13 製造商義務）單條就
   好幾千字，五筆候選全文塞進 prompt 會吃掉大量 token，而且真正相關
   的通常是條文開頭那幾段。這裡對「每一筆」跟「總量」都設上限，
   截斷處明確標記，讓人看報告時知道 LLM 當時只讀到部分內容。
"""

# 每一筆條文/CWE 描述進 prompt 前的字元上限。截斷是有代價的（可能
# 剛好切掉關鍵的但書），所以截斷處會留下明確標記，而不是靜默切斷。
MAX_CHARS_PER_ENTRY = 1500

# 整段 context 的字元上限。超過就停止加入後面的候選——候選本來就是
# 依相關性排序的，排在後面的被捨棄，比把整個 prompt 撐爆合理。
MAX_CONTEXT_CHARS = 12000

TRUNCATION_MARK = "……（本筆內容過長已截斷，完整條文請見原始法規）"

ENTRY_SEPARATOR = "\n\n---\n\n"


def entry_kind(article_no: str) -> str:
    """
    從 article_no 前綴判斷這筆的種類。
    fetch_cra.py 產生的編號一律是 "Article N" 或 "Annex <羅馬數字> ..."，
    fetch_iec.py 產生的一律是 "IEC 62443-4-x <ID>"，都不需要額外的
    metadata 欄位就能分辨。
    """
    prefix = article_no.strip().lower()
    if prefix.startswith("iec "):
        return "standard"
    return "annex" if prefix.startswith("annex") else "article"


def _truncate(text: str) -> str:
    text = (text or "").strip()
    if len(text) <= MAX_CHARS_PER_ENTRY:
        return text
    return text[:MAX_CHARS_PER_ENTRY].rstrip() + TRUNCATION_MARK


def format_clause_entry(entry: dict, prefix: str = "") -> str:
    """
    單筆條文/要求候選 → "[來源標頭]\\n內文"。CRA 跟 IEC 62443 共用這一支。

    標頭一定要放 article_no，這是 LLM 之後引用時唯一該寫出來的識別字串，
    也是下游 verify_citations() 用來檢查「LLM 引用的條號有沒有真的出現在
    我們給的資料裡」的依據。

    prefix 是給 CRA 用的（它的 article_no 是裸的 "Article 13"，需要補上
    來源名稱才知道是哪部法規）；IEC 的 article_no 本身已經含
    "IEC 62443-4-2" 前綴，不需要再補，否則標頭會變成重複的
    "[IEC 62443-4-2 IEC 62443-4-2 CR 1.7]"。

    group 只有 IEC 有（"FR 4 – Data confidentiality" 這種上層分類），
    帶進標頭是因為它說明了這條要求屬於哪個安全面向，對 LLM 判斷「這條
    跟這筆掃描結果是不是同一件事」很有幫助，成本只有幾個 token。
    """
    article_no = entry.get("article_no", "?")
    title = (entry.get("title") or "").strip()
    group = (entry.get("group") or "").strip()

    header = f"{prefix}{article_no}"
    if title and title != article_no:
        header += f" — {title}"
    if group:
        header += f"（{group}）"

    return f"[{header}]\n{_truncate(entry.get('text', ''))}"


def format_cra_entry(entry: dict) -> str:
    """單筆 CRA 候選。CRA 的 article_no 是裸條號，標頭要補上來源名稱。"""
    return format_clause_entry(entry, prefix="CRA ")


def format_iec_entry(entry: dict) -> str:
    """單筆 IEC 62443 候選。article_no 已含標準名稱，不再加前綴。"""
    return format_clause_entry(entry)


def format_cwe_entry(entry: dict) -> str:
    """
    單筆 CWE 候選 → 標頭 + 描述 + 官方緩解措施。

    mitigations 一併帶進去，是因為 CWE 條目裡的緩解措施是「經過整理的
    通用做法」，比 LLM 自己憑印象生出來的建議可靠——把它放進 context，
    LLM 的角色就從「自己想辦法」變成「挑出適用的那幾條並貼合這次的
    掃描結果」，幻覺空間小很多。
    """
    cwe_id = entry.get("cwe_id", "?")
    name = (entry.get("name") or "").strip()

    header = cwe_id
    if name:
        header += f" — {name}"

    parts = [f"[{header}]", _truncate(entry.get("description", ""))]

    mitigations = entry.get("mitigations") or []
    if isinstance(mitigations, str):
        mitigations = [mitigations]
    if mitigations:
        parts.append("官方建議緩解措施：")
        parts.extend(f"- {_truncate(m)}" for m in mitigations)

    return "\n".join(p for p in parts if p)


def collect_source_ids(
    cwe_entries: list[dict] | None,
    cra_entries: list[dict] | None,
    iec_entries: list[dict] | None = None,
) -> list[str]:
    """
    回傳這次餵進 context 的所有來源識別字串（CWE-79 / Article 13 /
    Annex I Part I (2)(a) / IEC 62443-4-2 CR 1.7 ...）。這份清單是
    「LLM 被允許引用的範圍」，verify_citations() 拿它當白名單做事後檢查。

    新增知識庫時，這裡漏掉是最容易犯又最難察覺的錯：白名單少了某個
    來源，LLM 引用它會被誤判成幻覺，報告上會出現「引用查核未通過」的
    紅字警告，但那條引用其實完全正確。
    """
    ids = [e.get("cwe_id", "") for e in (cwe_entries or [])]
    ids += [e.get("article_no", "") for e in (cra_entries or [])]
    ids += [e.get("article_no", "") for e in (iec_entries or [])]
    return [i for i in ids if i]


def build_context(
    cwe_entries: list[dict] | None = None,
    cra_entries: list[dict] | None = None,
    iec_entries: list[dict] | None = None,
) -> str:
    """
    把 CWE + IEC 62443 + CRA 三份候選組成單一段參考資料文字。

    順序刻意是「CWE → IEC → CRA」，對應人工複核時的思考順序：
    CWE 說明這是什麼弱點（問題是什麼），62443-4-2 說明元件層級該具備
    什麼能力才算處理掉它（技術上要做什麼），CRA 說明這件事在歐盟為什麼
    是義務（法律上為什麼非做不可）。由技術到法規，也讓 LLM 產出的段落
    順序（研判 → 修補 → 條文對應）自然一致。

    總長度超過 MAX_CONTEXT_CHARS 時，停止加入剩下的候選並在結尾標記，
    不做靜默捨棄——「有東西沒被讀進去」這件事必須看得見。
    """
    blocks: list[str] = []
    total = 0
    dropped = 0

    formatted = [format_cwe_entry(e) for e in (cwe_entries or [])]
    formatted += [format_iec_entry(e) for e in (iec_entries or [])]
    formatted += [format_cra_entry(e) for e in (cra_entries or [])]

    for block in formatted:
        if total + len(block) > MAX_CONTEXT_CHARS and blocks:
            dropped += 1
            continue
        blocks.append(block)
        total += len(block) + len(ENTRY_SEPARATOR)

    if dropped:
        blocks.append(f"（另有 {dropped} 筆相關性較低的候選因長度限制未列入）")

    return ENTRY_SEPARATOR.join(blocks)


if __name__ == "__main__":
    sample_cwe = [{
        "cwe_id": "CWE-319",
        "name": "Cleartext Transmission of Sensitive Information",
        "description": "The product transmits sensitive data in cleartext.",
        "mitigations": ["Encrypt the data with a reliable encryption scheme."],
    }]
    sample_cra = [{
        "article_no": "Annex I Part I (2)(a)",
        "title": "Part I Essential cybersecurity requirements",
        "text": "protect the confidentiality of stored, transmitted or otherwise processed data...",
    }]
    sample_iec = [{
        "article_no": "IEC 62443-4-2 CR 4.1",
        "title": "Information confidentiality",
        "group": "FR 4 – Data confidentiality",
        "text": "Requirement:\nComponents shall provide the capability to protect the "
                "confidentiality of information at rest...",
    }]
    print(build_context(sample_cwe, sample_cra, sample_iec))
    print()
    print("來源白名單：", collect_source_ids(sample_cwe, sample_cra, sample_iec))
