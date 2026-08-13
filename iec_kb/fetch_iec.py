#!/usr/bin/env python3
"""
從授權取得的 IEC 62443-4-1 / 4-2 PDF 解析出結構化的要求條目，輸出 json，
後面接 build_iec_index.py。跟 cwe_kb/fetch_cwe.py、cra_kb/fetch_cra.py
是同一套模式（下載/讀取 → 解析成統一結構 → 存 json），但來源這一步
有一個關鍵差異：

**CRA 能自動下載，62443 不行。** CRA 是 EUR-Lex 公開全文，fetch_cra.py
可以直接抓；IEC 62443 是付費標準，沒有合法的公開全文來源，所以這支
腳本不做任何下載，一律要求使用者用 --pdf 指定自己授權取得的檔案。

因此有兩個必須遵守的處理原則：

1. **輸出不進版控**：iec_data/*.json 內含標準原文，已經加進 .gitignore。
   跟 .env 同樣的理由——它不該跟著程式碼散布出去。
2. **主動剝除授權浮水印**：IEC 的個人授權 PDF 會在每一頁烙上被授權人
   的姓名、公司、訂單編號。這是個資，不該進到知識庫、更不該隨著 RAG
   context 被送到外部 LLM API。兩部標準的浮水印形式還不一樣：
   - 4-2 是頁尾三行水平文字（Customer/Order No./licence agreement）
   - 4-1 是側邊欄「旋轉 90 度」的文字，pdfplumber 抽出來會變成一堆
     反向的單字碎片（"desnecil"、"ypoc"…）。這種沒辦法用字串比對濾，
     改用 pdfplumber 的字元屬性 upright=False 直接把非水平文字整批
     排除，比維護一份雜訊字串清單可靠。

解析依據（兩部標準的排版都非常規則，實際核對過 PDF 內文）：

    4-2：   5.9 CR 1.7 – Strength of password-based authentication
              5.9.1 Requirement
              5.9.2 Rationale and supplemental guidance
              5.9.3 Requirement enhancements
              5.9.4 Security levels

    4-1：   5.8 SM-6: File integrity
              5.8.1 Requirement
              5.8.2 Rationale and supplemental guidance

差別只在編號跟標題之間的分隔符（4-2 用破折號、4-1 用冒號），以及 4-2
多了 enhancements/security levels 兩個小節，所以用同一套解析器、兩組
regex 就能涵蓋。

已知的排版例外（已處理，不是 bug）：4-1 的 SM-1 小節編號是標準本身
編錯的——rationale 被編成 "5.3" 而不是 "5.2.2"。這裡界定條目邊界只看
「帶 ID 的標題」（SM-n:/CR n.m –），不看小節編號連不連續，所以這個
錯號會自然被歸進 SM-1 的內文，不需要特例。
"""
import argparse
import json
import re
import sys
from pathlib import Path

try:
    import pdfplumber
except ImportError:
    sys.exit("缺少 pdfplumber，請先執行：pip install pdfplumber")

OUTPUT_DIR = Path(__file__).resolve().parent / "iec_data"

# 每部標準的解析設定。新增 62443 其他部（例如 3-3）時，原則上只要在
# 這裡多一組設定，不用改解析邏輯本身。
PART_SPECS = {
    "4-2": {
        "standard": "IEC 62443-4-2",
        "output": "iec_4_2.json",
        # 5.9 CR 1.7 – Strength of password-based authentication
        # 13.4 EDR 3.2 – Protection from malicious code
        "clause": re.compile(
            r"^(\d+(?:\.\d+)+)\s+((?:CR|EDR|HDR|NDR|SAR)\s+\d+\.\d+)\s*[–—-]\s*(.+)$"
        ),
        # 5 FR 1 – Identification and authentication control
        # 13 Embedded device requirements
        "group": re.compile(
            r"^\d+\s+(FR\s+\d+\s*[–—-]\s*.+"
            r"|(?:Software application|Embedded device|Host device|Network device)"
            r"\s+requirements)$"
        ),
        "expected_count": 88,  # 58 CR + 2 SAR + 8 EDR + 8 HDR + 12 NDR
    },
    "4-1": {
        "standard": "IEC 62443-4-1",
        "output": "iec_4_1.json",
        # 5.8 SM-6: File integrity
        "clause": re.compile(
            r"^(\d+(?:\.\d+)+)\s+((?:SM|SR|SD|SI|SVV|DM|SUM|SG)-\d+)\s*[:：]\s*(.+)$"
        ),
        # 5 Practice 1 – Security management
        "group": re.compile(r"^\d+\s+(Practice\s+\d+\s*[–—-]\s*.+)$"),
        "expected_count": 47,  # SM 13 + SR 5 + SD 4 + SI 2 + SVV 5 + DM 6 + SUM 5 + SG 7
    },
}

# 條目內的小節標題。四種名稱是兩部標準共用的固定用語，比對時放寬大小寫，
# 但要求整行只有「編號 + 名稱」，避免內文裡提到 "Requirement" 被誤判成標題。
SUBSECTION_PATTERN = re.compile(
    r"^\d+(?:\.\d+)+\s+"
    r"(Requirement enhancements|Requirements enhancements"
    r"|Rationale and supplemental guidance"
    r"|Security levels|Requirement)\s*$",
    re.IGNORECASE,
)

SUBSECTION_FIELD = {
    "requirement": "requirement",
    "rationale and supplemental guidance": "rationale",
    "requirement enhancements": "enhancements",
    "requirements enhancements": "enhancements",
    "security levels": "security_levels",
}

# 目錄行：尾端是點狀引導線 + 頁碼。解析目錄會產生一整批只有標題、
# 沒有內文的幽靈條目，而且會先於正文出現、把正文的內容覆蓋掉，
# 所以在進入解析前就整行濾掉——比起用頁碼區間跳過目錄，這個做法
# 不會因為不同版本的頁數不同而失效。
TOC_LINE_PATTERN = re.compile(r"\.{4,}\s*\d+\s*$")

# 正文起點。光靠 TOC_LINE_PATTERN 濾目錄是不夠的：標題太長而在目錄裡
# 折成兩行時，第一行不帶點狀引導線（引導線在第二行），會逃過過濾、被
# 當成真正的條目標題，然後把後面的 FOREWORD/INTRODUCTION 整段吸進去
# 當內文——4-1 的 SUM-3 就是這樣被解析成兩筆的。
#
# 改成直接從正文起點開始收，前面的封面、目錄、前言一律不看。兩部標準
# 的正文都是從 "1 Scope" 這個獨立標題開始（目錄裡的那一行帶引導線，
# 已經先被濾掉，所以這個樣式在整份文件裡只會命中一次，實測確認過）。
BODY_START_PATTERN = re.compile(r"^1\s+Scope\s*$")

# 頁首：奇偶頁的排版左右相反，兩種都要認得
#   IEC 62443-4-2:2019  IEC 2019 – 3 –
#   – 32 – IEC 62443-4-2:2019  IEC 2019
PAGE_HEADER_PATTERN = re.compile(
    r"^(–\s*\d+\s*–\s*)?IEC\s+62443-\d-\d:\d{4}.*?(–\s*\d+\s*–)?$"
)

# 頁尾的授權浮水印（含被授權人姓名/公司/訂單編號的個資，必須剝除）
LICENCE_NOISE_PATTERNS = [
    re.compile(r"^Customer:\s", re.IGNORECASE),
    re.compile(r"^Order No\.:", re.IGNORECASE),
    re.compile(r"licence agreement", re.IGNORECASE),
    re.compile(r"copyright of IEC", re.IGNORECASE),
    re.compile(r"^\s*$"),
]

# 雙語版 PDF 的語言分界。IEC 有些部是英法雙語合訂（檔名尾碼 b =
# bilingual，例如 iec62443-4-2{ed1.0}b.pdf；純英文版是 en），法文半部
# 的條目編號跟英文完全相同（CR 1.1 / CR 1.2 …），不切掉的話每一條都會
# 被解析兩次，而且因為 article_no 相同，下游 RRF 合併時會有一份被靜默
# 覆蓋——實際跑出來是 88 條變 179 條、全數重複。
#
# 用法文版目錄/前言的標題當切點，而不是用頁碼：頁數會隨版本改變，
# 這兩個標題是 IEC 雙語版的固定用語，比較不會失效。純英文版的 PDF
# 掃不到這兩個字，整份都會保留，所以這段邏輯對單語版是無害的。
LANGUAGE_BOUNDARY_PATTERN = re.compile(r"^(SOMMAIRE|AVANT-PROPOS)$")

# 內文裡「自成一行、不該被接到上一行去」的區塊起始樣式：清單項目、
# 條列編號、NOTE/EXAMPLE 標註。用來判斷換行是「段落內的折行」還是
# 「新的一個區塊」——PDF 抽出來的文字沒有段落資訊，只能靠這些樣式推。
BLOCK_START_PATTERN = re.compile(
    r"^(\(\d+\)|[a-z]\)|\d+\)|[•●▪◦‣]|NOTE\b|EXAMPLE\b|SL-C\b)"
)


def extract_lines(pdf_path: Path) -> list[str]:
    """
    把整份 PDF 抽成一串已經清理過的文字行。

    upright 過濾是關鍵的一步：4-1 的授權浮水印是旋轉 90 度的側邊欄文字，
    pdfplumber 會把它跟正文混在同一個 extract_text() 結果裡（變成一堆
    反向單字），用字串比對濾不乾淨。改成在字元層級先把非水平文字整批
    排除，正文完全不受影響。

    收錄範圍是「正文起點到法文版起點之間」：前面的封面/目錄/前言用
    BODY_START_PATTERN 切掉，後面的法文半部用 LANGUAGE_BOUNDARY_PATTERN
    切掉（單語版 PDF 不受後者影響）。
    """
    lines: list[str] = []
    with pdfplumber.open(str(pdf_path)) as pdf:
        for page in pdf.pages:
            upright_only = page.filter(lambda obj: obj.get("upright", True) is not False)
            text = upright_only.extract_text() or ""
            for raw in text.split("\n"):
                line = raw.strip()
                if not line:
                    continue
                if LANGUAGE_BOUNDARY_PATTERN.match(line):
                    print(f"[fetch_iec] 偵測到雙語版的法文半部起點（{line}），"
                          f"從這裡開始的內容不解析。")
                    return _drop_front_matter(lines)
                if PAGE_HEADER_PATTERN.match(line):
                    continue
                if TOC_LINE_PATTERN.search(line):
                    continue
                if any(p.search(line) for p in LICENCE_NOISE_PATTERNS):
                    continue
                lines.append(line)
    return _drop_front_matter(lines)


def _drop_front_matter(lines: list[str]) -> list[str]:
    """把正文起點之前的封面/目錄/前言丟掉，見 BODY_START_PATTERN 的說明。"""
    for i, line in enumerate(lines):
        if BODY_START_PATTERN.match(line):
            return lines[i:]
    print("[fetch_iec] 警告：找不到正文起點（\"1 Scope\"），將解析整份文件，"
          "目錄可能會被誤判成條目，建議人工核對輸出。")
    return lines


def dewrap(lines: list[str]) -> str:
    """
    把 PDF 的硬折行還原成段落。

    PDF 沒有段落資訊，每一行都是版面上的一行，直接用 "\\n".join 會讓
    BM25 斷詞跟 LLM 閱讀都被折行位置干擾。規則：
    - 上一行以連字號結尾 → 直接接起來不補空白（"password-" + "based"
      要變成 "password-based"；標準裡的 "IEC 62443-3-" + "3" 同理）
    - 這一行是清單/NOTE/EXAMPLE 等區塊開頭 → 另起一行，不接
    - 其餘 → 用空白接到上一行
    """
    out: list[str] = []
    for line in lines:
        if not out or BLOCK_START_PATTERN.match(line):
            out.append(line)
        elif out[-1].endswith("-"):
            out[-1] = out[-1][:-1] + line
        else:
            out[-1] = out[-1] + " " + line
    return "\n".join(out).strip()


def parse_clauses(lines: list[str], spec: dict) -> list[dict]:
    """
    掃過所有文字行，依「帶 ID 的條目標題」切分條目，條目內再依四個
    固定小節名稱分欄位。

    分成 requirement/rationale/enhancements/security_levels 四個欄位
    而不是存成一整塊 text，是為了讓下游能分別使用：embedding 只吃
    requirement + rationale（見 build_embedding_text 的說明），報告要
    印 security levels 時也不用再從整塊文字裡切一次。
    """
    clause_re = spec["clause"]
    group_re = spec["group"]

    entries: list[dict] = []
    current: dict | None = None
    current_group = ""
    field = "requirement"  # 標題之後、第一個小節標題之前的內容歸這裡
    buckets: dict[str, list[str]] = {}

    def flush():
        if current is None:
            return
        for key, value in buckets.items():
            current[key] = dewrap(value)
        entries.append(current)

    for line in lines:
        group_match = group_re.match(line)
        if group_match:
            current_group = re.sub(r"\s+", " ", group_match.group(1)).strip()
            continue

        clause_match = clause_re.match(line)
        if clause_match:
            flush()
            current = {
                "clause_no": clause_match.group(1),
                "clause_id": re.sub(r"\s+", " ", clause_match.group(2)).strip(),
                "title": clause_match.group(3).strip(),
                "group": current_group,
                "requirement": "",
                "rationale": "",
                "enhancements": "",
                "security_levels": "",
            }
            buckets = {}
            field = "requirement"
            continue

        if current is None:
            continue  # 第一個條目之前的內容（封面、前言、術語）不收

        sub_match = SUBSECTION_PATTERN.match(line)
        if sub_match:
            field = SUBSECTION_FIELD[sub_match.group(1).lower()]
            buckets.setdefault(field, [])
            continue

        buckets.setdefault(field, []).append(line)

    flush()
    return entries


def build_embedding_text(entry: dict, standard: str) -> str:
    """
    決定「拿什麼文字去做語意檢索」。

    刻意排除 security_levels：那一欄的內容每一條都長得幾乎一樣
    （"SL-C(IAC,component) 1: CR 1.7" 這種樣板句），對區分條目沒有
    任何資訊量，但因為每筆都有，會嚴重稀釋 BM25 的詞頻統計——常見
    到幾乎每筆都命中的詞，反而會把真正有鑑別度的關鍵字壓下去。

    enhancements 有納入：它描述的是「更高安全等級要額外做什麼」，
    含有具體技術字彙（hardware security module、TPM…），對檢索有用。
    """
    parts = [
        f"{standard} {entry['clause_id']} – {entry['title']}",
        entry.get("group", ""),
        entry.get("requirement", ""),
        entry.get("rationale", ""),
        entry.get("enhancements", ""),
    ]
    return "\n".join(p for p in parts if p)


def to_records(entries: list[dict], spec: dict) -> list[dict]:
    """
    轉成跟 cra_articles.json 一致的欄位命名（article_no/title/text/
    embedding_text）。

    沿用 CRA 的欄位名而不是另外發明一套，是因為下游三個地方都是照這組
    欄位寫的：core/hybrid_search.py 建 BM25 索引、retrieve_*.py 的 RRF
    合併拿 article_no 當唯一 key、core/rag_context.py 組 LLM context。
    共用欄位名等於這三處完全不用改。

    article_no 一定要帶上標準名稱前綴（"IEC 62443-4-2 CR 1.7"，而不是
    裸的 "CR 1.7"）：這個字串在下游被當成跨知識庫的全域唯一識別字串用，
    沒有命名空間的話，兩部標準之間、以及跟 CRA 的 "Article n" 之間都
    可能撞號，撞號的後果是 RRF 合併時其中一筆被靜默覆蓋。
    """
    standard = spec["standard"]
    records = []
    for e in entries:
        text_parts = [
            ("Requirement", e.get("requirement", "")),
            ("Rationale and supplemental guidance", e.get("rationale", "")),
            ("Requirement enhancements", e.get("enhancements", "")),
        ]
        text = "\n\n".join(f"{label}:\n{body}" for label, body in text_parts if body.strip())

        records.append({
            "article_no": f"{standard} {e['clause_id']}",
            "clause_id": e["clause_id"],
            "clause_no": e["clause_no"],
            "standard": standard,
            "title": e["title"],
            "group": e.get("group", ""),
            "text": text,
            "security_levels": e.get("security_levels", ""),
            "embedding_text": build_embedding_text(e, standard),
        })
    return records


def detect_part(pdf_path: Path) -> str | None:
    """從檔名猜是哪一部，讓 --part 在檔名正常時可以省略。"""
    name = pdf_path.name.lower()
    for part in PART_SPECS:
        if f"62443-{part}" in name.replace("_", "-"):
            return part
    return None


def verify(records: list[dict], spec: dict) -> None:
    """
    解析後的自我檢查，理由跟 fetch_cra.py 的 --verify 一致：PDF 版面
    解析很容易「安靜地少解析到一半」，沒有主動核對就不會有人發現。
    """
    expected = spec["expected_count"]
    if abs(len(records) - expected) > 2:
        print(f"警告：解析出 {len(records)} 筆，預期約 {expected} 筆，"
              f"落差過大，建議人工核對 PART_SPECS 的 regex 是否需要調整。")
    else:
        print(f"數量核對通過（預期約 {expected} 筆，解析出 {len(records)} 筆）。")

    # article_no 在下游是唯一 key，重複會導致內容被靜默覆蓋
    seen: dict[str, int] = {}
    for r in records:
        seen[r["article_no"]] = seen.get(r["article_no"], 0) + 1
    dupes = [k for k, v in seen.items() if v > 1]
    if dupes:
        print(f"警告：發現 {len(dupes)} 個重複的 article_no，下游會有內容被靜默覆蓋："
              + ", ".join(dupes))
    else:
        print("article_no 唯一性檢查通過。")

    empty = [r["article_no"] for r in records if not r["text"].strip()]
    if empty:
        print(f"警告：{len(empty)} 筆沒有解析到任何內文（可能是純交叉引用的條目，"
              f"也可能是解析失敗）：" + ", ".join(empty[:10])
              + (" ..." if len(empty) > 10 else ""))

    # 授權浮水印含個資，絕對不能留在輸出裡——這是硬性檢查，不是提醒
    leaked = [r["article_no"] for r in records
              if re.search(r"Customer:|Order No\.|licence agreement", r["text"], re.IGNORECASE)]
    if leaked:
        print(f"錯誤：{len(leaked)} 筆內文殘留授權浮水印文字（含被授權人個資），"
              f"請勿使用這份輸出：" + ", ".join(leaked[:5]))
    else:
        print("授權浮水印剝除檢查通過（輸出不含被授權人資訊）。")


def main():
    parser = argparse.ArgumentParser(
        description="從授權取得的 IEC 62443-4-1 / 4-2 PDF 解析出結構化要求條目"
    )
    parser.add_argument("--pdf", required=True,
                        help="你自己授權取得的標準 PDF 路徑（本腳本不做任何下載）")
    parser.add_argument("--part", choices=sorted(PART_SPECS),
                        help="哪一部標準；省略時從檔名推斷")
    parser.add_argument("--verify", action="store_true",
                        help="解析後核對條目數量、編號唯一性、浮水印是否剝除乾淨")
    args = parser.parse_args()

    pdf_path = Path(args.pdf)
    if not pdf_path.is_file():
        sys.exit(f"Error: 找不到 PDF：{pdf_path}")

    part = args.part or detect_part(pdf_path)
    if part is None:
        sys.exit("Error: 無法從檔名判斷是哪一部標準，請用 --part 4-1 或 --part 4-2 指定。")

    spec = PART_SPECS[part]
    print(f"解析 {spec['standard']}：{pdf_path}")

    lines = extract_lines(pdf_path)
    print(f"[診斷] 清理後共 {len(lines)} 行文字（已剝除頁首、目錄、授權浮水印）")

    entries = parse_clauses(lines, spec)
    records = to_records(entries, spec)

    OUTPUT_DIR.mkdir(exist_ok=True)
    output_path = OUTPUT_DIR / spec["output"]
    output_path.write_text(
        json.dumps(records, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    print(f"解析完成，共 {len(records)} 筆要求條目，存到 {output_path}")
    print("提醒：這份輸出含標準原文，已在 .gitignore 中，請勿提交或散布。")

    if args.verify:
        verify(records, spec)


if __name__ == "__main__":
    main()
