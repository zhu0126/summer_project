#!/usr/bin/env python3
"""
下載官方 CRA（Regulation (EU) 2024/2847）條文，解析成結構化 json，
每個 Article 一筆，準備給下一步 embedding 用。跟 cwe_kb/fetch_cwe.py
是同一套模式：下載 → 解析成統一結構 → 存 json，後面接 build_cra_index.py。

來源：EUR-Lex 官方公報 HTML 版本（Official Journal, 原始公告文本）。
CRA 全文條號：https://eur-lex.europa.eu/eli/reg/2024/2847

解析邏輯的依據：EUR-Lex 公報 HTML 全部採用同一套固定 CSS class
命名慣例（不是這份文件獨有，是歐盟所有法規公報共用的排版系統）：
    <p class="oj-ti-art">Article 13</p>          條號標題
    <p class="oj-sti-art">Obligations of ...</p>  條文標題（可能沒有）
    <p class="oj-normal">1.   ...</p>              條文內容（可能有多段）

已知限制：EUR-Lex 這個頁面掛了 AWS WAF 的 JavaScript 挑戰機制
（會回傳一段需要瀏覽器執行 JS 才能過關的驗證頁面），單純的 HTTP
請求（requests/urllib）無法自動通過，會拿到空的驗證頁而不是真正
的法規內容。因為建置知識庫是低頻動作（不需要每次掃描都重抓），
建議改用手動下載：

    1. 用瀏覽器打開 CRA_SOURCE_URL，等頁面真正載入完成
       （不是驗證中的畫面，是看得到 "Article 1" 這些條文的頁面）
    2. 另存新檔（Ctrl+S），存成「網頁，僅 HTML」格式
    3. 執行：python3 fetch_cra.py --input-file 你存的檔案路徑.html

--input-file 沒有指定時，仍會嘗試直接下載（保留這條路徑，
是因為不同時間點/不同網路環境，WAF 的判斷不一定每次都觸發，
也可能未來換成別的來源網址剛好沒有這層防護）。
"""
import argparse
import re
import sys
from pathlib import Path

import requests
from bs4 import BeautifulSoup

CRA_SOURCE_URL = "https://eur-lex.europa.eu/legal-content/EN/TXT/HTML/?uri=OJ:L_202402847"
OUTPUT_PATH = Path(__file__).resolve().parent / "cra_data" / "cra_articles.json"
EXPECTED_ARTICLE_COUNT = 71  # CRA 官方公告全文共 71 條，用來事後檢查解析是否正常

ARTICLE_NO_PATTERN = re.compile(r"Article\s+(\d+)", re.IGNORECASE)

BROWSER_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
}


def download_cra_html() -> str:
    session = requests.Session()
    session.headers.update(BROWSER_HEADERS)
    session.get("https://eur-lex.europa.eu/", timeout=30)
    resp = session.get(CRA_SOURCE_URL, timeout=60)

    print(f"[診斷] HTTP 狀態碼：{resp.status_code}")
    print(f"[診斷] Content-Type：{resp.headers.get('Content-Type')}")
    print(f"[診斷] 實際收到 bytes 數：{len(resp.content)}")

    if "awsWafCookie" in resp.text or "challenge.js" in resp.text:
        print("[fetch_cra] 偵測到 AWS WAF JavaScript 挑戰頁面，無法自動繞過。")
        print("[fetch_cra] 請改用手動下載：用瀏覽器打開網址、等頁面真正載入後另存新檔，")
        print(f"[fetch_cra]   再執行：python3 fetch_cra.py --input-file 你存的檔案路徑.html")
        sys.exit(1)

    resp.raise_for_status()
    return resp.text


def parse_via_css_classes(soup: BeautifulSoup) -> list[dict]:
    """
    主要解析路徑：依 EUR-Lex 公報固定的 CSS class 抓取條文結構。
    抓不到任何 oj-ti-art 標記時回傳空 list，讓呼叫端改用 fallback。

    已修正的 bug：原本直接掃描整份文件裡所有 oj-normal 段落，遇到
    下一個 oj-ti-art 才收尾。但最後一條 Article（71）之後接的是
    Annex II~VIII、CE 聲明範本、Notified Body 審查程序，這些段落
    同樣用 oj-normal，而且後面不會再出現任何 oj-ti-art 標記去終止
    收集——導致 Article 71 的 text 把後面幾千字的無關內容全部吸了
    進去，實測發現這會讓語意檢索誤判成「Article 71 內容跟查詢相關」，
    但其實是混進去的 Annex 內容造成的假訊號。修法：明確排除掉屬於
    任何 Annex 容器（<div id="anx_*">）底下的段落，Article 解析
    只收「不屬於 Annex」的內容。
    """
    articles = []
    current = None

    # EUR-Lex 公報的條文標記（oj-ti-art/oj-sti-art/oj-normal）
    # 在 DOM 裡是同一層級的平行 <p> 標籤，不是巢狀結構，所以用
    # find_all 依文件順序逐一掃過，遇到新的 oj-ti-art 就切下一條，
    # 不用處理巢狀關係。
    for tag in soup.find_all(["p"], class_=["oj-ti-art", "oj-sti-art", "oj-normal"]):
        # 這個段落如果屬於任何 Annex 容器（id 開頭是 "anx_"），
        # 就不是 Article 的內容，跳過——避免最後一條 Article 因為
        # 後面沒有終止標記，把整個 Annex 都吸進來。
        if tag.find_parent("div", id=re.compile(r"^anx_")) is not None:
            continue

        classes = tag.get("class", [])
        text = tag.get_text(" ", strip=True)
        if not text:
            continue

        if "oj-ti-art" in classes:
            match = ARTICLE_NO_PATTERN.search(text)
            if not match:
                continue
            if current is not None:
                articles.append(current)
            current = {
                "article_no": f"Article {match.group(1)}",
                "title": "",
                "text": "",
            }
        elif current is None:
            continue  # 還沒遇到第一個 Article 標記前的內容（如目錄、序言）不收
        elif "oj-sti-art" in classes and not current["title"]:
            current["title"] = text
        else:  # oj-normal
            current["text"] = (current["text"] + "\n" + text).strip()

    if current is not None:
        articles.append(current)

    return articles


def parse_via_regex_fallback(full_text: str) -> list[dict]:
    """
    備用解析路徑：找不到預期的 CSS class 時，改用「Article \\d+」
    這個文字規則直接切分整份純文字。準確度不如 CSS 版本（容易誤把
    內文裡提到「Article 5」這種引用也當成新條文起點），但至少能
    確保腳本不會直接得到空結果，讓使用者有東西可以先檢查。
    """
    matches = list(ARTICLE_NO_PATTERN.finditer(full_text))
    articles = []
    for i, match in enumerate(matches):
        start = match.start()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(full_text)
        chunk = full_text[start:end].strip()
        articles.append({
            "article_no": f"Article {match.group(1)}",
            "title": "",
            "text": chunk,
        })
    return articles


# Annex 清單項目的標籤格式，八個 Annex 混用兩種風格，都要能辨識：
# - 括號包住的數字/字母/羅馬數字，如 (1)、(a)、(i)（Annex I/III/VII/VIII 用）
# - 句點結尾的數字（含小數點分層），如 1.、3.、3.1.（Annex II/III/V/VII/VIII 用）
ANNEX_LABEL_PATTERN = re.compile(r"^(\([a-zA-Z0-9ivxIVX]+\)|[0-9]+(?:\.[0-9]+)*\.)$")

# Annex 內部再分段的標題格式，如 "Part I ..."、"Part II ..."、"Class I"。
# 用來在 article_no 裡帶入分段前綴，避免不同段落各自從 (1) 重新編號時
# 產生同名的 article_no（例如 Annex I Part I 跟 Part II 都有一個 "(1)"）。
ANNEX_PART_PATTERN = re.compile(r"^(Part|Class)\s+[IVXLC]+")

ANNEX_NUMBERS = ["I", "II", "III", "IV", "V", "VI", "VII", "VIII"]


def extract_annex_items(table, prefix: str = "") -> list[dict]:
    """
    多數 Annex 的技術要求是用巢狀表格表示的清單結構：
        <table>
          <tr><td></td><td><p class="oj-normal">(1)</p></td>
              <td><span>要求內容...</span></td></tr>
        </table>
    項目 (2) 底下常常還有子項目 (a)(b)，用「同一個 content_td 裡
    再巢狀一層 <table>」表示。這裡用遞迴處理任意深度的巢狀，不假設
    只有兩層——每進一層，label 前綴就疊加一次（例如 "(2)(a)"）。

    只走「這一層」的表格結構，用 table.find("tr") 抓第一列，不用
    find_all 掃全部子孫節點，避免把子項目的內容重複算進上一層。
    """
    items = []
    row = table.find("tr")
    if row is None:
        return items

    cells = row.find_all("td", recursive=False)
    label = None
    content_td = None
    for i, td in enumerate(cells):
        text = td.get_text(strip=True)
        if ANNEX_LABEL_PATTERN.match(text):
            label = text
            if i + 1 < len(cells):
                content_td = cells[i + 1]
            break

    if label is None or content_td is None:
        return items

    full_label = f"{prefix}{label}"

    # 這個項目「自己的」文字：content_td 底下直接的 <span> 或
    # <p class="oj-normal">，不含巢狀 <table> 裡子項目的文字
    # （子項目交給下面的遞迴處理，不要在這裡重複收進來）。
    own_parts = []
    for child in content_td.children:
        name = getattr(child, "name", None)
        if name == "span":
            own_parts.append(child.get_text(" ", strip=True))
        elif name == "p" and "oj-normal" in (child.get("class") or []):
            own_parts.append(child.get_text(" ", strip=True))
    own_text = " ".join(p for p in own_parts if p)

    if own_text:
        items.append({"label": full_label, "text": own_text})

    # 遞迴處理巢狀子項目（如果有的話），子項目的 table 是
    # content_td 的直接子節點
    for nested_table in content_td.find_all("table", recursive=False):
        items.extend(extract_annex_items(nested_table, prefix=full_label))

    return items


def parse_annex_table_based(container, annex_no: str) -> list[dict]:
    """
    解析用巢狀表格清單表示技術要求的 Annex（I/II/III/V/VI/VII/VIII 都是
    這種結構）。容器內用 class="oj-ti-grseq-1" 標記 Part I / Part II /
    Class I 這種段落標題，段落標題之後接著一連串代表清單項目的 <table>。

    已修正的 bug：原本（parse_annex_i）只處理 Annex I，而且沒有把
    Part 標題帶進 article_no，導致 Annex I Part I 跟 Part II 各自從
    (1) 重新編號、彼此撞號（見 CHANGELOG／issue 討論）。這裡改成
    只要偵測到目前段落標題符合 "Part <羅馬數字>" 或 "Class <羅馬數字>"
    格式，就把這個短前綴一併放進 article_no，同一份 Annex 底下不同
    Part/Class 就算數字重新從 1 開始編號也不會撞號。

    另外有些表格本身沒有編號標籤（例如 Annex VI 的 EU 符合性聲明
    範本文字，格式是純段落，不是清單），extract_annex_items() 對這種
    表格會回傳空 list——這裡改成退回「整張表當一筆項目，用出現順序編號」，
    避免這類內容被靜默漏掉整個消失在知識庫裡。
    """
    entries = []
    current_part = ""
    fallback_counter = 0
    for child in container.children:
        name = getattr(child, "name", None)
        if name == "p" and "oj-ti-grseq-1" in (child.get("class") or []):
            current_part = child.get_text(" ", strip=True)
            fallback_counter = 0
        elif name == "table":
            items = extract_annex_items(child)
            if not items:
                fallback_counter += 1
                text = child.get_text(" ", strip=True)
                if text:
                    items = [{"label": str(fallback_counter), "text": text}]

            part_match = ANNEX_PART_PATTERN.match(current_part)
            part_prefix = f"{part_match.group(0)} " if part_match else ""

            for item in items:
                entries.append({
                    "article_no": f"Annex {annex_no} {part_prefix}{item['label']}",
                    "title": current_part,
                    "text": item["text"],
                })

    return entries


def parse_annex_iv(container, annex_no: str) -> list[dict]:
    """
    Annex IV（CRITICAL PRODUCTS WITH DIGITAL ELEMENTS）不是表格清單，
    是一連串 <div class="oj-enumeration-spacing">，每個 div 裡兩個
    <p style="display: inline;">：第一個是 "1.   " 這種純數字標籤，
    第二個包著 <span> 裝實際文字。結構跟其他 Annex 的巢狀表格完全不同，
    需要獨立處理，不能沿用 extract_annex_items()。
    """
    entries = []
    for div in container.find_all("div", class_="oj-enumeration-spacing", recursive=False):
        ps = div.find_all("p", recursive=False)
        if not ps:
            continue
        label_match = re.match(r"^([0-9]+)", ps[0].get_text(strip=True))
        if label_match is None:
            continue
        label = label_match.group(1)
        body_text = " ".join(p.get_text(" ", strip=True) for p in ps[1:]).strip()
        if body_text:
            entries.append({
                "article_no": f"Annex {annex_no} ({label})",
                "title": "",
                "text": body_text,
            })

    return entries


def parse_all_annexes(soup: BeautifulSoup) -> list[dict]:
    """
    依序解析 Annex I ~ VIII（CRA 官方公告的 Annex 總數），不是只有
    Annex I。找不到某個 Annex 的容器時印警告並跳過，不讓整個解析中斷——
    理由跟 Article fallback 一致：讓使用者知道「這個 Annex 沒解析到」，
    而不是安靜地少了一塊卻毫無提示。
    """
    all_entries = []
    for roman in ANNEX_NUMBERS:
        container = soup.find(id=f"anx_{roman}")
        if container is None:
            print(f"[fetch_cra] 警告：找不到 id=\"anx_{roman}\"，Annex {roman} 內容可能沒有被解析到。")
            continue

        if roman == "IV":
            entries = parse_annex_iv(container, roman)
        else:
            entries = parse_annex_table_based(container, roman)

        print(f"[fetch_cra]   Annex {roman}：解析出 {len(entries)} 筆項目")
        all_entries.extend(entries)

    return all_entries


def parse_cra_html(html_text: str) -> tuple[list[dict], list[dict]]:
    soup = BeautifulSoup(html_text, "html.parser")

    articles = parse_via_css_classes(soup)
    if not articles:
        print("[fetch_cra] 警告：找不到預期的 oj-ti-art CSS class，"
              "改用文字規則 fallback 解析（準確度較低，建議人工核對結果）。")
        articles = parse_via_regex_fallback(soup.get_text("\n"))

    annex_entries = parse_all_annexes(soup)

    return articles, annex_entries


def build_embedding_text(article: dict) -> str:
    parts = [article["article_no"], article["title"], article["text"]]
    return "\n".join(p for p in parts if p)


def main():
    parser = argparse.ArgumentParser(description="下載並解析 CRA 官方條文")
    parser.add_argument("--input-file", default=None,
                         help="改用手動下載存好的本機 HTML 檔案（繞過 AWS WAF JS 挑戰），"
                              "不指定則嘗試直接下載")
    parser.add_argument("--verify", action="store_true",
                         help="解析完後檢查條文數量是否接近官方公告的 71 條，數量落差過大會印警告")
    args = parser.parse_args()

    if args.input_file:
        input_path = Path(args.input_file)
        if not input_path.is_file():
            print(f"Error: 找不到檔案 {input_path}")
            sys.exit(1)
        print(f"讀取本機檔案：{input_path}")
        html_text = input_path.read_text(encoding="utf-8", errors="replace")
    else:
        print(f"下載中：{CRA_SOURCE_URL}")
        html_text = download_cra_html()

    # 診斷輸出：不管解析成不成功，都先把原始 HTML 存下來，
    # 這樣「下載內容本身有沒有問題」跟「解析邏輯猜錯 CSS class」
    # 這兩種完全不同的失敗原因才分得清楚。
    OUTPUT_PATH.parent.mkdir(exist_ok=True)
    raw_dump_path = OUTPUT_PATH.parent / "raw_page.html"
    raw_dump_path.write_text(html_text, encoding="utf-8")
    print(f"[診斷] 內容長度：{len(html_text)} 字元，已存到 {raw_dump_path} 供人工檢查")
    print(f"[診斷] 內容包含 'oj-ti-art' 字樣：{'oj-ti-art' in html_text}")
    print(f"[診斷] 內容包含 'Article' 字樣：{'Article' in html_text}")

    articles, annex_entries = parse_cra_html(html_text)
    all_entries = articles + annex_entries
    for a in all_entries:
        a["embedding_text"] = build_embedding_text(a)

    OUTPUT_PATH.parent.mkdir(exist_ok=True)
    import json
    OUTPUT_PATH.write_text(
        json.dumps(all_entries, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    print(f"解析完成，共 {len(articles)} 條 Article + {len(annex_entries)} 筆 Annex 項目"
          f"（合計 {len(all_entries)} 筆），存到 {OUTPUT_PATH}")

    if args.verify:
        diff = abs(len(articles) - EXPECTED_ARTICLE_COUNT)
        if diff > 5:
            print(f"警告：Article 解析出 {len(articles)} 條，跟官方公告的 {EXPECTED_ARTICLE_COUNT} 條"
                  f"差距達 {diff} 條，建議人工核對 parse_via_css_classes() 的 CSS class 是否需要調整。")
        else:
            print(f"Article 數量核對通過（官方 {EXPECTED_ARTICLE_COUNT} 條，解析出 {len(articles)} 條）。")

        if annex_entries:
            print(f"Annex 解析出 {len(annex_entries)} 筆項目，"
                  f"建議抽查幾筆 embedding_text 內容確認標籤跟文字對得起來。")
        else:
            print("警告：Annex 沒有解析出任何項目，請檢查 raw_page.html 裡 id=\"anx_*\" 的結構。")

        # 迴歸檢查：article_no 在下游（retrieve_cra.py 的 RRF 合併）被當成
        # 唯一 id 使用，重複會導致其中一筆被靜默覆蓋——這正是原本 Annex I
        # Part I/Part II 撞號的那個 bug，加這個檢查避免未來又不小心引入。
        seen = {}
        for entry in all_entries:
            seen.setdefault(entry["article_no"], []).append(entry)
        dupes = {k: v for k, v in seen.items() if len(v) > 1}
        if dupes:
            print(f"警告：發現 {len(dupes)} 個重複的 article_no，下游會有內容被靜默覆蓋："
                  + ", ".join(dupes.keys()))
        else:
            print("article_no 唯一性檢查通過，沒有重複的條文編號。")


if __name__ == "__main__":
    main()