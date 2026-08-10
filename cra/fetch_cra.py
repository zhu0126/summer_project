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
容器網路白名單不包含 eur-lex.europa.eu，這支腳本沒辦法在開發環境
裡對真實檔案完整測試，只用手動構造的樣本驗證過解析邏輯本身。
下面的 fallback 機制是為了因應「萬一實際格式跟預期的 class 名稱
有落差」這種沒辦法在這裡驗證到的風險：找不到任何 oj-ti-art 標記時，
改用「Article \\d+」的文字規則切分，確保不會直接得到空結果。
請在你自己的機器執行後，用 --verify 確認解析出的條文數量合理
（CRA 官方公告全文共 71 條，數量落差太大代表解析邏輯需要調整）。
"""
import argparse
import re
import sys
from pathlib import Path

import requests
from bs4 import BeautifulSoup

CRA_SOURCE_URL = "https://eur-lex.europa.eu/legal-content/EN/TXT/HTML/?uri=OJ:L_202402847"
OUTPUT_PATH = Path("cra_data/cra_articles.json")
EXPECTED_ARTICLE_COUNT = 71  # CRA 官方公告全文共 71 條，用來事後檢查解析是否正常

ARTICLE_NO_PATTERN = re.compile(r"Article\s+(\d+)", re.IGNORECASE)

# 完整的瀏覽器標頭：EUR-Lex 對「明顯不是瀏覽器」的請求（例如標頭過於
#陽春的 urllib 預設請求）可能回傳空內容或做簡易反爬蟲判斷，即使 HTTP
# 狀態碼是 200。這裡盡量模擬真實瀏覽器會帶的標頭組合。
BROWSER_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
}


def download_cra_html() -> str:
    # 用 Session 而不是單次 request：先訪問一次網域首頁，讓伺服器
    # 有機會發回 cookie（EUR-Lex 部分頁面需要 session cookie 才會
    # 回傳完整內容，直接單次請求目標頁面可能拿到空的或被導向的內容），
    # 這是在模擬「手動用瀏覽器開網頁時，瀏覽器本來就會先建立連線、
    # 帶上 cookie」這個過程。
    session = requests.Session()
    session.headers.update(BROWSER_HEADERS)

    session.get("https://eur-lex.europa.eu/", timeout=30)

    resp = session.get(CRA_SOURCE_URL, timeout=60)

    print(f"[診斷] HTTP 狀態碼：{resp.status_code}")
    print(f"[診斷] Content-Type：{resp.headers.get('Content-Type')}")
    print(f"[診斷] Content-Length 標頭：{resp.headers.get('Content-Length')}")
    print(f"[診斷] 實際收到 bytes 數：{len(resp.content)}")

    resp.raise_for_status()
    return resp.text


def parse_via_css_classes(soup: BeautifulSoup) -> list[dict]:
    """
    主要解析路徑：依 EUR-Lex 公報固定的 CSS class 抓取條文結構。
    抓不到任何 oj-ti-art 標記時回傳空 list，讓呼叫端改用 fallback。
    """
    articles = []
    current = None

    # EUR-Lex 公報的條文標記（oj-ti-art/oj-sti-art/oj-normal）
    # 在 DOM 裡是同一層級的平行 <p> 標籤，不是巢狀結構，所以用
    # find_all 依文件順序逐一掃過，遇到新的 oj-ti-art 就切下一條，
    # 不用處理巢狀關係。
    for tag in soup.find_all(["p"], class_=["oj-ti-art", "oj-sti-art", "oj-normal"]):
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


def parse_cra_html(html_text: str) -> list[dict]:
    soup = BeautifulSoup(html_text, "html.parser")

    articles = parse_via_css_classes(soup)
    if articles:
        return articles

    print("[fetch_cra] 警告：找不到預期的 oj-ti-art CSS class，"
          "改用文字規則 fallback 解析（準確度較低，建議人工核對結果）。")
    return parse_via_regex_fallback(soup.get_text("\n"))


def build_embedding_text(article: dict) -> str:
    parts = [article["article_no"], article["title"], article["text"]]
    return "\n".join(p for p in parts if p)


def main():
    parser = argparse.ArgumentParser(description="下載並解析 CRA 官方條文")
    parser.add_argument("--verify", action="store_true",
                         help="解析完後檢查條文數量是否接近官方公告的 71 條，數量落差過大會印警告")
    args = parser.parse_args()

    print(f"下載中：{CRA_SOURCE_URL}")
    html_text = download_cra_html()

    # 診斷輸出：不管解析成不成功，都先把原始 HTML 存下來，
    # 這樣「下載內容本身有沒有問題」跟「解析邏輯猜錯 CSS class」
    # 這兩種完全不同的失敗原因才分得清楚。
    OUTPUT_PATH.parent.mkdir(exist_ok=True)
    raw_dump_path = OUTPUT_PATH.parent / "raw_page.html"
    raw_dump_path.write_text(html_text, encoding="utf-8")
    print(f"[診斷] 下載內容長度：{len(html_text)} 字元，已存到 {raw_dump_path} 供人工檢查")
    print(f"[診斷] 內容包含 'oj-ti-art' 字樣：{'oj-ti-art' in html_text}")
    print(f"[診斷] 內容包含 'Article' 字樣：{'Article' in html_text}")
    print(f"[診斷] 內容前 300 字元預覽：\n{html_text[:300]!r}")

    articles = parse_cra_html(html_text)
    for a in articles:
        a["embedding_text"] = build_embedding_text(a)

    OUTPUT_PATH.parent.mkdir(exist_ok=True)
    import json
    OUTPUT_PATH.write_text(
        json.dumps(articles, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    print(f"解析完成，共 {len(articles)} 條，存到 {OUTPUT_PATH}")

    if args.verify:
        diff = abs(len(articles) - EXPECTED_ARTICLE_COUNT)
        if diff > 5:
            print(f"警告：解析出 {len(articles)} 條，跟官方公告的 {EXPECTED_ARTICLE_COUNT} 條"
                  f"差距達 {diff} 條，建議人工核對 parse_via_css_classes() 的 CSS class 是否需要調整。")
        else:
            print(f"條文數量核對通過（官方 {EXPECTED_ARTICLE_COUNT} 條，解析出 {len(articles)} 條）。")


if __name__ == "__main__":
    main()