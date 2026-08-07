#!/usr/bin/env python3
"""
通用 Markdown -> PDF 報告轉換工具
用法:
    python3 md_to_pdf.py 輸入.md 輸出.pdf [--org "單位名稱"] [--title "報告標題"]

模板位置（與本檔案同資料夾）:
    style.css   - 版面樣式（可自由調整顏色、字型、頁首頁尾）
    page.html   - HTML 外框（{title}/{org}/{generated_at}/{body} 為佔位符）
"""
import argparse
import datetime
import re
from pathlib import Path

import markdown as md
from bs4 import BeautifulSoup
from weasyprint import HTML

TEMPLATE_DIR = Path(__file__).parent

# 表格儲存格文字若完全符合以下字樣（不分大小寫），會被轉成彩色風險標籤
RISK_CLASS = {
    "CRITICAL": "risk-critical",
    "嚴重": "risk-critical",
    "HIGH": "risk-high",
    "高": "risk-high",
    "MEDIUM": "risk-medium",
    "MED": "risk-medium",
    "中": "risk-medium",
    "LOW": "risk-low",
    "低": "risk-low",
    "INFO": "risk-info",
    "資訊": "risk-info",
}


def convert(md_path: str, out_pdf: str, title: str = None, org: str = ""):
    text = Path(md_path).read_text(encoding="utf-8")
    html_body = md.markdown(text, extensions=["tables", "fenced_code", "nl2br", "sane_lists"])
    soup = BeautifulSoup(html_body, "html.parser")

    # 用第一個 H1 當標題（若未指定 --title），並從內文移除避免重複顯示
    h1 = soup.find("h1")
    doc_title = title or (h1.get_text(strip=True) if h1 else Path(md_path).stem)
    if h1:
        h1.decompose()

    # 表格中若儲存格文字符合風險等級關鍵字，套上彩色標籤
    for td in soup.find_all("td"):
        text_content = td.get_text(strip=True)
        key = text_content.upper()
        cls = RISK_CLASS.get(key) or RISK_CLASS.get(text_content)
        if cls:
            td.clear()
            span = soup.new_tag("span")
            span["class"] = f"badge {cls}"
            span.string = text_content
            td.append(span)

    body_html = str(soup)

    page_tpl = (TEMPLATE_DIR / "page.html").read_text(encoding="utf-8")
    generated_at = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    org_line = f"<span>{org}</span>" if org else ""
    header_org = f'<span class="header-org">{org}</span>' if org else ""

    full_html = page_tpl.format(
        title=doc_title,
        org=org,
        org_line=org_line,
        header_org=header_org,
        generated_at=generated_at,
        body=body_html,
    )

    HTML(string=full_html, base_url=str(TEMPLATE_DIR)).write_pdf(
        out_pdf, stylesheets=[str(TEMPLATE_DIR / "style.css")]
    )
    print(f"已產生: {out_pdf}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Markdown 轉 PDF（含美編模板）")
    parser.add_argument("input", help="輸入 Markdown 檔案路徑")
    parser.add_argument("output", help="輸出 PDF 檔案路徑")
    parser.add_argument("--title", default=None, help="報告標題（預設取自第一個 H1）")
    parser.add_argument("--org", default="", help="單位/系統名稱，顯示於頁首頁尾")
    args = parser.parse_args()

    convert(args.input, args.output, title=args.title, org=args.org)
