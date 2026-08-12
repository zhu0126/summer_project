#!/usr/bin/env python3
"""
下載官方 CWE 資料（MITRE 提供），解析成結構化 json，
每個 CWE 條目（Weakness）一筆，準備給下一步 embedding 用。

來源固定用 cwec_latest.xml.zip，不用手動追版號，MITRE 會持續指向最新版本。

解析時故意用 local-name() 比對標籤名稱，不寫死 namespace URI
（例如 http://cwe.mitre.org/cwe-7）——CWE 改版時 namespace 版號
可能跟著變，用 local-name 比對可以在不修改程式碼的情況下沿用到新版本。
"""
import io
import sys
import json
import zipfile
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path

CWE_SOURCE_URL = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"
OUTPUT_PATH = Path(__file__).resolve().parent / "cwe_data" / "cwe_entries.json"


def localname(tag: str) -> str:
    """去掉 XML tag 前面的 namespace 部分，只留標籤名稱本身。"""
    return tag.rsplit("}", 1)[-1]


def download_cwe_xml() -> bytes:
    print(f"下載中：{CWE_SOURCE_URL}")
    with urllib.request.urlopen(CWE_SOURCE_URL, timeout=60) as resp:
        zip_bytes = resp.read()

    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
        xml_names = [n for n in zf.namelist() if n.endswith(".xml")]
        if not xml_names:
            raise RuntimeError("下載的 zip 檔裡找不到 .xml 檔案")
        return zf.read(xml_names[0])


def extract_text(el: ET.Element) -> str:
    """
    CWE 的描述欄位（Description/Extended_Description）內部常包含
    <xhtml:p> 這種排版標籤，用 itertext() 把所有子節點的文字內容
    抓出來接在一起，不需要另外處理巢狀標籤結構。
    """
    if el is None:
        return ""
    return " ".join(t.strip() for t in el.itertext() if t.strip())


def parse_weakness(weakness_el: ET.Element) -> dict:
    cwe_id = "CWE-" + weakness_el.get("ID", "")
    name = weakness_el.get("Name", "")
    abstraction = weakness_el.get("Abstraction", "")
    status = weakness_el.get("Status", "")

    description = ""
    extended_description = ""
    mitigations = []

    for child in weakness_el:
        tag = localname(child.tag)
        if tag == "Description":
            description = extract_text(child)
        elif tag == "Extended_Description":
            extended_description = extract_text(child)
        elif tag == "Potential_Mitigations":
            for mitigation_el in child:
                if localname(mitigation_el.tag) != "Mitigation":
                    continue
                desc_el = None
                for m_child in mitigation_el:
                    if localname(m_child.tag) == "Description":
                        desc_el = m_child
                        break
                text = extract_text(desc_el)
                if text:
                    mitigations.append(text)

    # 準備一份給 embedding 用的合併文字：把 name/description/mitigation
    # 接在一起，讓語意檢索時能同時比對到「這是什麼問題」跟「怎麼修」
    text_parts = [name, description, extended_description] + mitigations
    embedding_text = "\n".join(p for p in text_parts if p)

    return {
        "cwe_id": cwe_id,
        "name": name,
        "abstraction": abstraction,
        "status": status,
        "description": description,
        "extended_description": extended_description,
        "mitigations": mitigations,
        "embedding_text": embedding_text,
    }


def parse_cwe_xml(xml_bytes: bytes) -> list[dict]:
    root = ET.fromstring(xml_bytes)

    entries = []
    for el in root.iter():
        if localname(el.tag) != "Weakness":
            continue
        entry = parse_weakness(el)
        # 跳過已棄用（Deprecated）或內容空白的條目，避免 embedding 時
        # 塞進沒有實際判讀價值的資料
        if entry["status"] == "Deprecated" or not entry["embedding_text"]:
            continue
        entries.append(entry)

    return entries


def main():
    xml_bytes = download_cwe_xml()
    entries = parse_cwe_xml(xml_bytes)

    OUTPUT_PATH.parent.mkdir(exist_ok=True)
    OUTPUT_PATH.write_text(
        json.dumps(entries, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    print(f"解析完成，共 {len(entries)} 筆 CWE 條目，存到 {OUTPUT_PATH}")


if __name__ == "__main__":
    main()