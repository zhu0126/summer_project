#!/usr/bin/env python3
"""
讀 fetch_iec.py 產出的 iec_4_1.json / iec_4_2.json，用 fastembed 產生向量，
存進 Qdrant。跟 cwe_kb/build_cwe_index.py、cra_kb/build_cra_index.py 是
同一套模式，用同一顆 embedding model 確保三個知識庫的向量空間一致。

跟前兩者的唯一差異是「一支腳本要建兩個 collection」：62443-4-1 跟 4-2
分開存，不合併成一個。理由不是實作方便，是檢索品質——

    4-2 是技術要求（CR 1.7 密碼強度、CR 3.1 通訊完整性…），掃描結果
    幾乎都能落到某一條；4-1 是開發流程要求（SM-4 安全專業能力、
    SVV-4 滲透測試…），跟「tcp/23 telnet 開著」這種 finding 在語意上
    沒有任何相似性。

兩者混在同一個 collection、共用同一份 top-K 名額時，4-1 的條目會純粹
當雜訊擠掉真正有用的 CR 候選。這正是 analysis.py 開頭那段結論的延伸：
向量分數沒有能力區分「真的相關」跟「看起來有點像」，所以要在檢索之前
就用結構把不該被拿來比的東西隔開，而不是指望排序自己處理掉。

分開成兩個 collection 而不是一個 collection 加 payload filter：專案裡
現有的檢索程式碼從頭到尾沒用過 Qdrant 的 Filter，而 core/hybrid_search.py
的 BM25 索引是「一個 json 檔建一份」的。拆成兩檔兩 collection，dense
跟 sparse 兩條路都不用改任何共用程式碼。

第一次執行會自動下載 embedding model（存在本機快取，之後不用重下）。
Qdrant 連線預設指向本機 docker（localhost:6333）。
"""
import argparse
import json
import sys
from pathlib import Path

from fastembed import TextEmbedding
from qdrant_client import QdrantClient
from qdrant_client.models import Distance, PointStruct, VectorParams

DATA_DIR = Path(__file__).resolve().parent / "iec_data"
EMBEDDING_MODEL = "BAAI/bge-small-en-v1.5"  # 跟 cwe/cra collection 用同一顆
QDRANT_HOST = "localhost"
QDRANT_PORT = 6333

# 分批大小，理由跟另外兩個知識庫一致：一次把全部資料丟進 model.embed()
# 再一次性 upsert，瞬間記憶體尖峰遠高於平均值，容易被 OOM killer 終止。
BATCH_SIZE = 64

# part -> (資料檔, collection 名稱)。retrieve_iec.py 直接 import 這份對照表，
# 兩邊不會各寫一份 collection 名稱而寫錯字。
PARTS = {
    "4-1": {"file": "iec_4_1.json", "collection": "iec62443_4_1"},
    "4-2": {"file": "iec_4_2.json", "collection": "iec62443_4_2"},
}

# 掃描結果的逐筆檢索只查這一部（見模組開頭的說明）。retrieve_iec.py
# 跟 core/analysis.py 都以這個常數為準，不各自寫死字串。
DEFAULT_FINDING_PART = "4-2"


def data_path(part: str) -> Path:
    return DATA_DIR / PARTS[part]["file"]


def load_entries(part: str) -> list[dict]:
    path = data_path(part)
    if not path.is_file():
        print(f"Error: 找不到 {path}，請先執行："
              f"python -m iec_kb.fetch_iec --pdf <你的標準PDF> --part {part}")
        sys.exit(1)
    return json.loads(path.read_text(encoding="utf-8"))


def batched(items: list, size: int):
    for i in range(0, len(items), size):
        yield items[i:i + size]


def build_index(part: str, entries: list[dict], model: TextEmbedding, client: QdrantClient) -> None:
    collection = PARTS[part]["collection"]

    # 用一筆資料先測出向量維度，動態建立 collection，避免維度寫死之後
    # 換了 embedding model 卻忘記同步改這裡
    sample_vector = next(model.embed([entries[0]["embedding_text"]]))
    vector_size = len(sample_vector)

    if client.collection_exists(collection):
        client.delete_collection(collection)
    client.create_collection(
        collection_name=collection,
        vectors_config=VectorParams(size=vector_size, distance=Distance.COSINE),
    )

    total = len(entries)
    written = 0

    for batch in batched(entries, BATCH_SIZE):
        vectors = list(model.embed([e["embedding_text"] for e in batch]))
        points = [
            PointStruct(
                id=written + i,
                vector=vector.tolist(),
                payload={
                    "article_no": entry["article_no"],
                    "clause_id": entry["clause_id"],
                    "standard": entry["standard"],
                    "title": entry["title"],
                    "group": entry.get("group", ""),
                    "text": entry["text"],
                    "security_levels": entry.get("security_levels", ""),
                },
            )
            for i, (entry, vector) in enumerate(zip(batch, vectors))
        ]
        client.upsert(collection_name=collection, points=points)
        written += len(batch)
        print(f"  進度：{written}/{total}")

    print(f"已寫入 Qdrant collection '{collection}'，共 {written} 筆")


def main():
    parser = argparse.ArgumentParser(description="建立 IEC 62443 知識庫的 Qdrant 索引")
    parser.add_argument("--part", choices=sorted(PARTS),
                        help="只建其中一部；省略時兩部都建")
    args = parser.parse_args()

    parts = [args.part] if args.part else sorted(PARTS)

    print(f"載入 embedding model：{EMBEDDING_MODEL}（第一次執行會下載，請確保網路暢通）")
    model = TextEmbedding(EMBEDDING_MODEL)
    client = QdrantClient(host=QDRANT_HOST, port=QDRANT_PORT)

    for part in parts:
        print(f"\n=== IEC 62443-{part} ===")
        build_index(part, load_entries(part), model, client)


if __name__ == "__main__":
    main()
