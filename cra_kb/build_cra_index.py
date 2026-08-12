#!/usr/bin/env python3
"""
讀 fetch_cra.py 產出的 cra_articles.json，用 fastembed 產生向量，
存進 Qdrant 的 "cra" collection。跟 cwe_kb/build_cwe_index.py 是同一套
模式，只是資料來源跟 collection 名稱不同——用同一顆 embedding model，
確保跟 cwe collection 的向量空間一致，之後如果要合併查詢兩個知識庫
也不會有維度不一致的問題。

第一次執行會自動下載 embedding model（存在本機快取，之後不用重下）。
Qdrant 連線預設指向本機 docker（localhost:6333）。
"""
import json
import sys
from pathlib import Path

from fastembed import TextEmbedding
from qdrant_client import QdrantClient
from qdrant_client.models import Distance, PointStruct, VectorParams

INPUT_PATH = Path(__file__).resolve().parent / "cra_data" / "cra_articles.json"
COLLECTION_NAME = "cra"
EMBEDDING_MODEL = "BAAI/bge-small-en-v1.5"  # 跟 cwe collection 用同一顆，向量空間一致
QDRANT_HOST = "localhost"
QDRANT_PORT = 6333

# 分批處理的批次大小，理由跟 cwe_kb/build_cwe_index.py 一致：
# 一次把全部資料丟進 model.embed() 再一次性 upsert，瞬間記憶體尖峰
# 遠高於平均值，容易在資源有限的機器上被 OOM killer 強制終止。
BATCH_SIZE = 64


def load_entries() -> list[dict]:
    if not INPUT_PATH.is_file():
        print(f"Error: 找不到 {INPUT_PATH}，請先執行 fetch_cra.py")
        sys.exit(1)
    return json.loads(INPUT_PATH.read_text(encoding="utf-8"))


def batched(items: list, size: int):
    for i in range(0, len(items), size):
        yield items[i:i + size]


def build_index(entries: list[dict]) -> None:
    print(f"載入 embedding model：{EMBEDDING_MODEL}（第一次執行會下載，請確保網路暢通）")
    model = TextEmbedding(EMBEDDING_MODEL)

    client = QdrantClient(host=QDRANT_HOST, port=QDRANT_PORT)

    # 用一筆資料先測出向量維度，動態建立 collection，避免維度寫死
    # 之後換了不同的 embedding model 卻忘記同步改這裡的設定值
    sample_vector = next(model.embed([entries[0]["embedding_text"]]))
    vector_size = len(sample_vector)

    if client.collection_exists(COLLECTION_NAME):
        client.delete_collection(COLLECTION_NAME)
    client.create_collection(
        collection_name=COLLECTION_NAME,
        vectors_config=VectorParams(size=vector_size, distance=Distance.COSINE),
    )

    total = len(entries)
    written = 0
    next_id = 0

    for batch in batched(entries, BATCH_SIZE):
        texts = [e["embedding_text"] for e in batch]
        vectors = list(model.embed(texts))

        points = [
            PointStruct(
                id=next_id + i,
                vector=vector.tolist(),
                payload={
                    "article_no": entry["article_no"],
                    "title": entry["title"],
                    "text": entry["text"],
                },
            )
            for i, (entry, vector) in enumerate(zip(batch, vectors))
        ]

        client.upsert(collection_name=COLLECTION_NAME, points=points)
        next_id += len(batch)
        written += len(batch)
        print(f"  進度：{written}/{total}")

    print(f"已寫入 Qdrant collection '{COLLECTION_NAME}'，共 {written} 筆")


def main():
    entries = load_entries()
    build_index(entries)


if __name__ == "__main__":
    main()