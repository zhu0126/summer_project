#!/usr/bin/env python3
"""
讀 fetch_cwe.py 產出的 cwe_entries.json，用 fastembed 產生向量，
存進 Qdrant 的 "cwe" collection。

第一次執行會自動下載 embedding model（存在本機快取，之後不用重下）。
Qdrant 連線預設指向本機 docker（localhost:6333），跟你已經架好的環境對應。
"""
import json
import sys
from pathlib import Path

from fastembed import TextEmbedding
from qdrant_client import QdrantClient
from qdrant_client.models import Distance, PointStruct, VectorParams

INPUT_PATH = Path(__file__).resolve().parent / "cwe_data" / "cwe_entries.json"
COLLECTION_NAME = "cwe"
EMBEDDING_MODEL = "BAAI/bge-small-en-v1.5"  # 384 維，體積小、速度快，MVP 夠用
QDRANT_HOST = "localhost"
QDRANT_PORT = 6333

# 分批處理的批次大小：一次把 900+ 筆文字全部丟進 model.embed()、
# 一次把全部 PointStruct 物件建在記憶體裡再一次性 upsert，瞬間記憶體
# 尖峰用量遠高於平均值，資源有限的機器（例如 VM）容易被系統的
# OOM killer 強制終止（`zsh: killed`，不是 Python 例外，是作業系統
# 層級砍掉行程）。改成每次只處理一批，處理完就釋放，把尖峰壓低。
BATCH_SIZE = 64


def load_entries() -> list[dict]:
    if not INPUT_PATH.is_file():
        print(f"Error: 找不到 {INPUT_PATH}，請先執行 fetch_cwe.py")
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
        vectors = list(model.embed(texts))  # 只對這一批產生向量，不是全部

        points = [
            PointStruct(
                id=next_id + i,
                vector=vector.tolist(),
                payload={
                    "cwe_id": entry["cwe_id"],
                    "name": entry["name"],
                    "description": entry["description"],
                    "mitigations": entry["mitigations"],
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