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

INPUT_PATH = Path("cwe_data/cwe_entries.json")
COLLECTION_NAME = "cwe"
EMBEDDING_MODEL = "BAAI/bge-small-en-v1.5"  # 384 維，體積小、速度快，MVP 夠用
QDRANT_HOST = "localhost"
QDRANT_PORT = 6333


def load_entries() -> list[dict]:
    if not INPUT_PATH.is_file():
        print(f"Error: 找不到 {INPUT_PATH}，請先執行 fetch_cwe.py")
        sys.exit(1)
    return json.loads(INPUT_PATH.read_text(encoding="utf-8"))


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

    texts = [e["embedding_text"] for e in entries]
    print(f"產生 {len(texts)} 筆向量中...")
    vectors = list(model.embed(texts))

    points = [
        PointStruct(
            id=idx,
            vector=vector.tolist(),
            payload={
                "cwe_id": entry["cwe_id"],
                "name": entry["name"],
                "description": entry["description"],
                "mitigations": entry["mitigations"],
            },
        )
        for idx, (entry, vector) in enumerate(zip(entries, vectors))
    ]

    client.upsert(collection_name=COLLECTION_NAME, points=points)
    print(f"已寫入 Qdrant collection '{COLLECTION_NAME}'，共 {len(points)} 筆")


def main():
    entries = load_entries()
    build_index(entries)


if __name__ == "__main__":
    main()