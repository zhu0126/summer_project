import sys
sys.path.insert(0, '.')

from common import make_finding
from analysis import _build_rag_query, _cwe_candidates, _cra_candidates

# 換成你要測試的實際情境
finding = make_finding(
    "network", "nmap", "192.168.1.10", "info", "tcp/6379 redis",
    detail={"service": "redis", "state": "open"}
)

query = _build_rag_query(finding)
print(f"實際查詢字串: {query!r}")
print()

print("=== CWE 候選 ===")
for c in _cwe_candidates(finding):
    print(f"cwe_id       : {c['cwe_id']}")
    print(f"name         : {c['name']}")
    print(f"score        : {c['score']}")
    print(f"matched_by   : {c['matched_by']}")
    print(f"description  : {c['description']}")
    print(f"mitigations  : {c['mitigations']}")
    print("---")

print()
print("=== CRA 候選 ===")
for c in _cra_candidates(finding):
    print(f"article_no   : {c['article_no']}")
    print(f"title (Part) : {c['title']}")
    print(f"score        : {c['score']}")
    print(f"matched_by   : {c['matched_by']}")
    print(f"text (條文內容): {c['text']}")
    print("---")