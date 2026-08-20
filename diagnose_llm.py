#!/usr/bin/env python3
"""
一次性診斷腳本：確認「弱點名稱（weakness_name）」這條 LLM 路徑在目前這台
機器上到底斷在哪一段。

為什麼需要這支腳本：llm_advisor 的每一層失敗都是「印個警告然後回 None」的
降級設計（沒金鑰、沒套件、呼叫失敗都不該讓報告產不出來），好處是掃描不會
中斷，代價是失敗訊息混在幾百行掃描輸出裡很容易被漏看，而且有幾種失敗
（例如 derive_weakness_name 匯入不到而變成 None）根本不會在掃描當下印任何
東西。這支腳本把那些沉默的分支逐一攤開來檢查。

用法（在專案根目錄執行）：
    python3 diagnose_llm.py
"""
import os
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))


def check(label: str, ok: bool, detail: str = "") -> bool:
    mark = "OK  " if ok else "FAIL"
    print(f"[{mark}] {label}" + (f" — {detail}" if detail else ""))
    return ok


print("=" * 70)
print("LLM 弱點名稱路徑診斷")
print("=" * 70)
print(f"專案根目錄：{PROJECT_ROOT}")
print(f"目前工作目錄：{Path.cwd()}")
print(f"Python：{sys.executable}")
print()

# --- 1. .env 檔案本身 ---
env_path = PROJECT_ROOT / ".env"
if not check("找到 .env 檔案", env_path.is_file(), str(env_path)):
    print("     → 請確認 .env 放在專案根目錄（跟 core/ 同一層）。")
else:
    has_key_line = any(
        line.strip().startswith("ANTHROPIC_API_KEY")
        for line in env_path.read_text(encoding="utf-8", errors="replace").splitlines()
    )
    check(".env 內含 ANTHROPIC_API_KEY 這一行", has_key_line)

# --- 2. python-dotenv 有沒有裝、載得進來嗎 ---
try:
    from dotenv import load_dotenv
    check("python-dotenv 已安裝", True)
    load_dotenv(env_path)
except ImportError:
    check("python-dotenv 已安裝", False, "pip install python-dotenv")

# --- 3. 環境變數實際上有沒有值 ---
key = os.environ.get("ANTHROPIC_API_KEY")
if check("環境變數 ANTHROPIC_API_KEY 有值", bool(key),
         f"開頭 {key[:12]}…，長度 {len(key)}" if key else "空的"):
    # 常見的貼錯：整行連引號一起被當成值，或前後有空白
    if key.startswith(("'", '"')) or key.endswith(("'", '"')):
        check("金鑰沒有被引號包住", False, "值的前後有引號，dotenv 會原樣讀進來")
    if key != key.strip():
        check("金鑰前後沒有多餘空白", False)

# --- 4. anthropic 套件 ---
try:
    import anthropic
    check("anthropic 套件已安裝", True, f"版本 {getattr(anthropic, '__version__', '未知')}")
except ImportError:
    check("anthropic 套件已安裝", False, "pip install anthropic")

# --- 5. llm_advisor 這一側的判定 ---
from core import llm_advisor

check("llm_advisor.is_available()", llm_advisor.is_available())
print(f"       使用模型：{llm_advisor.MODEL_NAME}")
print(f"       弱點名稱快取檔：{llm_advisor.WEAKNESS_NAME_CACHE_PATH}"
      f"（{'存在' if llm_advisor.WEAKNESS_NAME_CACHE_PATH.is_file() else '不存在，會在第一次成功後建立'}）")

# --- 6. analysis 那一側到底有沒有拿到函式（這一段失敗時掃描當下是沉默的） ---
from core import analysis

check("analysis.derive_weakness_name 匯入成功",
      analysis.derive_weakness_name is not None,
      "為 None 代表 core/llm_advisor.py 是舊版（沒有這個函式），"
      "或匯入時出錯——這種情況掃描時不會印任何訊息")
check("analysis.derive_finding_summary 匯入成功",
      analysis.derive_finding_summary is not None)

# --- 7. 真的打一次 API ---
print()
print("-" * 70)
print("實際呼叫一次 Claude（用一筆假的 finding，不含任何真實掃描資料）")
print("-" * 70)

fake_finding = {
    "finding_id": "diagnose-0001",
    "target": "127.0.0.1",
    "category": "network",
    "source": "nmap",
    "severity": "info",
    "title": "tcp/23 telnet",
    "detail": {"service": "telnet", "state": "open", "port": 23},
}

result = analysis.analyze_finding(fake_finding)
print(f"status        = {result['status']}")
print(f"risk_level    = {result['risk_level']}")
print(f"weakness_name = {result.get('weakness_name')!r}")
print()

if result.get("weakness_name"):
    print("✅ LLM 路徑正常，弱點名稱有產生出來。")
    print("   如果網頁上仍然顯示舊的名稱，問題不在後端，請依序確認：")
    print("   1. 看的是不是這次新掃描的結果（舊掃描的 weakness_name 是 null，會退回顯示 title）")
    print("   2. 瀏覽器快取了舊版 index.html — 用 Ctrl+Shift+R 強制重新載入")
    print("   3. 開 F12 → Network → 找 /api/scan/current 的回應，看 JSON 裡有沒有 weakness_name 欄位")
else:
    print("❌ 弱點名稱沒有產生。上面第一個 FAIL 的項目就是原因；")
    print("   若全部都 OK 卻仍失敗，看上方是否有 [llm_advisor] 開頭的錯誤訊息。")
