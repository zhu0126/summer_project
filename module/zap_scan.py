import argparse
import shutil
import subprocess
import sys
import time
 
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse
 
from common import OUTPUT_DIR, print_file_status, save_findings_json, make_finding, print_findings
 
try:
    from zapv2 import ZAPv2
except ImportError:
    ZAPv2 = None
 
DEFAULT_ZAP_API_URL = "http://127.0.0.1:8080"
ZAP_STARTUP_TIMEOUT = 90  # daemon 冷啟動可能要一分鐘以上，給充裕的等待時間
 
 
class ZapConnectionError(Exception):
    """ZAP daemon 連不上時丟出，跟 requests/zapv2 底層各種例外型別隔開，
    讓呼叫端只需要認得這一種例外就能判斷『是連線問題』。"""
    pass
 
# ZAP 自己的 risk 分級（High/Medium/Low/Informational）代表 ZAP 內建規則庫
# 的專業判斷，但不直接拿來當作頂層的 severity——收集層階段統一先給 info，
# 讓 nmap/binwalk/zap 三種來源在「進合規判讀層之前」站在同一個起跑點，
# 不會有的來源已經被工具自己的規則庫打過分、有的還沒。
# ZAP 原本的判斷不會遺失，正規化成小寫後存進 detail.zap_risk，
# 合規判讀層仍然可以參考它，只是不再直接等於我們的 severity。
RISK_TO_ZAP_RISK = {
    "High": "high",
    "Medium": "medium",
    "Low": "low",
    "Informational": "info",
}
 
 
def check_zapv2_installed():
    if ZAPv2 is None:
        raise ImportError(
            "zaproxy (Python client) not installed. "
            "Run: pip install zaproxy"
        )
 
 
def validate_target_url(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise ValueError(f"'{url}' is not a valid http(s) URL")
    return url
 
 
def connect_zap(zap_api_url: str = DEFAULT_ZAP_API_URL) -> "ZAPv2":
    zap = ZAPv2(proxies={"http": zap_api_url, "https": zap_api_url})
    try:
        # 用 zap.core.version 當作連線探測：daemon 沒開的話這裡會直接丟例外，
        # 讓呼叫端能盡早發現「不是掃描目標的問題，是 ZAP daemon 沒啟動」。
        zap.core.version
    except Exception as e:
        raise ZapConnectionError(f"cannot connect to ZAP daemon at {zap_api_url} ({e})") from e
    return zap
 
 
def is_zap_reachable(zap_api_url: str = DEFAULT_ZAP_API_URL) -> bool:
    try:
        connect_zap(zap_api_url)
        return True
    except ZapConnectionError:
        return False
 
 
def find_zap_launcher() -> str:
    """
    找出可用的 ZAP 啟動指令。不同安裝方式的執行檔名稱不一樣
    （apt 版是 zaproxy，官方 tarball 版是 zap.sh），這裡都嘗試找找看。
    """
    for name in ("zaproxy", "zap.sh", "owasp-zap"):
        path = shutil.which(name)
        if path is not None:
            return path
    raise FileNotFoundError(
        "找不到可執行的 ZAP（嘗試過 zaproxy / zap.sh / owasp-zap）。"
        "請先安裝 ZAP，或改用 --zap-api-url 指向已經在跑的 daemon。"
    )
 
 
def start_zap_daemon(zap_api_url: str = DEFAULT_ZAP_API_URL) -> subprocess.Popen:
    """
    背景啟動一個 ZAP daemon。用 Popen（非阻塞）而不是 run，
    是因為 daemon 要一直活著、不能等它「執行完」——它本來就不會執行完。
    """
    launcher = find_zap_launcher()
    parsed = urlparse(zap_api_url)
    host = parsed.hostname or "127.0.0.1"
    port = parsed.port or 8080
 
    # daemon 啟動過程的 log 別直接噴到終端機，落地成檔案，
    # 掃描失敗時方便回頭查是不是 daemon 本身啟動有問題。
    startup_log = OUTPUT_DIR / "zap_daemon_startup.log"
    log_fp = open(startup_log, "w", encoding="utf-8")
 
    proc = subprocess.Popen(
        [launcher, "-daemon", "-host", host, "-port", str(port), "-config", "api.disablekey=true"],
        stdout=log_fp,
        stderr=subprocess.STDOUT,
    )
    print(f"[zap] 已啟動 ZAP daemon（pid={proc.pid}），啟動 log： {startup_log}")
    return proc
 
 
def wait_for_zap_ready(zap_api_url: str = DEFAULT_ZAP_API_URL, timeout: int = ZAP_STARTUP_TIMEOUT) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if is_zap_reachable(zap_api_url):
            return
        time.sleep(2)
    raise ZapConnectionError(f"ZAP daemon 在 {timeout} 秒內沒有就緒（啟動超時）")
 
 
def run_zap_scan(
    zap: "ZAPv2",
    target_url: str,
    base_name: str,
    active_scan: bool = True,
    poll_interval: int = 2,
) -> tuple[str, str]:
    log_lines = [f"Target: {target_url}", f"Started: {datetime.now().isoformat()}"]
 
    # 1. Spider：爬過目標網站的連結，讓 ZAP 知道有哪些頁面/端點存在
    log_lines.append("---- Spider ----")
    spider_id = zap.spider.scan(target_url)
    while int(zap.spider.status(spider_id)) < 100:
        time.sleep(poll_interval)
    log_lines.append(f"Spider finished. URLs found: {len(zap.spider.results(spider_id))}")
 
    # 2. Active scan：對爬到的端點實際送出攻擊性測試請求
    #    這步驟才是真正產生弱點發現的地方，spider 只是先探路
    if active_scan:
        log_lines.append("---- Active scan ----")
        ascan_id = zap.ascan.scan(target_url)
        while int(zap.ascan.status(ascan_id)) < 100:
            time.sleep(poll_interval)
        log_lines.append("Active scan finished.")
 
    log_path = OUTPUT_DIR / f"{base_name}.log"
    log_path.write_text("\n".join(log_lines) + "\n", encoding="utf-8")
 
    # 3. 取得 alerts：把 ZAP 原始的 alert 清單存成 raw json，保留完整欄位
    #    （跟 nmap 的 -oX、binwalk 的 .txt 一樣，都是「原始證據層」）
    alerts = zap.core.alerts(baseurl=target_url)
    raw_json_path = OUTPUT_DIR / f"{base_name}_raw.json"
    import json as _json
    raw_json_path.write_text(
        _json.dumps(alerts, indent=2, ensure_ascii=False), encoding="utf-8"
    )
 
    return str(raw_json_path), str(log_path)
 
 
def parse_zap_alerts(alerts: list[dict]) -> list[dict]:
    results = []
    for alert in alerts:
        risk = alert.get("risk", "Informational")
        results.append(make_finding(
            category="webapp",
            source="zap",
            target=alert.get("url", ""),
            severity="info",  # 收集層統一給 info，跟 nmap/binwalk 一致；真正的
                               # 風險判斷交給後面的合規判讀層根據 detail 重新評估
            title=alert.get("alert", alert.get("name", "")),
            detail={
                "param": alert.get("param", ""),
                "description": alert.get("description", "")[:200],
                "cweid": alert.get("cweid", ""),
                "zap_risk": RISK_TO_ZAP_RISK.get(risk, "info"),  # ZAP 自己的判斷，保留備查
            },
        ))
    return results
 
 
def run_scan(
    url: str,
    zap_api_url: str = DEFAULT_ZAP_API_URL,
    active_scan: bool = True,
    auto_start: bool = False,
) -> list[dict]:
    """
    完整跑一次 ZAP 掃描並回傳統一格式的 findings。
    設計理由跟 nmap_scan.run_scan / firmware_scan.run_scan 一致：
    失敗時丟出例外，交給呼叫端（CLI 的 main() 或 orchestrator）處理。
 
    auto_start=False（預設）：daemon 沒開就直接失敗，適合你會連續測試
    多個目標、想自己控制 daemon 什麼時候開/關的情境，效率最高。
 
    auto_start=True：偵測到 daemon 沒開才自動啟動，掃描結束後只關掉
    「自己啟動的那個」——如果偵測到 daemon 本來就在跑（你自己手動開的），
    完全不會去動它，避免誤殺你原本還想用的 daemon。
    """
    check_zapv2_installed()
    target_url = validate_target_url(url)
 
    daemon_proc = None
    if auto_start and not is_zap_reachable(zap_api_url):
        print("[zap] 偵測不到 ZAP daemon，嘗試自動啟動...")
        daemon_proc = start_zap_daemon(zap_api_url)
        try:
            wait_for_zap_ready(zap_api_url)
        except ZapConnectionError:
            daemon_proc.terminate()
            raise
        print("[zap] ZAP daemon 已就緒。")
 
    try:
        zap = connect_zap(zap_api_url)  # 連不上時丟 ZapConnectionError
 
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        host = urlparse(target_url).netloc.replace(":", "_")
        base_name = f"zap_{host}_{ts}"
 
        raw_json_file, log_file = run_zap_scan(
            zap, target_url, base_name, active_scan=active_scan
        )
 
        print("[zap] Scan finished.")
        print_file_status("RAW_JSON", raw_json_file)
        print_file_status("LOG", log_file)
 
        if not Path(raw_json_file).exists():
            return []
 
        import json as _json
        alerts = _json.loads(Path(raw_json_file).read_text(encoding="utf-8"))
        findings = parse_zap_alerts(alerts)
 
        json_file = save_findings_json(findings, base_name)
        print_file_status("JSON", json_file)
        print_findings(findings, empty_message="No alerts found.")
 
        return findings
    finally:
        # 只關掉自己剛剛啟動的 daemon；daemon_proc 是 None 代表
        # 這次掃描用的是「本來就在跑」的 daemon，不去動它。
        if daemon_proc is not None:
            print("[zap] 掃描結束，關閉自動啟動的 ZAP daemon...")
            daemon_proc.terminate()
            try:
                daemon_proc.wait(timeout=15)
            except subprocess.TimeoutExpired:
                daemon_proc.kill()
 
 
def main():
    parser = argparse.ArgumentParser(description="Web app vulnerability scanner (OWASP ZAP wrapper)")
    parser.add_argument("url", help="Target URL, e.g. http://192.168.1.1:8080")
    parser.add_argument(
        "--zap-api-url", default=DEFAULT_ZAP_API_URL,
        help=f"ZAP daemon API URL (default: {DEFAULT_ZAP_API_URL})"
    )
    parser.add_argument(
        "--no-active-scan", action="store_true",
        help="只做 spider，不送出攻擊性請求（適合尚未取得測試授權時的初步盤點）"
    )
    parser.add_argument(
        "--auto-start", action="store_true",
        help="偵測不到 ZAP daemon 時自動啟動，掃描結束後自動關閉（只關掉自己啟動的那個）"
    )
    args = parser.parse_args()
 
    try:
        run_scan(
            args.url,
            zap_api_url=args.zap_api_url,
            active_scan=not args.no_active_scan,
            auto_start=args.auto_start,
        )
    except ImportError as e:
        print(f"Error: {e}")
        sys.exit(1)
    except ValueError as e:
        print(f"Error: {e}")
        sys.exit(1)
    except FileNotFoundError as e:
        print(f"Error: {e}")
        sys.exit(1)
    except ZapConnectionError as e:
        print(f"Error: {e}")
        print("請確認 ZAP daemon 已啟動，例如：zaproxy -daemon -port 8080 -config api.disablekey=true")
        print("或加上 --auto-start 讓程式自動幫你啟動。")
        sys.exit(1)
 
 
if __name__ == "__main__":
    main()