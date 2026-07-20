import argparse
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
 
# ZAP daemon 例外觸發
class ZapConnectionError(Exception):
    pass
 
# ZAP 的 risk 分級直接對應到我們的 severity 欄位，統一轉小寫跟其他模組一致。
RISK_TO_SEVERITY = {
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
            severity=RISK_TO_SEVERITY.get(risk, "info"),
            title=alert.get("alert", alert.get("name", "")),
            detail={
                "param": alert.get("param", ""),
                "description": alert.get("description", "")[:200],
                "cweid": alert.get("cweid", ""),
            },
        ))
    return results
 
 
def run_scan(url: str, zap_api_url: str = DEFAULT_ZAP_API_URL, active_scan: bool = True,) -> list[dict]:
    """
    完整跑一次 ZAP 掃描並回傳統一格式的 findings。
    設計理由跟 nmap_scan.run_scan / firmware_scan.run_scan 一致：
    失敗時丟出例外，交給呼叫端（CLI 的 main() 或 orchestrator）處理。
    """
    check_zapv2_installed()
    target_url = validate_target_url(url)
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
    args = parser.parse_args()
 
    try:
        run_scan(args.url, zap_api_url=args.zap_api_url, active_scan=not args.no_active_scan)
    except ImportError as e:
        print(f"Error: {e}")
        sys.exit(1)
    except ValueError as e:
        print(f"Error: {e}")
        sys.exit(1)
    except ZapConnectionError as e:
        print(f"Error: {e}")
        print("請確認 ZAP daemon 已啟動，例如：zap.sh -daemon -port 8080 -config api.disablekey=true")
        sys.exit(1)
 
 
if __name__ == "__main__":
    main()