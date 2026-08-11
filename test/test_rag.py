from common import make_finding
from analysis import analyze_findings

test_findings = [
    # SMB — 老牌漏洞溫床（EternalBlue 這類），nmap 常見服務名
    make_finding("network", "nmap", "192.168.1.10", "info", "tcp/445 microsoft-ds",
                 detail={"service": "microsoft-ds", "state": "open"}),

    # VNC — 遠端桌面，很多裝置沒設密碼或用弱密碼
    make_finding("network", "nmap", "192.168.1.10", "info", "tcp/5900 vnc",
                 detail={"service": "vnc", "state": "open"}),

    # Redis — 預設沒有驗證機制，對外開放常被拿來當跳板
    make_finding("network", "nmap", "192.168.1.10", "info", "tcp/6379 redis",
                 detail={"service": "redis", "state": "open"}),

    # MQTT — IoT 裝置常用的訊息協定，很多實作預設不驗證
    make_finding("network", "nmap", "192.168.1.10", "info", "tcp/1883 mqtt",
                 detail={"service": "mqtt", "state": "open"}),

    # Modbus — 工控/IoT 協定，協定設計本身就沒有驗證機制
    make_finding("network", "nmap", "192.168.1.10", "info", "tcp/502 modbus",
                 detail={"service": "modbus", "state": "open"}),

    # RDP — 遠端桌面，常見暴力破解/已知漏洞目標
    make_finding("network", "nmap", "192.168.1.10", "info", "tcp/3389 ms-wbt-server",
                 detail={"service": "ms-wbt-server", "state": "open"}),

    # 韌體：U-Boot bootloader 字串，不在 FIRMWARE_RULES 的關鍵字裡
    make_finding("firmware", "binwalk", "fw.bin", "info", "U-Boot version string",
                 detail={"matched_keyword": None}),

    # 韌體：BusyBox 版本字串，常見韌體元件，可能對應已知 CVE
    make_finding("firmware", "binwalk", "fw.bin", "info", "BusyBox v1.19.4",
                 detail={"matched_keyword": None}),
]

for r in analyze_findings(test_findings):
    print(r["status"], "|", r["title"], "|", r.get("cwe_id"), "|", 
          (r.get("cra_reference") or "")[:60])