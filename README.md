# IoT Compliance Scanner

一個整合多個掃描工具的 IoT 產品資安合規盤點系統，結合規則比對、RAG 語意檢索、以及 AI 研判建議，自動生成符合法規（CRA）的合規報告。

## 功能特色

### 三種掃描模式

- **Network Scan (nmap)** — 掃描網路上的開放埠、服務、OS 指紋
- **Firmware Scan (binwalk)** — 解析固件中的檔案格式、密碼學金鑰、已知漏洞簽名
- **Web App Scan (ZAP)** — 自動化滲透測試、爬蟲、主動攻擊測試

### 智能分析層

1. **規則比對** — 內建 CWE/CRA 對應規則，直接判定合規狀態
2. **RAG 語意檢索** — 
   - 使用 Qdrant 向量資料庫存儲 CWE 弱點、CRA 法規條文、IEC 62443 要求
   - 混合搜尋：dense embedding (fastembed) + BM25 關鍵字，RRF 合併排名
   - 規則未涵蓋時提供候選參考資料

   三個知識庫的分工：

   | 知識庫 | 回答的問題 | 效力 |
   |---|---|---|
   | CWE | 這是什麼弱點？ | 分類參考 |
   | IEC 62443-4-2 | 元件技術上該具備什麼能力？ | 自願性標準 |
   | CRA | 法律上為什麼非做不可？ | 具強制力的歐盟法規 |

   IEC 62443 的另一部 **4-1（開發流程要求）** 不參與逐筆檢索——掃描測的是
   成品現狀，4-1 規範的是開發流程，兩者對不上。改成整場掃描查一次，
   在報告獨立一節呈現。
3. **AI 研判建議**（可選）—
   - 調用 Gemini LLM 為待複核項目撰寫研判意見
   - 強制引用驗證（只允許引用提供的參考資料，防止幻覺）
   - 需設定 `GEMINI_API_KEY` 環境變數

### 合規報告

- 自動產生 Markdown 報告，分 matched/needs_review 兩大區塊
- 自動轉換 PDF 版本（可選填單位名稱、報告標題）
- 免責聲明明確標示：AI 研判僅為參考意見，不等同最終法律判定

## 系統架構

```
掃描結果 (findings.json)
    ↓
[keyword_rules.py] ← 規則比對
    ├─ matched → 直接判定
    └─ needs_review → 進入 RAG 路徑
        ↓
[retrieve_cwe/iec/cra_hybrid()] ← Qdrant + fastembed
        ↓
[rag_context.py] ← 組裝 LLM prompt
        ↓
[llm_advisor.py] ← 可選：Gemini API 調用
        ↓
[report.py] ← Jinja2 樣板渲染
        ↓
output/report_*.md + report_*.pdf
```

## 安裝

### 前置要求

- Python 3.9+
- nmap（網路掃描模組）
- binwalk（固件掃描模組，含 7z/tar/gzip 等解壓工具）
- ZAP daemon（Web 應用掃描，可選；支持自動啟動）

### Python 依賴

```bash
pip install -r requirements.txt
```

### 知識庫初始化

CWE/CRA 資料庫需要一次性建立索引：

```bash
# CWE 知識庫
python -m cwe_kb.fetch_cwe

# CRA 知識庫
python -m cra_kb.fetch_cra
```

這些指令會從 MITRE（CWE）及 EUR-Lex（CRA）下載最新資料、建立 Qdrant collection。

#### IEC 62443 知識庫（需自備標準 PDF）

IEC 62443 是**付費標準**，沒有合法的公開全文來源，因此 `fetch_iec.py`
**不做任何下載**，一律要求你指定自己授權取得的 PDF：

```bash
python -m iec_kb.fetch_iec --pdf /path/to/iec62443-4-2.pdf --part 4-2 --verify
```

```bash
python -m iec_kb.fetch_iec --pdf /path/to/iec62443-4-1.pdf --part 4-1 --verify
```

```bash
python -m iec_kb.build_iec_index
```

`--part` 在檔名含 `62443-4-2` 之類字樣時可省略。`--verify` 會核對條目數量
（4-1 共 47 條、4-2 共 88 條）、編號唯一性，並確認授權浮水印已剝除乾淨。

解析器已處理三種 PDF 版面陷阱：

- **授權浮水印含個資**（被授權人姓名、公司、訂單編號）。4-2 是頁尾水平文字、
  4-1 是旋轉 90 度的側邊欄文字，兩種都會剝除，不會進到知識庫或送往 LLM API。
- **雙語版**（檔名尾碼 `b`）的法文半部條號跟英文完全相同，不切掉會讓每條被
  解析兩次、下游靜默覆蓋。
- **目錄折行**：標題太長時目錄第一行不帶點狀引導線，會被誤判成真正的條目。

> ⚠️ `iec_kb/iec_data/` 內含標準原文，已列入 `.gitignore`，**請勿提交或散布**。

### 環境變數設置（可選）

建立 `.env` 檔案（已在 `.gitignore`）：

```bash
GEMINI_API_KEY=your-actual-key-here
GEMINI_MODEL=gemini-2.5-flash
```

金鑰可從 [Google AI Studio](https://aistudio.google.com/app/apikey) 免費申請。

## 使用

### CLI（命令列）

#### 網路掃描 + 報告

```bash
# 基礎用法
python -m core.project --ip 192.168.1.1 --report

# 加入 LLM 研判建議
python -m core.project --ip 192.168.1.1 --report --llm

# 完整示例：指定操作者、PDF 標題等
python -m core.project \
  --ip 192.168.1.1 \
  --report \
  --llm \
  --operator "你的名字" \
  --org "單位名稱" \
  --title "合規盤點報告"
```

#### 固件掃描

```bash
python -m core.project \
  --firmware firmware.bin \
  --extract \
  --report
```

#### Web 應用掃描

```bash
# ZAP daemon 需另行啟動（或加 --zap-auto-start）
python -m core.project \
  --url http://target:8080 \
  --report \
  --zap-auto-start
```

#### 組合掃描

```bash
python -m core.project \
  --ip 192.168.1.0/24 \
  --firmware firmware.bin \
  --url http://target:8080 \
  --report --llm
```

#### nmap 進階選項

```bash
python -m core.project \
  --ip 192.168.1.1 \
  --ports 1-1000 \
  --timing T4 \
  --script-category vuln \
  --os-detection \
  --report
```

### Web UI（可視化）

啟動後端伺服器：

```bash
cd webapp/backend
python -m uvicorn main:app --reload
```

在瀏覽器開啟 `http://localhost:8000` — 三種掃描工具為收合面板，點擊標題展開參數區、配置後點「執行掃描」。

- 掃描進度實時顯示在右側
- 完成後自動下載 JSON、Markdown、PDF 報告

### 獨立產報告

已有 findings JSON 的情況下：

```bash
# 不用 LLM
python -m core.report output/combined_20260812_xxxxx.json

# 加上 LLM 研判
python -m core.report output/combined_20260812_xxxxx.json --llm
```

## 目錄結構

```
.
├── core/                      # 核心分析層
│   ├── project.py            # Orchestrator（CLI、Web API 入口）
│   ├── analysis.py           # 規則比對 + RAG 檢索 + LLM 研判
│   ├── keyword_rules.py      # 規則資料庫（CWE ID 對應）
│   ├── report.py             # 報告產生（Jinja2 樣板）
│   ├── rag_context.py        # context 格式化（LLM 用）
│   ├── llm_advisor.py        # Gemini LLM 呼叫 + 引用驗證
│   └── common.py             # 通用函式（finding 結構、檔案 I/O）
├── scanners/                 # 掃描模組
│   ├── nmap_scan.py
│   ├── firmware_scan.py
│   └── zap_scan.py
├── cwe_kb/                   # CWE 知識庫（Qdrant）
│   ├── fetch_cwe.py          # 下載 MITRE CWE、建立索引
│   └── retrieve_cwe.py       # 混合搜尋（dense + sparse）
├── cra_kb/                   # CRA 知識庫（Qdrant）
│   ├── fetch_cra.py          # 下載 EUR-Lex CRA、建立索引
│   └── retrieve_cra.py       # 混合搜尋
├── iec_kb/                   # IEC 62443 知識庫（Qdrant）
│   ├── fetch_iec.py          # 解析自備的標準 PDF（不做下載）
│   ├── build_iec_index.py    # 建 iec62443_4_1 / iec62443_4_2 兩個 collection
│   ├── retrieve_iec.py       # 混合搜尋（帶 part 參數）
│   └── iec_data/             # 標準原文，已 gitignore
├── templates/                # Jinja2 樣板
│   └── report.md.j2          # Markdown 報告樣板
├── webapp/                   # Web 前後端
│   ├── backend/main.py       # FastAPI 伺服器
│   └── frontend/index.html   # 單頁應用
├── test/                     # 單元測試
│   └── test_llm_advisor.py   # LLM 層離線測試（25 項）
├── md_to_pdf/                # Markdown → PDF 轉換
├── output/                   # 掃描結果、報告產出目錄
├── .env                      # 環境變數（API 金鑰）
├── .gitignore                # Git 忽略清單
└── requirements.txt          # Python 依賴清單
```

## 配置

### CWE/CRA 知識庫

- **資料來源**
  - CWE：MITRE CWE Top 25、Extended 版本（JSON API）
  - CRA：EUR-Lex 官方 XML（Regulation (EU) 2024/2847）
- **儲存位置**：本地 Qdrant 實例（`~/.qdrant/` 或環境變數 `QDRANT_PATH`）
- **嵌入模型**：`BAAI/bge-small-en-v1.5`（fastembed）
- **索引配置**：dense (1536-dim) + sparse (BM25) hybrid

### 前端表單項目

三個掃描工具面板預設收合（點擊展開）；Report 面板固定開啟，包含：

- 產生報告勾選
- 操作者名稱
- 單位名稱（PDF 頁首頁尾）
- 報告標題（PDF 書籤）

## API 端點（Web 後端）

| 方法 | 端點 | 說明 |
|------|------|------|
| GET | `/api/options` | 掃描工具下拉選單選項（timing、scan_technique 等） |
| POST | `/api/scan` | 啟動掃描工作（FormData：ip, firmware_file, url 等） |
| GET | `/api/scan/current` | 查詢當前掃描狀態（日誌、進度） |
| GET | `/api/download/{filename}` | 下載報告/JSON |

## 測試

```bash
# 離線單元測試（LLM 層、context 組裝）
python test/test_llm_advisor.py

# 手動測試 LLM 引用驗證
python -m core.llm_advisor
```

所有測試無外部依賴（不需 Qdrant、不需 API 金鑰）。

## 降級設計（可靠性）

系統採用「fail-soft」策略，任何選用依賴失敗都不中斷報告產出：

| 失敗情況 | 行為 |
|---------|------|
| Qdrant 連不上 | 退化為純 BM25（sparse-only）排名，仍產出報告 |
| CWE/CRA/IEC 索引未建立 | 該知識庫候選為空，其他兩個照常 |
| 未建 IEC 索引（無標準 PDF） | 62443 候選與開發流程對照整節略過 |
| `rank-bm25` 未安裝 | 退化為純向量（dense-only）排名 |
| Gemini API 金鑰未設/無效 | LLM 段落略過，報告仍可閱讀 |
| PDF 轉換失敗 | Markdown 報告正常產出 |
| ZAP daemon 不存在 | 加 `--zap-auto-start` 自動啟動；或略過 Web 掃描 |

## 已知限制

1. **Web UI 單一使用者** — 同一時間僅允許一個掃描工作執行（防止 stdout 和檔案 I/O 競爭）
2. **LLM 上下文長度** — 超長候選資料會被截斷至 12KB，防止 token 超標
3. **CRA 條文解析** — EUR-Lex XML 格式變動時需更新 `fetch_cra.py`
4. **nmap 依賴** — 網路掃描必須本機安裝 nmap；Docker 容器化可考慮 FROM nmap/nmap
5. **IEC 62443 需自備 PDF** — 付費標準，無法隨專案散布；PDF 版面若改版
   （不同 edition）可能需要調整 `fetch_iec.py` 的 `PART_SPECS` regex
6. **62443-4-1 無法由掃描驗證** — 開發流程要求既不能被掃描結果證明也不能
   被否證，報告該節僅是自評起點，且只列前 8 條（全文共 47 條）

## 故障排除

### 「CWE 候選查詢失敗」

```
[analysis] CWE 候選查詢失敗，略過（...）
```

**解決**：
```bash
python -m cwe_kb.fetch_cwe  # 重新建立索引
```

### LLM 段落未出現

檢查：
```bash
python -c "from core.llm_advisor import is_available; print(is_available())"
```

結果為 `False` 的話：
- 確認 `pip install google-genai`
- 確認 `.env` 裡有 `GEMINI_API_KEY=...`
- 確認 API 金鑰有效（去 AI Studio 測試）

### PDF 轉換失敗

```bash
pip install markdown beautifulsoup4 weasyprint
```

注意：`weasyprint` 需要 libffi、libjpeg 等系統庫，Linux 用 apt/yum、macOS 用 brew、Windows 用 Visual C++ Build Tools。

## 開發

### 新增掃描工具

在 `scanners/` 建立 `new_tool_scan.py`，實現 `run_scan(target, **kwargs) -> list[dict]` 介面，返回 findings 清單。

findings 結構（必需欄位）：
```python
{
    "finding_id": str,      # UUID
    "category": str,        # "network" / "firmware" / "webapp" / custom
    "source": str,          # "nmap" / "binwalk" / "zap" / custom
    "target": str,          # IP / 檔案路徑 / URL
    "title": str,           # 項目標題
    "severity": str,        # "critical" / "high" / "medium" / "low" / "info"
    "detail": dict,         # 工具特定欄位
}
```

### 擴展規則

編輯 `core/keyword_rules.py`：新增規則到 `KEYWORD_RULES` 清單，對應 CWE ID 和 CRA 條號。

## 貢獻

Bug report、建議功能、PR 皆歡迎！

## 授權

MIT License（待確認）

## 聯絡

- 問題回報：GitHub Issues
- 技術討論：GitHub Discussions

---

**最後更新**：2026-08-13  
**版本**：0.1.0-alpha
