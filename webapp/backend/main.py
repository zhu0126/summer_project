#!/usr/bin/env python3
"""
FastAPI 後端：把 project.py 的 run_pipeline() 包成 HTTP API，供前端呼叫。

單一使用者、本機執行的假設：同一時間只允許一個掃描工作在跑（用一個
全域鎖 + 單一 job 記錄），不做多工作佇列。這是刻意的簡化——多個掃描
同時跑會讓 stdout 擷取、輸出資料夾切換（common.get_output_dir()/
set_output_dir() 是全域狀態，不是 thread-local）互相干擾，要做對
「多工作並行」需要更大的重構（例如每個 job 開獨立 process），對
「先在本地跑起來」這個目標來說不是必要的第一步。
"""
import shutil
import sys
import threading
import uuid
from pathlib import Path

from fastapi import FastAPI, UploadFile, Form, File, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware

# 讓 backend/main.py 能 import 到專案根目錄下的 core/、scanners/ 套件。
# 目錄結構假設：<專案根>/webapp/backend/main.py，往上三層就是專案根。
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from core import project  # noqa: E402
from core import common  # noqa: E402
from core import pentest_planner  # noqa: E402
from scanners import nmap_scan  # noqa: E402
from scanners import zap_scan  # noqa: E402

# 專案根目錄（backend/main.py 往上兩層）。用絕對路徑而不是讓
# set_output_dir() 用相對路徑「output」，是因為相對路徑會跟著
# uvicorn 啟動時的工作目錄走——如果從 webapp/backend/ 底下啟動，
# 輸出會意外跑到 webapp/backend/output/，跟透過 CLI（在專案根目錄
# 執行 python3 -m core.project）產生的 output/ 分散在兩個不同地方，
# 導致同一個工具、不同執行方式的輸出資料夾不一致。
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent

UPLOAD_DIR = Path(__file__).resolve().parent / "uploads"
UPLOAD_DIR.mkdir(exist_ok=True)

FRONTEND_DIR = Path(__file__).resolve().parent.parent / "frontend"

app = FastAPI(title="IoT Compliance Scanner API")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # 本機單人使用的工具，先簡化；要對外部署時務必收斂
    allow_methods=["*"],
    allow_headers=["*"],
)

_lock = threading.Lock()
_job: dict | None = None  # 目前唯一的一份 job 狀態（單一工作佇列，不支援並行）

# 掃描進度的階段清單跟顯示用標籤。跟 core/project.py 的 progress_cb
# 呼叫時用的 stage 字串一一對應——這裡只負責「怎麼顯示」，實際
# 「什麼時候切換到哪個狀態」的邏輯留在 project.py 那邊決定。
STAGE_LABELS = {
    "nmap": "Network scan (nmap)",
    "firmware": "Firmware scan (binwalk)",
    "zap": "Web app scan (ZAP)",
    "analysis": "法規 Mapping",
    "report": "報告產出",
}


def _build_initial_stages(ip: str | None, firmware: str | None, url: str | None, make_report: bool) -> dict:
    """
    掃描開始前就能決定每個階段是否會執行：有沒有提供對應目標、
    有沒有勾選產生報告。不會執行的階段直接標成 skipped（不執行），
    不用等 pipeline 跑到那一步才知道會跳過。
    """
    return {
        "nmap": {"label": STAGE_LABELS["nmap"], "status": "pending" if ip else "skipped"},
        "firmware": {"label": STAGE_LABELS["firmware"], "status": "pending" if firmware else "skipped"},
        "zap": {"label": STAGE_LABELS["zap"], "status": "pending" if url else "skipped"},
        "analysis": {"label": STAGE_LABELS["analysis"], "status": "pending"},
        "report": {"label": STAGE_LABELS["report"], "status": "pending" if make_report else "skipped"},
    }


def _run_job(job_ref: dict, params: dict) -> None:
    def _progress_cb(stage: str, status: str) -> None:
        if stage in job_ref["stages"]:
            job_ref["stages"][stage]["status"] = status

    try:
        result = project.run_pipeline(progress_cb=_progress_cb, **params)
        job_ref["status"] = "done"
        job_ref["result"] = result
    except Exception as e:
        job_ref["status"] = "error"
        job_ref["error"] = str(e)
        # pipeline 中途拋出例外時，還停在 pending/running 的階段一律標成
        # error，不然前端會停在「進行中」轉圈圈，看起來像卡住而不是失敗。
        for stage in job_ref["stages"].values():
            if stage["status"] in ("pending", "running"):
                stage["status"] = "error"
    finally:
        # 清掉這次上傳的韌體暫存檔（如果有），pipeline 執行完已經不需要
        # 原始檔案了，避免 uploads/ 資料夾一直累積舊檔案佔用磁碟空間。
        firmware_path = params.get("firmware")
        if firmware_path and Path(firmware_path).is_file():
            try:
                Path(firmware_path).unlink()
            except OSError:
                pass


@app.get("/api/options")
def get_options():
    """
    回傳前端下拉選單要用的合法選項，直接來源就是後端已經定義好的
    集合，前端不需要自己硬編一份可能跟後端邏輯對不上的清單。
    """
    return {
        "timing": sorted(nmap_scan.VALID_TIMING_TEMPLATES),
        "scan_technique": sorted(nmap_scan.SCAN_TECHNIQUES),
        "script_category": sorted(nmap_scan.VALID_SCRIPT_CATEGORIES),
        "zap_api_url_default": zap_scan.DEFAULT_ZAP_API_URL,
    }


@app.post("/api/scan")
async def start_scan(
    ip: str = Form(""),
    ports: str = Form(""),
    timing: str = Form("T3"),
    os_detection: bool = Form(False),
    scan_technique: str = Form(""),
    host_discovery: bool = Form(False),
    script_category: str = Form(""),
    extract: bool = Form(False),
    matryoshka: bool = Form(False),
    run_as_root: bool = Form(False),
    url: str = Form(""),
    zap_api_url: str = Form(""),
    active_scan: bool = Form(True),
    zap_auto_start: bool = Form(False),
    make_report: bool = Form(False),
    operator: str = Form("unknown"),
    org: str = Form(""),
    title: str = Form(""),
    firmware_file: UploadFile | None = File(None),
):
    global _job

    if not (ip.strip() or url.strip() or (firmware_file is not None and firmware_file.filename)):
        raise HTTPException(status_code=400, detail="至少要提供 IP、韌體檔案、URL 其中一項目標。")

    if not _lock.acquire(blocking=False):
        raise HTTPException(status_code=409, detail="已經有一個掃描工作正在執行，請稍候再試。")

    try:
        firmware_path = None
        if firmware_file is not None and firmware_file.filename:
            # 檔名只取 basename，避免上傳檔名帶路徑片段（如 "../../x"）
            # 被拿來當實際寫入路徑，寫到 uploads/ 資料夾以外的地方。
            safe_filename = Path(firmware_file.filename).name
            firmware_path = str(UPLOAD_DIR / safe_filename)
            with open(firmware_path, "wb") as f:
                shutil.copyfileobj(firmware_file.file, f)

        job_id = uuid.uuid4().hex[:12]
        job_ref = {
            "id": job_id,
            "status": "running",
            "stages": _build_initial_stages(ip.strip() or None, firmware_path, url.strip() or None, make_report),
            "result": None,
            "error": None,
        }
        _job = job_ref

        params = dict(
            ip=ip.strip() or None,
            ports=ports.strip() or None,
            timing=timing,
            os_detection=os_detection,
            vuln_scripts=False,  # 前端統一用 script_category 表達，不重複開放兩種寫法
            scan_technique=scan_technique or None,
            host_discovery=host_discovery,
            script_category=script_category or None,
            firmware=firmware_path,
            extract=extract,
            matryoshka=matryoshka,
            run_as_root=run_as_root,
            url=url.strip() or None,
            zap_api_url=zap_api_url.strip() or zap_scan.DEFAULT_ZAP_API_URL,
            active_scan=active_scan,
            zap_auto_start=zap_auto_start,
            make_report=make_report,
            operator=operator.strip() or "unknown",
            org=org.strip(),
            title=title.strip() or None,
            output_root=PROJECT_ROOT / "output",
        )

        def _target():
            try:
                _run_job(job_ref, params)
            finally:
                _lock.release()

        threading.Thread(target=_target, daemon=True).start()
        return {"job_id": job_id}
    except Exception:
        _lock.release()
        raise


@app.get("/api/scan/current")
def get_current_scan():
    if _job is None:
        raise HTTPException(status_code=404, detail="尚未執行過任何掃描。")
    return _job


@app.post("/api/pentest-plan")
def generate_pentest_plan(use_llm: bool = Form(True)):
    """
    Compliance 頁「產生測試計畫」按鈕呼叫的端點：對最近一次完成的掃描結果
    （_job["result"]["merged_findings"]）跑 pentest_planner.build_test_plan()，
    回傳給前端直接顯示可複製執行的 scanners/claude_pentest_scan.py 指令。

    只讀取既有掃描結果，不會觸發新掃描；build_test_plan() 本身只產生「計畫
    與指令字串」，不執行任何攻擊性行為，所以這裡不需要跟 /api/scan 一樣搶
    _lock——它不寫檔、不碰 common.get_output_dir() 那份全域輸出路徑狀態，
    跟一次正在跑的掃描不會互相干擾。use_llm=True 時會呼叫 Claude 幫每個
    活目標推導測試目標，需要 ANTHROPIC_API_KEY；沒設定時 build_test_plan()
    會自動降級成通用樣板，不會噴錯。
    """
    if _job is None or _job.get("result") is None:
        raise HTTPException(status_code=404, detail="尚未有完成的掃描結果，請先完成一次掃描。")

    merged_findings = _job["result"].get("merged_findings") or []
    plan = pentest_planner.build_test_plan(merged_findings, use_llm=use_llm)
    return {"plan": plan}


@app.get("/api/download/{filename}")
def download_file(filename: str):
    if _job is None or _job.get("result") is None:
        raise HTTPException(status_code=404, detail="沒有可下載的檔案。")

    run_dir = Path(_job["result"]["run_dir"]).resolve()
    # 防止路徑穿越（filename 裡塞 "../" 之類的片段）：只取檔名本身，
    # 並確認最終路徑真的落在這次執行的輸出資料夾底下。
    target = (run_dir / Path(filename).name).resolve()
    if run_dir not in target.parents and target != run_dir:
        raise HTTPException(status_code=400, detail="不合法的檔案路徑。")
    if not target.is_file():
        raise HTTPException(status_code=404, detail="找不到這個檔案。")

    return FileResponse(target, filename=target.name)


# 靜態前端掛在最後，確保 /api/* 路由優先於這個 catch-all 生效
app.mount("/", StaticFiles(directory=str(FRONTEND_DIR), html=True), name="frontend")