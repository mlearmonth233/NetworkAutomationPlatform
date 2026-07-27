from __future__ import annotations

import asyncio
import json
import os
import sys
import threading
import uuid
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Form, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from .collector import CollectionOptions, Device, run_collection_job
from .network_tools import run_bulk_tests


def _resolve_bundle_dir() -> Path:
    """Where templates/ and static/ live: the PyInstaller extraction dir when
    frozen into an exe, otherwise the project root during normal development."""
    if getattr(sys, "frozen", False):
        return Path(getattr(sys, "_MEIPASS", Path(sys.executable).resolve().parent))
    return Path(__file__).resolve().parent.parent


def _resolve_storage_root() -> Path:
    """Where job output is written. A packaged exe may be double-clicked from
    anywhere (Desktop, a USB stick, Program Files) so job data is kept in a
    stable, always-writable per-user folder instead of next to the program."""
    if getattr(sys, "frozen", False):
        base = Path(os.environ.get("LOCALAPPDATA") or Path.home())
        return base / "NetworkAutomationStudio" / "storage" / "jobs"
    return Path(__file__).resolve().parent.parent / "storage" / "jobs"


BASE_DIR = _resolve_bundle_dir()
STORAGE_ROOT = _resolve_storage_root()
STORAGE_ROOT.mkdir(parents=True, exist_ok=True)
JOB_META_FILENAME = "job_meta.json"

app = FastAPI(title="Network Automation Studio", version="2.3.0")
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")
templates = Jinja2Templates(directory=BASE_DIR / "templates")

jobs: dict[str, dict[str, Any]] = {}
job_controls: dict[str, dict[str, Any]] = {}
subscribers: dict[str, set[asyncio.Queue]] = {}
main_loop: asyncio.AbstractEventLoop | None = None


def write_job_meta(job_id: str) -> None:
    """Best-effort persistence of job status/results (never credentials) so
    job history survives an app restart."""
    job = jobs.get(job_id)
    if not job:
        return
    meta = {key: value for key, value in job.items() if key != "events"}
    job_dir = STORAGE_ROOT / job_id
    try:
        job_dir.mkdir(parents=True, exist_ok=True)
        (job_dir / JOB_META_FILENAME).write_text(json.dumps(meta, default=str), encoding="utf-8")
    except OSError:
        pass


def load_job_history_from_disk() -> None:
    if not STORAGE_ROOT.exists():
        return
    for job_dir in STORAGE_ROOT.iterdir():
        meta_path = job_dir / JOB_META_FILENAME
        if not meta_path.is_file():
            continue
        try:
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        job_id = meta.get("id") or job_dir.name
        if meta.get("status") in ("RUNNING", "QUEUED"):
            meta["status"] = "INTERRUPTED"
        meta.setdefault("events", [])
        jobs[job_id] = meta


def job_summary(job: dict[str, Any]) -> dict[str, Any]:
    """Small, JSON-safe summary for the history list (no live event log)."""
    results = job.get("results") or []
    return {
        "id": job["id"],
        "status": job["status"],
        "created_at": job.get("created_at"),
        "completed_at": job.get("completed_at"),
        "device_count": len(job.get("devices", [])),
        "devices": job.get("devices", []),
        "successful": sum(1 for r in results if r.get("status") == "SUCCESS"),
        "failed": sum(1 for r in results if r.get("status") == "FAILED"),
        "cancelled": sum(1 for r in results if r.get("status") == "CANCELLED"),
        "has_zip": bool(job.get("zip_path")) and Path(job["zip_path"]).is_file(),
        "has_workbook": bool(job.get("workbook_path")) and Path(job["workbook_path"]).is_file(),
        "has_results_csv": bool(job.get("results_path")) and Path(job["results_path"]).is_file(),
    }


@app.on_event("startup")
async def startup_event() -> None:
    global main_loop
    main_loop = asyncio.get_running_loop()
    load_job_history_from_disk()


def publish(job_id: str, event: dict[str, Any]) -> None:
    jobs[job_id].setdefault("events", []).append(event)
    jobs[job_id]["events"] = jobs[job_id]["events"][-300:]
    if main_loop is None:
        return

    def _send() -> None:
        for queue in subscribers.get(job_id, set()).copy():
            try:
                queue.put_nowait(event)
            except asyncio.QueueFull:
                pass

    main_loop.call_soon_threadsafe(_send)


def parse_devices(raw: str) -> list[Device]:
    try:
        rows = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=400, detail="Invalid device data") from exc

    if not isinstance(rows, list) or not rows:
        raise HTTPException(status_code=400, detail="Add at least one device")

    devices: list[Device] = []
    for position, row in enumerate(rows, start=1):
        try:
            name = str(row.get("name") or row.get("host") or "").strip()
            host = str(row.get("host") or "").strip()
            port = int(row.get("port") or 22)
            device_type = str(row.get("device_type") or "cisco_ios").strip()
        except (AttributeError, TypeError, ValueError) as exc:
            raise HTTPException(status_code=400, detail=f"Invalid device row {position}") from exc
        if not name or not host:
            raise HTTPException(status_code=400, detail=f"Device row {position} requires name and host")
        if not 1 <= port <= 65535:
            raise HTTPException(status_code=400, detail=f"Invalid port on row {position}")
        devices.append(Device(name=name, host=host, port=port, device_type=device_type))
    return devices


@app.get("/", response_class=HTMLResponse)
async def home(request: Request) -> HTMLResponse:
    return templates.TemplateResponse("index.html", {"request": request})


@app.post("/api/jobs")
async def create_job(
    devices_json: str = Form(...),
    username: str = Form(...),
    password: str = Form(...),
    enable_secret: str = Form(""),
    concurrent_devices: int = Form(5),
    sequential_authentication: bool = Form(True),
    auth_timeout: int = Form(180),
    custom_commands_json: str = Form("[]"),
) -> JSONResponse:
    devices = parse_devices(devices_json)
    if not username.strip() or not password:
        raise HTTPException(status_code=400, detail="Username and password are required")
    if not 1 <= concurrent_devices <= 20:
        raise HTTPException(status_code=400, detail="Concurrent devices must be between 1 and 20")
    if not 30 <= auth_timeout <= 600:
        raise HTTPException(status_code=400, detail="Authentication timeout must be between 30 and 600 seconds")
    try:
        custom_commands = json.loads(custom_commands_json)
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=400, detail="Invalid custom command data") from exc
    if not isinstance(custom_commands, list):
        raise HTTPException(status_code=400, detail="Custom commands must be a list")
    cleaned_commands = []
    for value in custom_commands:
        command = str(value).strip()
        if not command:
            continue
        if not command.lower().startswith(("show ", "sh ", "terminal ")):
            raise HTTPException(status_code=400, detail=f"Only read-only show commands are allowed: {command}")
        if command not in cleaned_commands:
            cleaned_commands.append(command)
    if len(cleaned_commands) > 100:
        raise HTTPException(status_code=400, detail="A maximum of 100 custom commands is allowed")

    options = CollectionOptions()
    job_id = uuid.uuid4().hex
    jobs[job_id] = {
        "id": job_id, "status": "QUEUED",
        "created_at": datetime.now().astimezone().isoformat(), "completed_at": None,
        "devices": [asdict(device) for device in devices],
        "results": [], "events": [], "results_path": None,
        "zip_path": None, "workbook_path": None,
        "concurrent_devices": concurrent_devices,
        "sequential_authentication": sequential_authentication,
        "auth_timeout": auth_timeout,
        "custom_commands": cleaned_commands,
    }
    subscribers[job_id] = set()
    cancel_event = threading.Event()
    job_controls[job_id] = {
        "cancel_event": cancel_event,
        "active_connections": {},
        "lock": threading.Lock(),
    }
    write_job_meta(job_id)

    def complete(results, results_path: Path, workbook_path: Path, zip_path: Path, status: str) -> None:
        jobs[job_id]["status"] = status
        jobs[job_id]["completed_at"] = datetime.now().astimezone().isoformat()
        jobs[job_id]["results"] = [asdict(item) for item in results]
        jobs[job_id]["results_path"] = str(results_path)
        jobs[job_id]["workbook_path"] = str(workbook_path)
        jobs[job_id]["zip_path"] = str(zip_path)
        write_job_meta(job_id)
        job_controls.pop(job_id, None)

    def worker() -> None:
        jobs[job_id]["status"] = "RUNNING"
        write_job_meta(job_id)
        try:
            run_collection_job(
                job_id=job_id, devices=devices, username=username.strip(), password=password,
                enable_secret=enable_secret, options=options, storage_root=STORAGE_ROOT,
                notify=lambda event: publish(job_id, event), completion_callback=complete,
                concurrent_devices=concurrent_devices, custom_commands=cleaned_commands,
                sequential_authentication=sequential_authentication, auth_timeout=auth_timeout,
                cancel_event=cancel_event,
                active_connections=job_controls[job_id]["active_connections"],
                connections_lock=job_controls[job_id]["lock"],
            )
        except Exception as exc:
            jobs[job_id]["status"] = "FAILED"
            jobs[job_id]["completed_at"] = datetime.now().astimezone().isoformat()
            write_job_meta(job_id)
            job_controls.pop(job_id, None)
            publish(job_id, {"type": "log", "message": f"Job failed unexpectedly: {type(exc).__name__}: {exc}"})
            publish(job_id, {"type": "job_complete", "status": "FAILED", "successful": 0, "failed": len(devices), "cancelled": 0})

    threading.Thread(target=worker, daemon=True, name=f"collector-{job_id[:8]}").start()
    return JSONResponse({"job_id": job_id})


@app.get("/api/jobs")
async def list_jobs() -> JSONResponse:
    ordered = sorted(jobs.values(), key=lambda job: job.get("created_at") or "", reverse=True)
    return JSONResponse({"jobs": [job_summary(job) for job in ordered[:50]]})


@app.get("/api/jobs/{job_id}")
async def get_job(job_id: str) -> JSONResponse:
    job = jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return JSONResponse({key: value for key, value in job.items() if key != "events"})


@app.post("/api/jobs/{job_id}/cancel")
async def cancel_job(job_id: str) -> JSONResponse:
    job = jobs.get(job_id)
    controls = job_controls.get(job_id)
    if not job or not controls:
        raise HTTPException(status_code=404, detail="Job not found or already finished")
    if job["status"] not in ("QUEUED", "RUNNING"):
        raise HTTPException(status_code=400, detail="Job is not currently running")
    controls["cancel_event"].set()
    with controls["lock"]:
        live_connections = list(controls["active_connections"].values())
    for connection in live_connections:
        try:
            connection.disconnect()
        except Exception:
            pass
    publish(job_id, {"type": "log", "message": "Cancellation requested by user - stopping remaining devices"})
    return JSONResponse({"status": "cancelling"})


@app.get("/api/jobs/{job_id}/download")
async def download_zip(job_id: str) -> FileResponse:
    job = jobs.get(job_id)
    if not job or not job.get("zip_path"):
        raise HTTPException(status_code=404, detail="ZIP file is not available")
    return FileResponse(job["zip_path"], filename=f"catalyst-configs-{job_id[:8]}.zip")


@app.get("/api/jobs/{job_id}/technical-review.xlsx")
async def download_workbook(job_id: str) -> FileResponse:
    job = jobs.get(job_id)
    if not job or not job.get("workbook_path"):
        raise HTTPException(status_code=404, detail="Technical review workbook is not available")
    return FileResponse(job["workbook_path"], filename=f"network-technical-review-{job_id[:8]}.xlsx")


@app.get("/api/jobs/{job_id}/results.csv")
async def download_results(job_id: str) -> FileResponse:
    job = jobs.get(job_id)
    if not job or not job.get("results_path"):
        raise HTTPException(status_code=404, detail="Results file is not available")
    return FileResponse(job["results_path"], filename=f"collection-results-{job_id[:8]}.csv")


@app.get("/api/jobs/{job_id}/files")
async def list_files(job_id: str) -> JSONResponse:
    job_dir = STORAGE_ROOT / job_id
    if not job_dir.exists():
        raise HTTPException(status_code=404, detail="Job files not found")
    files = [str(path.relative_to(job_dir)) for path in job_dir.rglob("*.log")]
    return JSONResponse({"files": sorted(files)})


@app.get("/api/jobs/{job_id}/file")
async def read_file(job_id: str, path: str) -> JSONResponse:
    job_dir = (STORAGE_ROOT / job_id).resolve()
    requested = (job_dir / path).resolve()
    if job_dir not in requested.parents or not requested.is_file():
        raise HTTPException(status_code=404, detail="File not found")
    return JSONResponse({"path": path, "content": requested.read_text(encoding="utf-8", errors="replace")})


@app.post("/api/network-tests")
async def network_tests(request: Request) -> JSONResponse:
    payload = await request.json()
    raw_targets = payload.get("targets", [])
    timeout_seconds = payload.get("timeout_seconds", 2)

    if not isinstance(raw_targets, list):
        raise HTTPException(status_code=400, detail="Targets must be a list")

    targets = [str(value).strip() for value in raw_targets if str(value).strip()]
    if not targets:
        raise HTTPException(status_code=400, detail="Add at least one IP address or hostname")
    if len(targets) > 1000:
        raise HTTPException(status_code=400, detail="A maximum of 1000 targets can be tested at once")

    try:
        timeout = int(timeout_seconds)
    except (TypeError, ValueError) as exc:
        raise HTTPException(status_code=400, detail="Invalid ping timeout") from exc
    if not 1 <= timeout <= 10:
        raise HTTPException(status_code=400, detail="Ping timeout must be between 1 and 10 seconds")

    results = await asyncio.to_thread(run_bulk_tests, targets, timeout)
    return JSONResponse({"count": len(results), "results": results})


@app.websocket("/ws/jobs/{job_id}")
async def job_websocket(websocket: WebSocket, job_id: str) -> None:
    if job_id not in jobs:
        await websocket.close(code=4404)
        return
    await websocket.accept()
    queue: asyncio.Queue = asyncio.Queue(maxsize=500)
    subscribers.setdefault(job_id, set()).add(queue)
    try:
        for event in jobs[job_id].get("events", []):
            await websocket.send_json(event)
        while True:
            event = await queue.get()
            await websocket.send_json(event)
    except WebSocketDisconnect:
        pass
    finally:
        remaining = subscribers.get(job_id, set())
        remaining.discard(queue)
        if not remaining and jobs.get(job_id, {}).get("status") not in ("RUNNING", "QUEUED"):
            subscribers.pop(job_id, None)
