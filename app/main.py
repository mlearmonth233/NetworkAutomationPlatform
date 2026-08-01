from __future__ import annotations

import asyncio
import hashlib
import json
import os
import sys
import threading
import uuid
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import Any

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from .collector import CollectionOptions, Device, DeviceResult, run_collection_job
from .compliance import check_firmware_compliance, parse_tech_stack
from .ddi import analyze_config, build_ddi_workbook, fetch_running_config
from .network_tools import run_bulk_tests
from .r2o_check import run_r2o_check


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
R2O_STORAGE_ROOT = STORAGE_ROOT.parent / "r2o_checks"
R2O_STORAGE_ROOT.mkdir(parents=True, exist_ok=True)
DDI_STORAGE_ROOT = STORAGE_ROOT.parent / "ddi_analyses"
DDI_STORAGE_ROOT.mkdir(parents=True, exist_ok=True)
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
            role = str(row.get("role") or "").strip()
        except (AttributeError, TypeError, ValueError) as exc:
            raise HTTPException(status_code=400, detail=f"Invalid device row {position}") from exc
        if not name or not host:
            raise HTTPException(status_code=400, detail=f"Device row {position} requires name and host")
        if not 1 <= port <= 65535:
            raise HTTPException(status_code=400, detail=f"Invalid port on row {position}")
        devices.append(Device(name=name, host=host, port=port, device_type=device_type, role=role))
    return devices


def parse_custom_commands(custom_commands_json: str) -> list[str]:
    try:
        custom_commands = json.loads(custom_commands_json)
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=400, detail="Invalid custom command data") from exc
    if not isinstance(custom_commands, list):
        raise HTTPException(status_code=400, detail="Custom commands must be a list")
    cleaned_commands: list[str] = []
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
    return cleaned_commands


@app.get("/", response_class=HTMLResponse)
async def home(request: Request) -> HTMLResponse:
    def asset_version(filename: str) -> str:
        try:
            content = (BASE_DIR / "static" / filename).read_bytes()
            return hashlib.md5(content).hexdigest()[:12]
        except OSError:
            return "0"

    return templates.TemplateResponse("index.html", {
        "request": request,
        "app_js_version": asset_version("app.js"),
        "styles_css_version": asset_version("styles.css"),
    })


def _start_collection_thread(
    job_id: str,
    devices: list[Device],
    username: str,
    password: str,
    enable_secret: str,
    concurrent_devices: int,
    custom_commands: list[str],
    sequential_authentication: bool,
    auth_timeout: int,
    retry_indices: set[int] | None = None,
    existing_results: dict[int, Any] | None = None,
) -> None:
    """Shared by create_job and the retry endpoint. When retry_indices is
    given, only those device indices are actually (re)collected - every
    other device's existing_results entry is carried through untouched into
    the merged final output, so retrying a failed device never discards
    what already succeeded."""
    options = CollectionOptions()
    cancel_event = threading.Event()
    job_controls[job_id] = {
        "cancel_event": cancel_event,
        "active_connections": {},
        "lock": threading.Lock(),
    }

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
                concurrent_devices=concurrent_devices, custom_commands=custom_commands,
                sequential_authentication=sequential_authentication, auth_timeout=auth_timeout,
                cancel_event=cancel_event,
                active_connections=job_controls[job_id]["active_connections"],
                connections_lock=job_controls[job_id]["lock"],
                retry_indices=retry_indices, existing_results=existing_results,
            )
        except Exception as exc:
            jobs[job_id]["status"] = "FAILED"
            jobs[job_id]["completed_at"] = datetime.now().astimezone().isoformat()
            write_job_meta(job_id)
            job_controls.pop(job_id, None)
            publish(job_id, {"type": "log", "message": f"Job failed unexpectedly: {type(exc).__name__}: {exc}"})
            publish(job_id, {"type": "job_complete", "status": "FAILED", "successful": 0, "failed": len(devices), "cancelled": 0})

    threading.Thread(target=worker, daemon=True, name=f"collector-{job_id[:8]}").start()


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
    cleaned_commands = parse_custom_commands(custom_commands_json)

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
    write_job_meta(job_id)

    _start_collection_thread(
        job_id, devices, username, password, enable_secret, concurrent_devices,
        cleaned_commands, sequential_authentication, auth_timeout,
    )
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


@app.post("/api/jobs/{job_id}/retry")
async def retry_job(
    job_id: str,
    username: str = Form(...),
    password: str = Form(...),
    enable_secret: str = Form(""),
) -> JSONResponse:
    job = jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    if job["status"] in ("QUEUED", "RUNNING"):
        raise HTTPException(status_code=400, detail="Job is still running")
    if not username.strip() or not password:
        raise HTTPException(status_code=400, detail="Username and password are required")

    devices = [Device(**item) for item in job.get("devices", [])]
    if not devices:
        raise HTTPException(status_code=400, detail="This job has no device list to retry")

    existing_results: dict[int, Any] = {}
    successful_indices: set[int] = set()
    for item in job.get("results", []):
        result = DeviceResult(**item)
        existing_results[result.index] = result
        if result.status == "SUCCESS":
            successful_indices.add(result.index)
    retry_indices = {i for i in range(len(devices)) if i not in successful_indices}
    if not retry_indices:
        raise HTTPException(status_code=400, detail="Every device in this job already succeeded - nothing to retry")

    jobs[job_id]["status"] = "RUNNING"
    write_job_meta(job_id)
    subscribers.setdefault(job_id, set())
    publish(job_id, {"type": "log", "message": f"Retrying {len(retry_indices)} device(s); {len(successful_indices)} already-successful device(s) will be kept as-is"})

    _start_collection_thread(
        job_id, devices, username, password, enable_secret,
        job.get("concurrent_devices", 5), job.get("custom_commands", []),
        job.get("sequential_authentication", True), job.get("auth_timeout", 180),
        retry_indices=retry_indices, existing_results=existing_results,
    )
    return JSONResponse({"status": "retrying", "retrying_count": len(retry_indices), "kept_count": len(successful_indices)})


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


@app.post("/api/r2o-check")
async def r2o_check(
    site_label: str = Form("R2O Check"),
    sitebook: UploadFile | None = File(None),
    lld: UploadFile | None = File(None),
    cmdb: UploadFile | None = File(None),
    network_diagram: UploadFile | None = File(None),
    rack_elevations: UploadFile | None = File(None),
) -> JSONResponse:
    uploads = {
        "sitebook": sitebook, "lld": lld, "cmdb": cmdb,
        "network_diagram": network_diagram, "rack_elevations": rack_elevations,
    }
    if not any(uploads.values()):
        raise HTTPException(status_code=400, detail="Upload at least one document")

    max_bytes = 60 * 1024 * 1024  # generous headroom above the ~23MB seen in practice
    read_bytes: dict[str, bytes | None] = {}
    for key, upload in uploads.items():
        if upload is None:
            read_bytes[key] = None
            continue
        content = await upload.read()
        if len(content) > max_bytes:
            raise HTTPException(status_code=400, detail=f"{upload.filename} is too large (max 60MB)")
        read_bytes[key] = content

    try:
        findings, summary, workbook, source_counts = await asyncio.to_thread(
            run_r2o_check,
            site_label.strip() or "R2O Check",
            read_bytes["sitebook"], read_bytes["lld"], read_bytes["cmdb"],
            read_bytes["network_diagram"], read_bytes["rack_elevations"],
        )
    except Exception as exc:
        raise HTTPException(
            status_code=400,
            detail=f"Could not process the uploaded documents: {type(exc).__name__}: {exc}",
        ) from exc

    check_id = uuid.uuid4().hex
    check_dir = R2O_STORAGE_ROOT / check_id
    check_dir.mkdir(parents=True, exist_ok=True)
    report_path = check_dir / "r2o-check-report.xlsx"
    workbook.save(report_path)

    return JSONResponse({
        "check_id": check_id,
        "site_label": site_label,
        "source_counts": source_counts,
        "summary": summary,
        "conflicts": findings["conflicts"],
        "coverage_gaps": findings["coverage_gaps"],
    })


@app.get("/api/r2o-check/{check_id}/download")
async def download_r2o_report(check_id: str) -> FileResponse:
    report_path = R2O_STORAGE_ROOT / check_id / "r2o-check-report.xlsx"
    if not report_path.is_file():
        raise HTTPException(status_code=404, detail="Report not found")
    return FileResponse(report_path, filename=f"r2o-check-{check_id[:8]}.xlsx")


@app.post("/api/ddi/analyze")
async def ddi_analyze(
    config_file: UploadFile | None = File(None),
    config_text: str = Form(""),
    host: str = Form(""),
    port: int = Form(22),
    device_type: str = Form("cisco_ios"),
    username: str = Form(""),
    password: str = Form(""),
    enable_secret: str = Form(""),
    hide_no_helpers: bool = Form(False),
    exclude_vlans: str = Form(""),
) -> JSONResponse:
    try:
        exclude_vlan_set = {int(v.strip()) for v in exclude_vlans.split(",") if v.strip()}
    except ValueError:
        raise HTTPException(status_code=400, detail="Exclude VLANs must be a comma-separated list of numbers")

    if config_file is not None:
        raw = await config_file.read()
        text = raw.decode("utf-8", errors="replace")
        source_label = config_file.filename or "uploaded file"
    elif config_text.strip():
        text = config_text
        source_label = "pasted configuration"
    elif host.strip():
        if not username.strip() or not password:
            raise HTTPException(status_code=400, detail="Username and password are required to connect")
        try:
            text = await asyncio.to_thread(
                fetch_running_config, host.strip(), port, device_type, username.strip(), password, enable_secret,
            )
        except Exception as exc:
            raise HTTPException(status_code=400, detail=f"Could not connect: {type(exc).__name__}: {exc}") from exc
        source_label = f"{host.strip()} (live collection)"
    else:
        raise HTTPException(status_code=400, detail="Upload a config file, paste one, or provide device connection details")

    analysis = await asyncio.to_thread(analyze_config, text, source_label, hide_no_helpers, exclude_vlan_set)
    workbook = await asyncio.to_thread(build_ddi_workbook, analysis)

    analysis_id = uuid.uuid4().hex
    analysis_dir = DDI_STORAGE_ROOT / analysis_id
    analysis_dir.mkdir(parents=True, exist_ok=True)
    workbook_path = analysis_dir / "ddi-analysis.xlsx"
    await asyncio.to_thread(workbook.save, workbook_path)

    return JSONResponse({
        "analysis_id": analysis_id,
        "source_label": analysis["source_label"],
        "vlan_helpers": analysis["vlan_helpers"],
        "unique_helpers": analysis["unique_helpers"],
        "svi_config_text": analysis["svi_config_text"],
        "vlan_count": len(analysis["vlan_interfaces"]),
    })


@app.get("/api/ddi/{analysis_id}/download")
async def download_ddi_analysis(analysis_id: str) -> FileResponse:
    workbook_path = DDI_STORAGE_ROOT / analysis_id / "ddi-analysis.xlsx"
    if not workbook_path.is_file():
        raise HTTPException(status_code=404, detail="Analysis not found")
    return FileResponse(workbook_path, filename=f"ddi-analysis-{analysis_id[:8]}.xlsx")


@app.post("/api/compliance/firmware")
async def compliance_firmware(
    job_id: str = Form(...),
    tech_stack_file: UploadFile = File(...),
) -> JSONResponse:
    job = jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    devices = job.get("results") or []
    if not devices:
        raise HTTPException(status_code=400, detail="This job has no collected device results yet")

    raw = await tech_stack_file.read()
    try:
        tech_stack = await asyncio.to_thread(parse_tech_stack, raw)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Could not read the Tech Stack file: {type(exc).__name__}: {exc}") from exc
    if not tech_stack:
        raise HTTPException(status_code=400, detail="No 'Tech Stack' sheet with the expected columns was found in that file")

    results = await asyncio.to_thread(check_firmware_compliance, devices, tech_stack)
    return JSONResponse({
        "job_id": job_id,
        "results": results,
        "compliant_count": sum(1 for r in results if r["status"] == "COMPLIANT"),
        "non_compliant_count": sum(1 for r in results if r["status"] == "NON_COMPLIANT"),
        "unknown_count": sum(1 for r in results if r["status"] == "UNKNOWN"),
    })


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
