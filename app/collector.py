from __future__ import annotations

import csv
from concurrent.futures import ThreadPoolExecutor, as_completed
import re
import threading
import zipfile
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Iterable

from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException

from .log_analysis import analyze_show_logging, format_analysis_section, highest_severity


@dataclass(frozen=True)
class Device:
    name: str
    host: str
    port: int = 22
    device_type: str = "cisco_ios"


@dataclass
class CollectionOptions:
    running_config: bool = True
    startup_config: bool = True
    show_version: bool = True
    show_inventory: bool = True
    show_interfaces_status: bool = False
    show_cdp_neighbors: bool = False
    extended_diagnostics: bool = True
    collect_wlc_ap_info: bool = True
    show_logging: bool = True


@dataclass
class DeviceResult:
    index: int
    inventory_name: str
    host: str
    status: str = "WAITING"
    detected_hostname: str = ""
    model: str = ""
    serial_number: str = ""
    software_version: str = ""
    platform: str = ""
    access_point_count: int = 0
    output_directory: str = ""
    log_file: str = ""
    error: str = ""
    log_alert_count: int = 0
    log_highest_severity: str = "None"


ProgressCallback = Callable[[dict], None]
LOG_FILE_LOCK = threading.Lock()

BASE_COMMANDS = [
    "show interface mgmt0",
    "show cdp neighbors",
    "show cdp neighbors detail",
    "show vlan",
    "show vpc brief",
    "show port-channel summary",
    "show etherchannel summary",
    "show interfaces trunk",
    "show interfaces status",
    "show interfaces brief",
    "show ip interface brief",
    "show interfaces",
    "show mac address-table",
    "show mac-address-table",
    "show spanning-tree",
    "show spanning-tree blockedports",
    "show ip arp",
    "show ip route summary",
    "show ip route 0.0.0.0",
    "show ip eigrp neighbors",
    "show ip eigrp interfaces",
    "show ip ospf neighbor",
    "show ip ospf interface",
    "show ip bgp summary",
    "show ip bgp neighbors",
    "show ip bgp neighbors detail",
    "show ip bgp 0.0.0.0/0",
    "show ip mroute",
    "show ip pim interface brief",
    "show ip pim interface",
    "show class-map",
    "show policy-map",
    "show policy-map interface",
    "show module",
    "show power",
    "show environment all",
    "show version | include uptime",
    "show power inline",
    "show environment temperature status",
    "show lldp neighbors",
    "show lldp neighbors detail",
]

WLC_BULK_COMMANDS = [
    ("show ap summary", 360),
    ("show ap config general", 1200),
    ("show ap inventory all", 600),
    ("show ap uptime", 600),
    ("show ap image", 600),
    ("show ap tag summary", 600),
    ("show wireless stats ap join summary", 600),
    ("show ap dot11 5ghz summary", 600),
    ("show ap dot11 24ghz summary", 600),
    ("show wireless client summary", 600),
    ("show wireless stats client detail", 900),
]

INVALID_PATTERNS = (
    "% Invalid input",
    "% Unrecognized command",
    "Invalid command",
    "Incomplete command",
    "Ambiguous command",
    "Command not found",
)


def safe_name(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_.-]", "_", value.strip())
    return cleaned or "unknown-device"


def extract_hostname(prompt: str, fallback: str) -> str:
    value = re.sub(r"[>#]\s*$", "", prompt.strip()).strip()
    return value or fallback


def first_match(patterns: Iterable[str], text: str) -> str:
    for pattern in patterns:
        match = re.search(pattern, text, re.MULTILINE | re.IGNORECASE)
        if match:
            return match.group(1).strip()
    return ""


def extract_version_details(show_version: str, show_inventory: str = "") -> dict[str, str]:
    version = first_match(
        [r"Cisco IOS XE Software,\s+Version\s+([^\s,]+)", r"Cisco IOS Software.*?Version\s+([^\s,]+)"],
        show_version,
    )
    model = first_match(
        [r"^[Mm]odel [Nn]umber\s*:\s*(\S+)", r"^[Cc]isco\s+(\S+)\s+\(.+?\)\s+processor", r"^[Cc]isco\s+(\S+)\s+processor"],
        show_version,
    )
    serial = first_match(
        [r"Processor board ID\s+(\S+)", r"System [Ss]erial [Nn]umber\s*:\s*(\S+)"],
        show_version,
    )
    if show_inventory:
        model = model or first_match([r"PID:\s*([^,\s]+)"], show_inventory)
        serial = serial or first_match([r"SN:\s*([^,\s]+)"], show_inventory)
    return {"model": model, "serial_number": serial, "software_version": version}


def detect_platform(show_version: str, model: str, device_type: str) -> tuple[str, bool]:
    haystack = f"{show_version}\n{model}\n{device_type}".upper()
    if any(marker in haystack for marker in ("C9800", "WIRELESS CONTROLLER", "AIR-CT", "CISCO_WLC", "WLC")):
        return ("Cisco Wireless LAN Controller", True)
    if "NEXUS" in haystack or "NX-OS" in haystack:
        return ("Cisco Nexus", False)
    if "IOS XE" in haystack:
        return ("Cisco IOS-XE", False)
    return ("Cisco IOS", False)


def run_command(connection, command: str, timeout: int = 180) -> tuple[str, str]:
    try:
        output = connection.send_command(command, read_timeout=timeout, strip_prompt=True, strip_command=True)
        status = "FAILED / UNSUPPORTED" if any(item.lower() in output.lower() for item in INVALID_PATTERNS) else "SUCCESS"
        return output, status
    except Exception as exc:
        return f"{type(exc).__name__}: {exc}", "FAILED"


def append_section(parts: list[str], command: str, output: str, status: str) -> None:
    parts.extend([
        "=" * 96,
        f"COMMAND: {command}",
        f"STATUS : {status}",
        "=" * 96,
        "",
        output.rstrip(),
        "",
        "",
    ])


def parse_ap_names(show_ap_summary: str) -> list[str]:
    names: list[str] = []
    for raw_line in show_ap_summary.splitlines():
        line = raw_line.strip()
        if not line or set(line) <= {"-", "="}:
            continue
        lowered = line.lower()
        if lowered.startswith(("number of aps", "ap name", "ap-name", "name ", "mac address")):
            continue
        token = line.split()[0]
        if token.lower() in {"ap", "name", "slot", "mac"}:
            continue
        if re.fullmatch(r"[0-9a-fA-F:.]+", token):
            continue
        if re.fullmatch(r"[A-Za-z0-9_.:-]{2,64}", token) and token not in names:
            names.append(token)
    return names


def unique_log_path(job_dir: Path, hostname: str, host: str) -> Path:
    candidate = job_dir / f"{safe_name(hostname)}.log"
    if not candidate.exists():
        return candidate
    return job_dir / f"{safe_name(hostname)}_{safe_name(host)}.log"


def collect_one(
    index: int,
    device: Device,
    username: str,
    password: str,
    enable_secret: str,
    options: CollectionOptions,
    job_dir: Path,
    notify: ProgressCallback,
    custom_commands: list[str] | None = None,
    authentication_lock: threading.Lock | None = None,
    auth_timeout: int = 180,
    cancel_event: threading.Event | None = None,
    active_connections: dict[int, Any] | None = None,
    connections_lock: threading.Lock | None = None,
) -> DeviceResult:
    result = DeviceResult(index=index, inventory_name=device.name, host=device.host, status="WAITING")

    def cancelled() -> bool:
        return cancel_event is not None and cancel_event.is_set()

    if cancelled():
        result.status = "CANCELLED"
        result.error = "Cancelled before starting"
        notify({"type": "device_update", "result": asdict(result)})
        return result

    result.status = "CONNECTING"
    notify({"type": "device_update", "result": asdict(result)})
    connection = None

    try:
        connect_args = dict(
            device_type=device.device_type,
            host=device.host,
            port=device.port,
            username=username,
            password=password,
            secret=enable_secret or password,
            conn_timeout=30,
            auth_timeout=max(30, min(int(auth_timeout), 600)),
            banner_timeout=90,
            timeout=180,
            session_timeout=180,
            fast_cli=False,
        )

        if authentication_lock is not None:
            notify({"type": "log", "message": f"{device.name} ({device.host}): waiting for MFA authentication slot"})
            with authentication_lock:
                if cancelled():
                    result.status = "CANCELLED"
                    result.error = "Cancelled while waiting for authentication slot"
                    notify({"type": "device_update", "result": asdict(result)})
                    return result
                notify({"type": "log", "message": f"{device.name} ({device.host}): starting SSH authentication; approve PingID if prompted"})
                connection = ConnectHandler(**connect_args)
        else:
            if cancelled():
                result.status = "CANCELLED"
                result.error = "Cancelled before starting"
                notify({"type": "device_update", "result": asdict(result)})
                return result
            notify({"type": "log", "message": f"{device.name} ({device.host}): starting SSH authentication"})
            connection = ConnectHandler(**connect_args)

        if active_connections is not None and connections_lock is not None:
            with connections_lock:
                active_connections[index] = connection

        if cancelled():
            result.status = "CANCELLED"
            result.error = "Cancelled by user"
            notify({"type": "device_update", "result": asdict(result)})
            return result

        if not connection.check_enable_mode():
            connection.enable()
        connection.send_command("terminal length 0", expect_string=r"[#>]", read_timeout=15)

        hostname = extract_hostname(connection.find_prompt(), device.name)
        result.detected_hostname = hostname
        result.status = "COLLECTING"
        notify({"type": "device_update", "result": asdict(result)})

        parts = [
            "=" * 96,
            "NETWORK DEVICE COLLECTION LOG",
            "=" * 96,
            f"Inventory name : {device.name}",
            f"Management IP  : {device.host}",
            f"Detected host  : {hostname}",
            f"Collected      : {datetime.now().astimezone().isoformat()}",
            "=" * 96,
            "",
            "",
        ]
        attempted = successful = failed = 0

        notify({"type": "log", "message": f"{hostname}: detecting platform with show version"})
        show_version, version_status = run_command(connection, "show version", 120)
        attempted += 1
        successful += version_status == "SUCCESS"
        failed += version_status != "SUCCESS"
        if options.show_version:
            append_section(parts, "show version", show_version, version_status)

        show_inventory = ""
        if options.show_inventory:
            notify({"type": "log", "message": f"{hostname}: collecting show inventory"})
            show_inventory, status = run_command(connection, "show inventory", 180)
            attempted += 1
            successful += status == "SUCCESS"
            failed += status != "SUCCESS"
            append_section(parts, "show inventory", show_inventory, status)

        details = extract_version_details(show_version, show_inventory)
        result.model = details["model"]
        result.serial_number = details["serial_number"]
        result.software_version = details["software_version"]
        result.platform, is_wlc = detect_platform(show_version, result.model, device.device_type)

        commands: list[tuple[str, int]] = []
        if options.running_config:
            commands.append(("show running-config", 300))
        if options.startup_config:
            commands.append(("show startup-config", 300))
        if options.show_interfaces_status:
            commands.append(("show interfaces status", 180))
        if options.show_cdp_neighbors:
            commands.append(("show cdp neighbors detail", 180))
        if options.show_logging:
            commands.append(("show logging", 600))
        if options.extended_diagnostics:
            commands.extend((command, 240) for command in BASE_COMMANDS)

        if custom_commands:
            commands.extend((command, 600) for command in custom_commands)

        show_logging_output = ""
        seen: set[str] = {"show version", "show inventory"}
        for command, timeout in commands:
            if command in seen:
                continue
            seen.add(command)
            if cancelled():
                notify({"type": "log", "message": f"{hostname}: cancellation requested - stopping before {command}"})
                break
            notify({"type": "log", "message": f"{hostname}: collecting {command}"})
            output, status = run_command(connection, command, timeout)
            attempted += 1
            successful += status == "SUCCESS"
            failed += status != "SUCCESS"
            append_section(parts, command, output, status)
            if command == "show logging" and status == "SUCCESS":
                show_logging_output = output

        if show_logging_output:
            log_alerts = analyze_show_logging(show_logging_output)
            result.log_alert_count = len(log_alerts)
            result.log_highest_severity = highest_severity(log_alerts)
            parts.extend(format_analysis_section(log_alerts))
            if log_alerts:
                notify({"type": "log_alert", "device": hostname, "host": device.host, "count": len(log_alerts), "highest_severity": result.log_highest_severity})
                notify({"type": "log", "message": f"{hostname}: WARNING - {len(log_alerts)} log alert(s) detected; highest severity {result.log_highest_severity}"})
            else:
                notify({"type": "log", "message": f"{hostname}: show logging analysis found no high-confidence issues"})

        if is_wlc and options.collect_wlc_ap_info:
            parts.extend(["#" * 96, "WIRELESS LAN CONTROLLER / ACCESS POINT INFORMATION", "#" * 96, "", ""])
            notify({"type": "log", "message": f"{hostname}: WLC detected; collecting AP information"})
            ap_summary = ""
            for command, timeout in WLC_BULK_COMMANDS:
                if cancelled():
                    notify({"type": "log", "message": f"{hostname}: cancellation requested - stopping before {command}"})
                    break
                output, status = run_command(connection, command, timeout)
                attempted += 1
                successful += status == "SUCCESS"
                failed += status != "SUCCESS"
                append_section(parts, command, output, status)
                if command == "show ap summary" and status == "SUCCESS":
                    ap_summary = output

            # AP count is derived from show ap summary, but detailed collection is
            # deliberately performed once with the controller-wide command
            # `show ap config general`. No per-AP hostname loop is required.
            result.access_point_count = len(parse_ap_names(ap_summary))

        was_cancelled = cancelled()
        if was_cancelled:
            result.error = result.error or "Cancelled by user"
            collection_status_line = "CANCELLED BY USER - partial output above"
        elif failed == 0:
            collection_status_line = "COMPLETED"
        else:
            collection_status_line = "COMPLETED WITH WARNINGS"

        parts.extend([
            "=" * 96,
            "END OF COLLECTION",
            "=" * 96,
            f"Platform            : {result.platform}",
            f"Access points found : {result.access_point_count}",
            f"Commands attempted  : {attempted}",
            f"Commands successful : {successful}",
            f"Commands failed     : {failed}",
            f"Collection status   : {collection_status_line}",
            "=" * 96,
            "",
        ])

        with LOG_FILE_LOCK:
            log_path = unique_log_path(job_dir, hostname, device.host)
            log_path.write_text("\n".join(parts), encoding="utf-8")
        result.output_directory = str(job_dir)
        result.log_file = str(log_path)
        result.status = "CANCELLED" if was_cancelled else "SUCCESS"
        notify({"type": "log", "message": f"{hostname}: collection {'cancelled' if was_cancelled else 'completed'} - {log_path.name}"})

    except NetmikoAuthenticationException as exc:
        if cancelled():
            result.status = "CANCELLED"
            result.error = "Cancelled by user"
        else:
            result.status = "FAILED"
            result.error = f"Authentication failed: {exc}"
        notify({"type": "log", "message": f"{device.name} ({device.host}): {result.error}"})
    except NetmikoTimeoutException as exc:
        if cancelled():
            result.status = "CANCELLED"
            result.error = "Cancelled by user"
        else:
            result.status = "FAILED"
            result.error = f"Connection timed out: {exc}"
        notify({"type": "log", "message": f"{device.name} ({device.host}): {result.error}"})
    except Exception as exc:
        if cancelled():
            result.status = "CANCELLED"
            result.error = "Cancelled by user"
        else:
            result.status = "FAILED"
            result.error = f"{type(exc).__name__}: {exc}"
    finally:
        if active_connections is not None and connections_lock is not None:
            with connections_lock:
                active_connections.pop(index, None)
        if connection is not None:
            try:
                connection.disconnect()
            except Exception:
                pass

    notify({"type": "device_update", "result": asdict(result)})
    return result


def write_results(job_dir: Path, results: list[DeviceResult]) -> Path:
    path = job_dir / "collection-results.csv"
    fieldnames = [
        "inventory_name", "host", "detected_hostname", "status", "platform", "model",
        "serial_number", "software_version", "access_point_count", "log_alert_count", "log_highest_severity", "log_file", "error",
    ]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for item in sorted(results, key=lambda row: row.index):
            data = asdict(item)
            writer.writerow({key: data[key] for key in fieldnames})
    return path


def create_zip(job_dir: Path) -> Path:
    zip_path = job_dir / "network-device-logs.zip"
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in job_dir.rglob("*"):
            if path.is_file() and path != zip_path and path.name != "job_meta.json":
                archive.write(path, path.relative_to(job_dir))
    return zip_path


def run_collection_job(
    job_id: str,
    devices: list[Device],
    username: str,
    password: str,
    enable_secret: str,
    options: CollectionOptions,
    storage_root: Path,
    notify: ProgressCallback,
    completion_callback: Callable[[list[DeviceResult], Path, Path, Path, str], None],
    concurrent_devices: int = 5,
    custom_commands: list[str] | None = None,
    sequential_authentication: bool = True,
    auth_timeout: int = 180,
    cancel_event: threading.Event | None = None,
    active_connections: dict[int, Any] | None = None,
    connections_lock: threading.Lock | None = None,
) -> None:
    job_dir = storage_root / job_id
    job_dir.mkdir(parents=True, exist_ok=True)
    results_by_index: list[DeviceResult | None] = [None] * len(devices)
    worker_count = max(1, min(int(concurrent_devices), 20, len(devices)))
    authentication_lock = threading.Lock() if sequential_authentication else None
    if cancel_event is None:
        cancel_event = threading.Event()
    if active_connections is None:
        active_connections = {}
    if connections_lock is None:
        connections_lock = threading.Lock()
    notify({"type": "job_started", "total": len(devices), "concurrent_devices": worker_count})
    notify({"type": "log", "message": f"Starting collection with {worker_count} worker(s)"})
    if sequential_authentication:
        notify({"type": "log", "message": f"MFA mode enabled: SSH authentication is sequential; authenticated devices collect in parallel (authentication timeout {auth_timeout}s)"})
    else:
        notify({"type": "log", "message": f"Parallel authentication enabled (authentication timeout {auth_timeout}s)"})

    with ThreadPoolExecutor(max_workers=worker_count, thread_name_prefix="device-collector") as executor:
        future_map = {}
        for index, device in enumerate(devices):
            notify({"type": "log", "message": f"Queued {device.name} ({device.host})"})
            future = executor.submit(
                collect_one,
                index,
                device,
                username,
                password,
                enable_secret,
                options,
                job_dir,
                notify,
                custom_commands,
                authentication_lock,
                auth_timeout,
                cancel_event,
                active_connections,
                connections_lock,
            )
            future_map[future] = (index, device)

        complete_count = 0
        for future in as_completed(future_map):
            index, device = future_map[future]
            try:
                result = future.result()
            except Exception as exc:
                result = DeviceResult(
                    index=index,
                    inventory_name=device.name,
                    host=device.host,
                    status="FAILED",
                    error=f"{type(exc).__name__}: {exc}",
                )
                notify({"type": "device_update", "result": asdict(result)})
            results_by_index[index] = result
            complete_count += 1
            completed = [item for item in results_by_index if item is not None]
            notify({
                "type": "progress",
                "complete": complete_count,
                "total": len(devices),
                "successful": sum(item.status == "SUCCESS" for item in completed),
                "failed": sum(item.status == "FAILED" for item in completed),
                "cancelled": sum(item.status == "CANCELLED" for item in completed),
                "active": min(worker_count, len(devices) - complete_count),
                "queued": max(0, len(devices) - complete_count - worker_count),
            })

    results = [item for item in results_by_index if item is not None]
    results_path = write_results(job_dir, results)
    from .reporting import create_technical_review_workbook
    workbook_path = create_technical_review_workbook(job_dir, results)
    zip_path = create_zip(job_dir)
    job_status = "CANCELLED" if cancel_event.is_set() else "COMPLETE"
    completion_callback(results, results_path, workbook_path, zip_path, job_status)
    notify({
        "type": "job_complete",
        "status": job_status,
        "successful": sum(item.status == "SUCCESS" for item in results),
        "failed": sum(item.status == "FAILED" for item in results),
        "cancelled": sum(item.status == "CANCELLED" for item in results),
    })
