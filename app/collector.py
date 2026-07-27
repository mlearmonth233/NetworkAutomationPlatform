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
    "show ip route",
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

# Classic AireOS controllers (5500/8500/WiSM2/2500 series) run a completely
# different OS from IOS-XE - no privileged/enable mode, different pagination
# command, and different show-command syntax entirely. show sysinfo and show
# inventory are collected separately (see collect_one) for hostname/model
# detection, so they're not repeated here.
AIREOS_COMMANDS: list[tuple[str, int]] = [
    ("show interface detailed management", 60),
    ("show redundancy summary", 60),
    ("show wlan apgroups", 60),
    ("show advanced 802.11a summary", 60),
    ("show advanced 802.11b summary", 60),
    ("show ap summary", 120),
    ("show ap inventory all", 600),
    ("show ap stats ethernet summary", 120),
    ("show ap cdp neighbors all", 180),
    ("show cdp nei", 60),
    ("show lldp nei", 60),
    # Kept last deliberately: by far the slowest, most fragile command
    # (confirmed to run to 200K+ lines on a large real deployment), so a
    # manually-interrupted or otherwise cut-short session still collects
    # everything else first rather than losing it all behind this one.
    ("show run-config", 1200),
]

# Confirmed from a real APC AOS (Network Management Card) SSH session on a
# switched PDU. The user's original list had console/web/ntp repeated at the
# end (matching the real capture exactly) - deduplicated here since running
# the same read-only command twice adds nothing.
APC_COMMANDS: list[tuple[str, int]] = [
    ("user", 60),
    ("web", 60),
    ("console", 60),
    ("ftp", 60),
    ("ntp", 60),
    ("snmp", 60),
    ("snmpv3", 60),
    ("tcpip", 60),
    ("date", 60),
    ("olStatus all", 60),
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


def extract_aireos_sysinfo(show_sysinfo: str) -> dict[str, str]:
    """Best-effort field extraction from AireOS `show sysinfo` output.
    AireOS formats fields as 'Label.......... value' with a variable-length
    run of dots; exact spacing/labels can vary slightly by AireOS release,
    so this is deliberately tolerant and degrades to empty strings (rather
    than guessing wrong) if a field isn't found - the raw show sysinfo
    section in the log remains the authoritative source either way."""
    system_name = first_match([r"^System Name[.\s]+(\S.*?)\s*$"], show_sysinfo)
    product_version = first_match([r"^Product Version[.\s]+(\S.*?)\s*$"], show_sysinfo)
    return {"system_name": system_name, "product_version": product_version}


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


def run_command_with_confirmation(connection, command: str, timeout: int = 180) -> tuple[str, str]:
    """Some AireOS commands (namely `show run-config`) show a one-time
    'Press Enter to continue...' gate before producing their real output,
    with a long, uneven pause before that output arrives on controllers
    with many APs. A quiet-period timing read (Netmiko's own
    send_command_w_enter) cuts off during that pause rather than waiting
    through it, and Netmiko's default auto-detected prompt pattern doesn't
    reliably match AireOS's parenthesized "(hostname) >" prompt format
    either - so this builds the wait explicitly: a quick timing read for
    the (fast-arriving) confirmation text, then a pattern-based read using
    an explicitly re.escape'd prompt, which is what actually waits
    correctly through a long pause instead of returning early or hanging."""
    try:
        stage1 = connection.send_command_timing(command, read_timeout=30, strip_prompt=False, strip_command=True)
        if "Press Enter to" not in stage1 and "Press any key" not in stage1:
            # No confirmation gate appeared (e.g. a different AireOS
            # release) - what we already have is the real output.
            status = "FAILED / UNSUPPORTED" if any(item.lower() in stage1.lower() for item in INVALID_PATTERNS) else "SUCCESS"
            return stage1, status
        pattern = rf"{re.escape(connection.base_prompt)}[>#]\s*$"
        stage2 = connection.send_command(
            connection.RETURN, expect_string=pattern, read_timeout=timeout,
            strip_prompt=True, strip_command=True,
        )
        output = f"{stage1}\n{stage2}"
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
        if re.match(r"^[A-Za-z]{1,4}\s*=\s*\S", line):
            continue  # a legend line, e.g. 'CC = Country Code' / 'RD = Regulatory Domain'
        token = line.split()[0]
        if token.lower() in {"ap", "name", "slot", "mac"}:
            continue
        if re.fullmatch(r"[0-9a-fA-F:.]+", token):
            continue
        if re.fullmatch(r"[A-Za-z0-9_.:-]{2,64}", token) and token not in names:
            names.append(token)
    return names


def parse_aireos_ap_ethernet_summary(output: str) -> list[dict[str, str]]:
    """Parses AireOS `show ap stats ethernet summary` output into one row per
    AP (its primary/first Ethernet interface). Format confirmed against a
    real 5520 capture: each AP's block starts with the AP name at column 0
    immediately followed by its interface name, status, and speed;
    continuation lines for the AP's other interfaces (e.g. LAN1) are
    indented, and are skipped here since they repeat the same AP name."""
    rows: list[dict[str, str]] = []
    for line in output.splitlines():
        if not line.strip() or line[0].isspace():
            continue
        parts = line.split()
        if len(parts) < 3 or "ethernet" not in parts[1].lower():
            continue  # header/separator line, or anything not matching the expected shape
        rows.append({
            "ap_name": parts[0], "interface": parts[1], "status": parts[2],
            "speed": parts[3] if len(parts) > 3 else "",
        })
    return rows


def parse_aireos_ap_cdp_neighbors(output: str) -> list[dict[str, str]]:
    """Parses AireOS `show ap cdp neighbors all` output. Format confirmed
    against a real 5520 capture (256 APs): each AP has one line with its
    name, its own IP, the upstream neighbor switch's name, and the neighbor
    port, followed by an indented continuation line giving the neighbor
    switch's own IP address."""
    rows: list[dict[str, str]] = []
    lines = output.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i]
        stripped = line.strip()
        is_separator = stripped and not (set(stripped.replace(" ", "")) - {"-"})
        if not stripped or is_separator or stripped.lower().startswith("ap name") or line[:1].isspace():
            i += 1
            continue
        parts = line.split()
        if len(parts) < 4:
            i += 1
            continue
        ap_name, ap_ip, neighbor_name = parts[0], parts[1], parts[2]
        neighbor_port = " ".join(parts[3:])
        neighbor_ip = ""
        if i + 1 < len(lines) and lines[i + 1][:1].isspace():
            match = re.search(r"IP address:\s*(\S+)", lines[i + 1])
            if match:
                neighbor_ip = match.group(1)
            i += 1  # consume the continuation line so it isn't misread as its own row
        rows.append({
            "ap_name": ap_name, "ap_ip": ap_ip, "neighbor_name": neighbor_name,
            "neighbor_port": neighbor_port, "neighbor_ip": neighbor_ip,
        })
        i += 1
    return rows


def parse_aireos_radio_summary(output: str) -> dict[str, str]:
    """Parses AireOS `show advanced 802.11a summary` / `show advanced
    802.11b summary` output into {ap_name: radio_mac}. Both commands share
    the same column layout (AP Name, MAC Address, Slot, Admin, Oper,
    Channel, TxPower, BSS Color) - confirmed against a real 5520 capture
    (256 APs) for the 802.11b/2.4GHz case; 802.11a/5GHz uses the identical
    format for the other band. If an AP appears more than once (a
    tri-radio AP with two 5GHz-capable slots), only the first occurrence
    is kept - the common dual-radio case is unaffected."""
    rows: dict[str, str] = {}
    started = False
    for line in output.splitlines():
        stripped = line.strip()
        if not started:
            if stripped and not (set(stripped.replace(" ", "")) - {"-"}):
                started = True
            continue
        if not stripped:
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        ap_name, mac = parts[0], parts[1]
        if not re.fullmatch(r"[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}", mac):
            continue
        rows.setdefault(ap_name, mac.lower())
    return rows


def parse_aireos_ap_summary(output: str) -> list[dict[str, str]]:
    """Parses AireOS `show ap summary` output - a fixed-width table where
    the Location column can contain spaces (e.g. "default location"), so
    only the first four columns (AP Name, Slots, AP Model, Ethernet MAC -
    none of which contain spaces) are extracted; everything from Location
    onward is intentionally not parsed rather than risk misaligning on a
    column that can contain embedded spaces. Confirmed against a real
    5520 capture (256 APs). Parsing starts after the dashed separator line
    so the preceding summary/header lines are never mistaken for data."""
    rows: list[dict[str, str]] = []
    started = False
    for line in output.splitlines():
        stripped = line.strip()
        if not started:
            if stripped and not (set(stripped.replace(" ", "")) - {"-"}):
                started = True
            continue
        if not stripped:
            continue
        parts = line.split()
        if len(parts) < 4:
            continue
        ap_name, _slots, model, mac = parts[0], parts[1], parts[2], parts[3]
        if not re.fullmatch(r"[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}", mac):
            continue  # doesn't look like a MAC in the expected column - skip defensively
        rows.append({"ap_name": ap_name, "model": model, "mac_address": mac})
    return rows


def parse_aireos_ap_inventory(output: str) -> list[dict[str, str]]:
    """Parses AireOS `show ap inventory all` output: repeated per-AP blocks,
    each starting with 'Inventory for <ap-name>' followed by NAME/DESCR and
    PID/VID/SN lines. Confirmed against a real 5520 capture."""
    rows: list[dict[str, str]] = []
    blocks = re.split(r"(?m)^Inventory for\s+(\S+)\s*$", output)
    pairs = iter(blocks[1:])  # blocks[0] is anything before the first match (should be empty)
    for ap_name, block in zip(pairs, pairs):
        pid = re.search(r"PID:\s*([^,\s]+)", block)
        serial = re.search(r"SN:\s*([^,\s]+)", block)
        rows.append({
            "ap_name": ap_name, "model": pid.group(1) if pid else "",
            "serial_number": serial.group(1) if serial else "",
        })
    return rows


def parse_apc_about(output: str) -> dict[str, str]:
    """Parses APC AOS `about` output. Only the first 'Hardware Factory'
    block is the PDU itself - the 'Network Management Card' block that
    follows is the separate management card, with its own PID/SN. Confirmed
    against a real Schneider Electric AOS v7.1.2 / RPDU 2g APP v7.1.3
    session."""
    block_match = re.search(r"Hardware Factory\s*\n-+\s*\n(.*?)(?:\n\n|\nNetwork Management Card)", output, re.DOTALL)
    block = block_match.group(1) if block_match else output
    model = re.search(r"Model Number:\s*(\S+)", block)
    serial = re.search(r"Serial Number:\s*(\S+)", block)
    mac = re.search(r"MAC Address:\s*([0-9A-Fa-f ]{17})", block)
    return {
        "model": model.group(1) if model else "",
        "serial_number": serial.group(1) if serial else "",
        "mac_address": mac.group(1).strip().replace(" ", ":").lower() if mac else "",
    }


def parse_apc_system(output: str) -> dict[str, str]:
    """Parses APC AOS `system` output for identifying fields. Confirmed
    against a real session."""
    name = re.search(r"^Name:\s*(\S+)", output, re.MULTILINE)
    contact = re.search(r"^Contact:\s*(.+)$", output, re.MULTILINE)
    location = re.search(r"^Location:\s*(.+)$", output, re.MULTILINE)
    return {
        "hostname": name.group(1) if name else "",
        "contact": contact.group(1).strip() if contact else "",
        "location": location.group(1).strip() if location else "",
    }


def parse_apc_outlet_status(output: str) -> list[dict[str, str]]:
    """Parses APC AOS `olStatus all` output - one row per switched outlet
    with its assigned name and On/Off state. Confirmed against a real
    session (outlet names there followed a '<device>_PWR-<feed>' naming
    convention, e.g. 'SWC001_PWR-B')."""
    rows: list[dict[str, str]] = []
    for line in output.splitlines():
        match = re.match(r"\s*(\d+):\s*(\S+):\s*(On|Off)\s*$", line)
        if match:
            rows.append({"outlet": match.group(1), "name": match.group(2), "status": match.group(3)})
    return rows


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

        is_wlc = False
        if device.device_type == "cisco_wlc":
            # Classic AireOS-based WLC (5500/8500/WiSM2/2500 series). This is
            # a different OS from IOS/IOS-XE with no privileged/enable mode
            # at all, so skip that step entirely rather than risk the
            # "Failed to enter enable mode" error that comes from trying it
            # against a platform that doesn't support it.
            connection.send_command("config paging disable", read_timeout=15)

            attempted = successful = failed = 0
            notify({"type": "log", "message": f"{device.name}: collecting show sysinfo"})
            show_sysinfo, sysinfo_status = run_command(connection, "show sysinfo", 60)
            attempted += 1
            successful += sysinfo_status == "SUCCESS"
            failed += sysinfo_status != "SUCCESS"

            notify({"type": "log", "message": f"{device.name}: collecting show inventory"})
            show_inventory, inv_status = run_command(connection, "show inventory", 60)
            attempted += 1
            successful += inv_status == "SUCCESS"
            failed += inv_status != "SUCCESS"

            sysinfo_details = extract_aireos_sysinfo(show_sysinfo)
            inventory_details = extract_version_details("", show_inventory)
            result.software_version = sysinfo_details["product_version"]
            result.model = inventory_details["model"]
            result.serial_number = inventory_details["serial_number"]
            result.platform = "Cisco AireOS WLC"
            hostname = sysinfo_details["system_name"] or device.name
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
            append_section(parts, "show sysinfo", show_sysinfo, sysinfo_status)
            append_section(parts, "show inventory", show_inventory, inv_status)

            commands: list[tuple[str, int]] = list(AIREOS_COMMANDS)
            if custom_commands:
                commands.extend((command, 600) for command in custom_commands)
            seen: set[str] = {"show sysinfo", "show inventory"}
        elif device.device_type == "generic_termserver":
            # APC AOS (Network Management Card) switched PDU. Like AireOS,
            # this has no privileged/enable mode at all - confirmed directly
            # from a real session (no enable-mode transition anywhere in
            # the captured CLI). No pagination workaround either - none was
            # observed for any command in that same real capture.
            attempted = successful = failed = 0
            notify({"type": "log", "message": f"{device.name}: collecting about"})
            about_output, about_status = run_command(connection, "about", 60)
            attempted += 1
            successful += about_status == "SUCCESS"
            failed += about_status != "SUCCESS"

            notify({"type": "log", "message": f"{device.name}: collecting system"})
            system_output, system_status = run_command(connection, "system", 60)
            attempted += 1
            successful += system_status == "SUCCESS"
            failed += system_status != "SUCCESS"

            about_details = parse_apc_about(about_output)
            system_details = parse_apc_system(system_output)
            result.model = about_details["model"]
            result.serial_number = about_details["serial_number"]
            result.platform = "APC PDU (AOS)"
            hostname = system_details["hostname"] or device.name
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
            append_section(parts, "about", about_output, about_status)
            append_section(parts, "system", system_output, system_status)

            commands = list(APC_COMMANDS)
            if custom_commands:
                commands.extend((command, 600) for command in custom_commands)
            seen = {"about", "system"}
        else:
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

            seen: set[str] = {"show version", "show inventory"}

        show_logging_output = ""
        aireos_ap_ethernet_output = ""
        aireos_ap_cdp_output = ""
        aireos_ap_summary_output = ""
        aireos_ap_inventory_output = ""
        for command, timeout in commands:
            if command in seen:
                continue
            seen.add(command)
            if cancelled():
                notify({"type": "log", "message": f"{hostname}: cancellation requested - stopping before {command}"})
                break
            notify({"type": "log", "message": f"{hostname}: collecting {command}"})
            if command == "show run-config":
                output, status = run_command_with_confirmation(connection, command, timeout)
            else:
                output, status = run_command(connection, command, timeout)
            attempted += 1
            successful += status == "SUCCESS"
            failed += status != "SUCCESS"
            append_section(parts, command, output, status)
            if command == "show logging" and status == "SUCCESS":
                show_logging_output = output
            if command == "show ap stats ethernet summary" and status == "SUCCESS":
                aireos_ap_ethernet_output = output
            if command == "show ap cdp neighbors all" and status == "SUCCESS":
                aireos_ap_cdp_output = output
            if command == "show ap summary" and status == "SUCCESS":
                aireos_ap_summary_output = output
            if command == "show ap inventory all" and status == "SUCCESS":
                aireos_ap_inventory_output = output

        if device.device_type == "cisco_wlc" and any([aireos_ap_ethernet_output, aireos_ap_cdp_output, aireos_ap_summary_output, aireos_ap_inventory_output]):
            ap_names = {row["ap_name"] for row in parse_aireos_ap_ethernet_summary(aireos_ap_ethernet_output)}
            ap_names |= {row["ap_name"] for row in parse_aireos_ap_cdp_neighbors(aireos_ap_cdp_output)}
            ap_names |= {row["ap_name"] for row in parse_aireos_ap_summary(aireos_ap_summary_output)}
            ap_names |= {row["ap_name"] for row in parse_aireos_ap_inventory(aireos_ap_inventory_output)}
            result.access_point_count = len(ap_names)

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
    retry_indices: set[int] | None = None,
    existing_results: dict[int, DeviceResult] | None = None,
) -> None:
    """retry_indices/existing_results let this re-run just a subset of a
    previous job's devices (the ones that failed/were cancelled) while
    keeping every other device's prior result intact in the final merged
    output - so retrying a failed device never loses what already
    succeeded. When retry_indices is None, every device is (re)collected,
    matching the original full-job behavior."""
    job_dir = storage_root / job_id
    job_dir.mkdir(parents=True, exist_ok=True)
    results_by_index: list[DeviceResult | None] = [None] * len(devices)
    collect_indices = retry_indices if retry_indices is not None else set(range(len(devices)))
    if existing_results:
        for index, prior in existing_results.items():
            if index not in collect_indices:
                results_by_index[index] = prior
    worker_count = max(1, min(int(concurrent_devices), 20, len(collect_indices) or 1))
    authentication_lock = threading.Lock() if sequential_authentication else None
    if cancel_event is None:
        cancel_event = threading.Event()
    if active_connections is None:
        active_connections = {}
    if connections_lock is None:
        connections_lock = threading.Lock()
    notify({"type": "job_started", "total": len(devices), "concurrent_devices": worker_count})
    kept_count = len(devices) - len(collect_indices)
    if kept_count:
        notify({"type": "log", "message": f"Keeping {kept_count} previously-collected device result(s); (re)collecting {len(collect_indices)}"})
    notify({"type": "log", "message": f"Starting collection with {worker_count} worker(s)"})
    if sequential_authentication:
        notify({"type": "log", "message": f"MFA mode enabled: SSH authentication is sequential; authenticated devices collect in parallel (authentication timeout {auth_timeout}s)"})
    else:
        notify({"type": "log", "message": f"Parallel authentication enabled (authentication timeout {auth_timeout}s)"})

    with ThreadPoolExecutor(max_workers=worker_count, thread_name_prefix="device-collector") as executor:
        future_map = {}
        for index, device in enumerate(devices):
            if index not in collect_indices:
                continue
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

        complete_count = sum(1 for item in results_by_index if item is not None)
        total = len(devices)
        if complete_count:
            # Reflect the carried-over devices in progress immediately, rather
            # than looking like the job is starting from zero.
            kept = [item for item in results_by_index if item is not None]
            notify({
                "type": "progress", "complete": complete_count, "total": total,
                "successful": sum(item.status == "SUCCESS" for item in kept),
                "failed": sum(item.status == "FAILED" for item in kept),
                "cancelled": sum(item.status == "CANCELLED" for item in kept),
                "active": min(worker_count, len(collect_indices)),
                "queued": max(0, len(collect_indices) - worker_count),
            })
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
                "total": total,
                "successful": sum(item.status == "SUCCESS" for item in completed),
                "failed": sum(item.status == "FAILED" for item in completed),
                "cancelled": sum(item.status == "CANCELLED" for item in completed),
                "active": min(worker_count, total - complete_count),
                "queued": max(0, total - complete_count - worker_count),
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