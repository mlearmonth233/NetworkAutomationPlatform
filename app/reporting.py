from __future__ import annotations

import html
import re
import zipfile
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable
from xml.etree.ElementTree import Element, SubElement, tostring

from .collector import (
    DeviceResult,
    parse_aireos_ap_cdp_neighbors,
    parse_aireos_ap_ethernet_summary,
    parse_aireos_ap_inventory,
    parse_aireos_ap_summary,
)
from .log_analysis import analyze_show_logging

SECTION_RE = re.compile(
    r"={20,}\nCOMMAND:\s*(.*?)\nSTATUS\s*:\s*(.*?)\n={20,}\n\n?(.*?)(?=\n\n={20,}\nCOMMAND:|\n\n={20,}\nEND OF COLLECTION|\Z)",
    re.DOTALL,
)


def parse_sections(text: str) -> dict[str, dict[str, str]]:
    sections: dict[str, dict[str, str]] = {}
    for command, status, output in SECTION_RE.findall(text):
        sections[command.strip().lower()] = {"status": status.strip(), "output": output.strip()}
    return sections


def split_columns(line: str) -> list[str]:
    return [part.strip() for part in re.split(r"\s{2,}", line.rstrip()) if part.strip()]


def normalise_mac(value: str) -> str:
    raw = re.sub(r"[^0-9A-Fa-f]", "", value)
    if len(raw) == 12:
        return ":".join(raw[i:i + 2] for i in range(0, 12, 2)).upper()
    return value.strip()


def parse_ap_config(output: str, controller: str, controller_ip: str) -> list[dict[str, Any]]:
    # C9800 output uses repeated labelled blocks. Split before the AP name label while
    # retaining the label, then promote the most useful technical-review fields.
    starts = list(re.finditer(r"(?im)^(?:Cisco\s+)?AP\s+(?:Name|Identifier)\s*[:.]", output))
    if not starts:
        starts = list(re.finditer(r"(?im)^AP Name\s*[:.]", output))
    blocks: list[str] = []
    if starts:
        for idx, match in enumerate(starts):
            end = starts[idx + 1].start() if idx + 1 < len(starts) else len(output)
            blocks.append(output[match.start():end])
    else:
        blocks = [output]

    aliases = {
        "hostname": [r"^(?:Cisco\s+)?AP\s+(?:Name|Identifier)\s*[:.]\s*(.+)$", r"^AP Name\s*[:.]\s*(.+)$"],
        "mac_address": [r"^(?:AP |Ethernet )?MAC Address\s*[:.]\s*(\S+)", r"^Base Radio MAC\s*[:.]\s*(\S+)"],
        "ip_address": [r"^IP(?:v4)? Address\s*[:.]\s*(\S+)", r"^AP IP Address\s*[:.]\s*(\S+)"],
        "serial_number": [r"^(?:AP )?Serial Number\s*[:.]\s*(\S+)", r"^Serial Number\s*[:.]\s*(\S+)"],
        "model": [r"^(?:AP )?Model(?: Number)?\s*[:.]\s*(\S+)", r"^Product/Model Number\s*[:.]\s*(\S+)"],
        "software_version": [r"^(?:AP )?(?:IOS|Software|Image) Version\s*[:.]\s*(.+)$"],
        "site_tag": [r"^Site Tag Name\s*[:.]\s*(.+)$", r"^Site Tag\s*[:.]\s*(.+)$"],
        "policy_tag": [r"^Policy Tag Name\s*[:.]\s*(.+)$", r"^Policy Tag\s*[:.]\s*(.+)$"],
        "rf_tag": [r"^RF Tag Name\s*[:.]\s*(.+)$", r"^RF Tag\s*[:.]\s*(.+)$"],
        "location": [r"^(?:AP )?Location\s*[:.]\s*(.+)$"],
        "country": [r"^Country Code\s*[:.]\s*(.+)$"],
        "uptime": [r"^(?:AP )?Uptime\s*[:.]\s*(.+)$"],
        "join_time": [r"^(?:Last )?Join Time\s*[:.]\s*(.+)$"],
        "state": [r"^(?:AP )?(?:Operational )?State\s*[:.]\s*(.+)$"],
        "primary_controller": [r"^Primary Controller Name\s*[:.]\s*(.+)$"],
        "secondary_controller": [r"^Secondary Controller Name\s*[:.]\s*(.+)$"],
    }

    rows: list[dict[str, Any]] = []
    for block in blocks:
        row: dict[str, Any] = {"controller": controller, "controller_ip": controller_ip}
        for key, patterns in aliases.items():
            for pattern in patterns:
                match = re.search(pattern, block, re.MULTILINE | re.IGNORECASE)
                if match:
                    row[key] = match.group(1).strip()
                    break
        if row.get("mac_address"):
            row["mac_address"] = normalise_mac(str(row["mac_address"]))
        if row.get("hostname") or row.get("mac_address") or row.get("serial_number"):
            rows.append(row)
    return rows


def parse_interface_status(output: str, device: str, management_ip: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line in output.splitlines():
        if not line.strip() or line.lstrip().startswith(("Port ", "----", "Legend")):
            continue
        parts = split_columns(line)
        if len(parts) >= 4 and re.match(r"^(?:Gi|Te|Twe|Fo|Hu|Eth|Po|Fa|Vl|mgmt|Lo)\S*", parts[0], re.I):
            row = {"device": device, "management_ip": management_ip, "interface": parts[0]}
            # show interfaces status normally produces Port, Name, Status, Vlan, Duplex, Speed, Type.
            fields = ["description", "status", "vlan", "duplex", "speed", "type"]
            for key, value in zip(fields, parts[1:]):
                row[key] = value
            rows.append(row)
    return rows


def parse_ip_interface_brief(output: str, device: str, management_ip: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line in output.splitlines():
        if not line.strip() or line.lower().startswith("interface") or set(line.strip()) <= {"-"}:
            continue
        parts = line.split()
        if len(parts) >= 6 and re.match(r"^[A-Za-z].*\d", parts[0]):
            rows.append({
                "device": device,
                "management_ip": management_ip,
                "interface": parts[0],
                "ip_address": parts[1],
                "ok": parts[2],
                "method": parts[3],
                "status": " ".join(parts[4:-1]),
                "protocol": parts[-1],
            })
    return rows


def parse_vlans(output: str, device: str, management_ip: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line in output.splitlines():
        match = re.match(r"^\s*(\d+)\s+(\S.*?)\s{2,}(active|act/unsup|suspended|shutdown)\s*(.*)$", line, re.I)
        if match:
            rows.append({"device": device, "management_ip": management_ip, "vlan_id": int(match.group(1)),
                         "name": match.group(2).strip(), "status": match.group(3), "ports": match.group(4).strip()})
    return rows


def parse_neighbors(output: str, device: str, management_ip: str, protocol: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if protocol == "CDP":
        blocks = re.split(r"(?m)^-+\s*$", output)
        for block in blocks:
            dev = re.search(r"(?im)^Device ID:\s*(.+)$", block)
            local = re.search(r"(?im)^Interface:\s*([^,]+),\s*Port ID \(outgoing port\):\s*(.+)$", block)
            ip = re.search(r"(?im)^\s*IP address:\s*(\S+)", block)
            platform = re.search(r"(?im)^Platform:\s*([^,]+)", block)
            if dev:
                rows.append({"device": device, "management_ip": management_ip, "protocol": protocol,
                             "neighbor": dev.group(1).strip(), "neighbor_ip": ip.group(1) if ip else "",
                             "local_interface": local.group(1).strip() if local else "",
                             "remote_interface": local.group(2).strip() if local else "",
                             "platform": platform.group(1).strip() if platform else ""})
    else:
        blocks = re.split(r"(?im)(?=^Local Intf:|^Local Interface:)", output)
        for block in blocks:
            local = re.search(r"(?im)^Local (?:Intf|Interface):\s*(.+)$", block)
            name = re.search(r"(?im)^(?:System Name|Chassis id):\s*(.+)$", block)
            port = re.search(r"(?im)^Port id:\s*(.+)$", block)
            mgmt = re.search(r"(?im)^Management Address(?:es)?:?\s*(?:IP:\s*)?(\S+)", block)
            if local and name:
                rows.append({"device": device, "management_ip": management_ip, "protocol": protocol,
                             "neighbor": name.group(1).strip(), "neighbor_ip": mgmt.group(1) if mgmt else "",
                             "local_interface": local.group(1).strip(), "remote_interface": port.group(1).strip() if port else "",
                             "platform": ""})
    return rows


def parse_inventory(output: str, device: str, management_ip: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    current_name = current_descr = ""
    for line in output.splitlines():
        head = re.match(r'^NAME:\s*"([^"]*)",\s*DESCR:\s*"([^"]*)"', line)
        if head:
            current_name, current_descr = head.group(1), head.group(2)
            continue
        item = re.match(r"^PID:\s*([^,]*),\s*VID:\s*([^,]*),\s*SN:\s*(\S*)", line)
        if item:
            rows.append({"device": device, "management_ip": management_ip, "name": current_name,
                         "description": current_descr, "pid": item.group(1).strip(), "vid": item.group(2).strip(),
                         "serial_number": item.group(3).strip()})
    return rows


def parse_arp(output: str, device: str, management_ip: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line in output.splitlines():
        match = re.match(r"^Internet\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)", line)
        if match:
            rows.append({"device": device, "management_ip": management_ip, "ip_address": match.group(1),
                         "age": match.group(2), "mac_address": normalise_mac(match.group(3)),
                         "type": match.group(4), "interface": match.group(5)})
    return rows


def parse_mac_table(output: str, device: str, management_ip: str) -> list[dict[str, Any]]:
    """Parses `show mac address-table` / `show mac-address-table` output.
    Written to handle both the IOS/IOS-XE layout (Vlan/Mac Address/Type/Ports)
    and the NX-OS layout (which adds a '*'/'G' primary-entry marker prefix
    and extra age/Secure/NTFY columns before Ports) with one pattern, since
    a MAC address and the dynamic/static keyword are distinctive enough
    anchors regardless of how many columns sit between them and the port
    field at the end of the line. A static entry mapped to several ports at
    once (e.g. a multicast MAC) is expanded into one row per port so the
    sheet stays a simple one-MAC-to-one-port lookup."""
    rows: list[dict[str, Any]] = []
    pattern = re.compile(
        r"^\**\s*[A-Za-z]?\s*(\d+)\s+([0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4})\s+"
        r"(dynamic|static|self)\b.*?\s(\S+)\s*$",
        re.IGNORECASE,
    )
    for line in output.splitlines():
        match = pattern.match(line.strip())
        if not match:
            continue
        vlan, mac, entry_type, ports = match.group(1), match.group(2), match.group(3).upper(), match.group(4)
        for port in ports.split(","):
            port = port.strip()
            if port:
                rows.append({
                    "device": device, "management_ip": management_ip, "vlan": vlan,
                    "mac_address": normalise_mac(mac), "type": entry_type, "port": port,
                })
    return rows


_ROUTE_AGE_PATTERN = re.compile(r"^(\d+w\d+d|\d+d\d+h|\d\d:\d\d:\d\d|\d+h\d+m|never)$")


def _finalize_route_via(code: str, prefix: str, rest: str, device: str, management_ip: str) -> dict[str, Any] | None:
    match = re.search(r"via\s+(\d+\.\d+\.\d+\.\d+)\s*,?\s*(.*)$", rest.strip())
    if not match:
        return None
    next_hop = match.group(1)
    tail_parts = [part.strip() for part in match.group(2).split(",") if part.strip()]
    age = interface = ""
    if len(tail_parts) >= 2:
        age, interface = tail_parts[0], tail_parts[1]
    elif len(tail_parts) == 1:
        # A lone trailing field could be either the age or the interface
        # (e.g. a static route configured with just an exit interface and no
        # age at all) - distinguish by shape rather than assuming position.
        if _ROUTE_AGE_PATTERN.match(tail_parts[0]):
            age = tail_parts[0]
        else:
            interface = tail_parts[0]
    return {
        "device": device, "management_ip": management_ip, "code": code, "prefix": prefix,
        "next_hop": next_hop, "age": age, "interface": interface,
        "is_default": prefix == "0.0.0.0/0" or "*" in code,
    }


def parse_routes(output: str, device: str, management_ip: str) -> list[dict[str, Any]]:
    """Parses IOS/IOS-XE `show ip route` output. Handles the three shapes a
    route entry can take: connected/local routes (no via-clause at all, just
    'is directly connected'), a single line with the via-clause included,
    and a two-line wrap (code+prefix on one line, the via-clause on the
    next) which IOS uses for longer multi-letter codes like 'D EX'/'O E2'
    and for additional equal-cost paths. Confirmed against constructed
    samples covering all of these; NX-OS uses a structurally different
    format ('*via ... protocol-name' with no leading code letter) not
    covered here."""
    rows: list[dict[str, Any]] = []
    pending: tuple[str, str] | None = None

    for raw_line in output.splitlines():
        line = raw_line.rstrip("\n")
        stripped = line.strip()
        if not stripped:
            continue

        connected = re.match(r"^([A-Za-z*]+(?:\s[A-Za-z0-9]+)?)\s+(\S+)\s+is directly connected,\s*(\S+)", line)
        if connected:
            code, prefix, interface = connected.group(1), connected.group(2), connected.group(3)
            rows.append({
                "device": device, "management_ip": management_ip, "code": code, "prefix": prefix,
                "next_hop": "", "age": "", "interface": interface,
                "is_default": prefix == "0.0.0.0/0" or "*" in code,
            })
            pending = None
            continue

        headed = re.match(r"^([A-Za-z*]+(?:\s[A-Za-z0-9]+)?)\s+(\d+\.\d+\.\d+\.\d+(?:/\d+)?)\s*(.*)$", line)
        if headed and not re.search(r"is variably subnetted|is subnetted", line):
            code, prefix, rest = headed.group(1), headed.group(2), headed.group(3).strip()
            if rest:
                row = _finalize_route_via(code, prefix, rest, device, management_ip)
                if row:
                    rows.append(row)
                    pending = (code, prefix)  # further via-only lines may follow (ECMP)
                    continue
            pending = (code, prefix)  # no via on this line - expect it on the next
            continue

        if pending and re.match(r"^\s*(?:\[[^\]]+\]\s*)?via\s+\S+", line):
            code, prefix = pending
            row = _finalize_route_via(code, prefix, stripped, device, management_ip)
            if row:
                rows.append(row)
            continue

        pending = None  # banner text, subnet-summary lines, etc. reset context
    return rows


def parse_port_channels(output: str, device: str, management_ip: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line in output.splitlines():
        match = re.match(r"^\s*(\d+)\s+(Po\d+\([^)]*\))\s+(\S+)\s+(.+)$", line)
        if match:
            port_channel = match.group(2)
            member_ports = match.group(4).strip()
            # The aggregate's own flag can be a combo like "(SD)" (Layer2 +
            # Down) - a bare uppercase D anywhere in it means the whole
            # port-channel is down. Each member's flag is always a single
            # character, so "(D)" there means specifically that one link is
            # down (Cisco's legend uses lowercase for unrelated states like
            # 's' suspended or 'd' default-port, so this is deliberately
            # case-sensitive and exact for members).
            aggregate_flag = re.search(r"\(([^)]*)\)", port_channel)
            aggregate_down = bool(aggregate_flag and "D" in aggregate_flag.group(1))
            member_down = "(D)" in member_ports
            rows.append({
                "device": device, "management_ip": management_ip, "group": int(match.group(1)),
                "port_channel": port_channel, "protocol": match.group(3), "member_ports": member_ports,
                "has_down_link": aggregate_down or member_down,
            })
    return rows


def collect_report_data(results: list[DeviceResult]) -> dict[str, list[dict[str, Any]]]:
    data: dict[str, list[dict[str, Any]]] = {
        "devices": [], "aps": [], "interfaces": [], "vlans": [], "neighbors": [],
        "port_channels": [], "routes": [], "arp": [], "mac_table": [], "inventory": [], "commands": [], "log_alerts": [],
    }
    for result in sorted(results, key=lambda row: row.index):
        data["devices"].append({
            "inventory_name": result.inventory_name, "hostname": result.detected_hostname,
            "management_ip": result.host, "status": result.status, "platform": result.platform,
            "model": result.model, "serial_number": result.serial_number,
            "software_version": result.software_version, "access_point_count": result.access_point_count,
            "log_alert_count": result.log_alert_count, "log_highest_severity": result.log_highest_severity,
            "log_file": Path(result.log_file).name if result.log_file else "", "error": result.error,
        })
        if not result.log_file or not Path(result.log_file).exists():
            continue
        text = Path(result.log_file).read_text(encoding="utf-8", errors="replace")
        sections = parse_sections(text)
        hostname = result.detected_hostname or result.inventory_name
        for command, section in sections.items():
            data["commands"].append({"device": hostname, "management_ip": result.host, "command": command,
                                     "status": section["status"], "output_characters": len(section["output"])})
        if "show logging" in sections:
            for alert in analyze_show_logging(sections["show logging"]["output"]):
                data["log_alerts"].append({
                    "device": hostname,
                    "management_ip": result.host,
                    "severity": alert["severity"],
                    "severity_number": alert["severity_number"],
                    "category": alert["category"],
                    "facility": alert["facility"],
                    "mnemonic": alert["mnemonic"],
                    "occurrences": alert["occurrences"],
                    "first_seen": alert["first_seen"],
                    "last_seen": alert["last_seen"],
                    "message": alert["message"],
                    "raw_example": alert["raw_example"],
                })
        if "show ap config general" in sections:
            data["aps"].extend(parse_ap_config(sections["show ap config general"]["output"], hostname, result.host))
        elif any(cmd in sections for cmd in (
            "show ap stats ethernet summary", "show ap cdp neighbors all", "show ap summary", "show ap inventory all",
        )):
            # AireOS path: merge whichever of these four commands ran, keyed
            # by AP name, since together they cover hostname, IP address,
            # MAC address, model, and serial number.
            ap_rows: dict[str, dict[str, Any]] = {}

            def ap_row(ap_name: str) -> dict[str, Any]:
                return ap_rows.setdefault(ap_name, {
                    "controller": hostname, "controller_ip": result.host, "hostname": ap_name,
                })

            if "show ap stats ethernet summary" in sections:
                for row in parse_aireos_ap_ethernet_summary(sections["show ap stats ethernet summary"]["output"]):
                    ap_row(row["ap_name"])
            if "show ap summary" in sections:
                for row in parse_aireos_ap_summary(sections["show ap summary"]["output"]):
                    entry = ap_row(row["ap_name"])
                    entry["model"] = row["model"]
                    entry["mac_address"] = row["mac_address"]
            if "show ap inventory all" in sections:
                for row in parse_aireos_ap_inventory(sections["show ap inventory all"]["output"]):
                    entry = ap_row(row["ap_name"])
                    entry.setdefault("model", row["model"])
                    entry["serial_number"] = row["serial_number"]
            if "show ap cdp neighbors all" in sections:
                for row in parse_aireos_ap_cdp_neighbors(sections["show ap cdp neighbors all"]["output"]):
                    entry = ap_row(row["ap_name"])
                    entry["ip_address"] = row["ap_ip"]
                    entry["neighbor_name"] = row["neighbor_name"]
                    entry["neighbor_ip"] = row["neighbor_ip"]
                    entry["neighbor_port"] = row["neighbor_port"]
            data["aps"].extend(ap_rows.values())
        if "show interfaces status" in sections:
            data["interfaces"].extend(parse_interface_status(sections["show interfaces status"]["output"], hostname, result.host))
        if "show ip interface brief" in sections:
            ip_rows = parse_ip_interface_brief(sections["show ip interface brief"]["output"], hostname, result.host)
            # Merge IP information into status rows where possible; otherwise append standalone records.
            by_name = {(r["device"], r["interface"]): r for r in data["interfaces"] if r["device"] == hostname}
            for ip_row in ip_rows:
                existing = by_name.get((hostname, ip_row["interface"]))
                if existing:
                    existing.update({"ip_address": ip_row["ip_address"], "protocol": ip_row["protocol"]})
                else:
                    data["interfaces"].append(ip_row)
        if "show vlan" in sections:
            data["vlans"].extend(parse_vlans(sections["show vlan"]["output"], hostname, result.host))
        for command in ("show cdp neighbors detail", "show cdp neighbor detail"):
            if command in sections:
                data["neighbors"].extend(parse_neighbors(sections[command]["output"], hostname, result.host, "CDP"))
                break
        for command in ("show lldp neighbors detail", "show lldp neighbor detail"):
            if command in sections:
                data["neighbors"].extend(parse_neighbors(sections[command]["output"], hostname, result.host, "LLDP"))
                break
        if "show inventory" in sections:
            data["inventory"].extend(parse_inventory(sections["show inventory"]["output"], hostname, result.host))
        if "show ip arp" in sections:
            data["arp"].extend(parse_arp(sections["show ip arp"]["output"], hostname, result.host))
        for command in ("show mac address-table", "show mac-address-table"):
            if command in sections:
                data["mac_table"].extend(parse_mac_table(sections[command]["output"], hostname, result.host))
        if "show ip route" in sections:
            data["routes"].extend(parse_routes(sections["show ip route"]["output"], hostname, result.host))
        else:
            for command in ("show ip route 0.0.0.0", "show ip route summary"):
                if command in sections:
                    data["routes"].extend(parse_routes(sections[command]["output"], hostname, result.host))
        for command in ("show etherchannel summary", "show port-channel summary"):
            if command in sections:
                data["port_channels"].extend(parse_port_channels(sections[command]["output"], hostname, result.host))
    return data


# Minimal standards-compliant XLSX writer. It uses only Python's standard library,
# avoiding a heavyweight spreadsheet dependency in the local collector.
class SimpleXlsxWriter:
    def __init__(self) -> None:
        self.sheets: list[tuple[str, list[list[Any]], list[int], set[int]]] = []

    def add_sheet(self, name: str, rows: list[list[Any]], widths: list[int] | None = None, highlight_rows: set[int] | None = None) -> None:
        safe = re.sub(r"[\\/*?:\[\]]", "-", name)[:31] or "Sheet"
        self.sheets.append((safe, rows, widths or [], highlight_rows or set()))

    @staticmethod
    def _col_name(index: int) -> str:
        value = index + 1
        out = ""
        while value:
            value, rem = divmod(value - 1, 26)
            out = chr(65 + rem) + out
        return out

    @staticmethod
    def _cell(ref: str, value: Any, style: int = 0) -> str:
        if value is None:
            return f'<c r="{ref}" s="{style}"/>'
        if isinstance(value, bool):
            return f'<c r="{ref}" s="{style}" t="b"><v>{1 if value else 0}</v></c>'
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            return f'<c r="{ref}" s="{style}"><v>{value}</v></c>'
        text = html.escape(str(value), quote=False)
        return f'<c r="{ref}" s="{style}" t="inlineStr"><is><t xml:space="preserve">{text}</t></is></c>'

    def _sheet_xml(self, rows: list[list[Any]], widths: list[int], highlight_rows: set[int] | None = None) -> bytes:
        highlight_rows = highlight_rows or set()
        max_cols = max((len(r) for r in rows), default=1)
        max_rows = max(len(rows), 1)
        cols = ""
        for idx in range(max_cols):
            width = widths[idx] if idx < len(widths) else 18
            cols += f'<col min="{idx + 1}" max="{idx + 1}" width="{max(8, min(width, 45))}" customWidth="1"/>'
        sheet_rows: list[str] = []
        for r_idx, row in enumerate(rows, start=1):
            if r_idx == 1:
                style = 1  # header
            elif (r_idx - 2) in highlight_rows:  # r_idx-2 converts back to the 0-based data-row index
                style = 2  # highlighted (e.g. a port channel with a down link)
            else:
                style = 0  # normal
            cells = "".join(self._cell(f"{self._col_name(c_idx)}{r_idx}", value, style)
                            for c_idx, value in enumerate(row))
            sheet_rows.append(f'<row r="{r_idx}" ht="{24 if r_idx == 1 else 18}" customHeight="1">{cells}</row>')
        last = f"{self._col_name(max_cols - 1)}{max_rows}"
        xml = f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
  <dimension ref="A1:{last}"/>
  <sheetViews><sheetView workbookViewId="0"><pane ySplit="1" topLeftCell="A2" activePane="bottomLeft" state="frozen"/></sheetView></sheetViews>
  <sheetFormatPr defaultRowHeight="18"/>
  <cols>{cols}</cols>
  <sheetData>{''.join(sheet_rows)}</sheetData>
  <autoFilter ref="A1:{last}"/>
</worksheet>'''
        return xml.encode("utf-8")

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        sheet_entries = "".join(f'<sheet name="{html.escape(name, quote=True)}" sheetId="{idx}" r:id="rId{idx}"/>'
                                for idx, (name, _, _, _) in enumerate(self.sheets, start=1))
        rels = "".join(f'<Relationship Id="rId{idx}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet{idx}.xml"/>'
                       for idx in range(1, len(self.sheets) + 1))
        rels += f'<Relationship Id="rId{len(self.sheets)+1}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>'
        overrides = "".join(f'<Override PartName="/xl/worksheets/sheet{idx}.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
                            for idx in range(1, len(self.sheets) + 1))
        created = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
        styles = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
<fonts count="2"><font><sz val="10"/><name val="Aptos"/></font><font><b/><color rgb="FFFFFFFF"/><sz val="10"/><name val="Aptos"/></font></fonts>
<fills count="4"><fill><patternFill patternType="none"/></fill><fill><patternFill patternType="gray125"/></fill><fill><patternFill patternType="solid"><fgColor rgb="FF17365D"/><bgColor indexed="64"/></patternFill></fill><fill><patternFill patternType="solid"><fgColor rgb="FFFDE2E1"/><bgColor indexed="64"/></patternFill></fill></fills>
<borders count="2"><border><left/><right/><top/><bottom/><diagonal/></border><border><left style="thin"><color rgb="FFD9E2F3"/></left><right style="thin"><color rgb="FFD9E2F3"/></right><top style="thin"><color rgb="FFD9E2F3"/></top><bottom style="thin"><color rgb="FFD9E2F3"/></bottom><diagonal/></border></borders>
<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>
<cellXfs count="3"><xf numFmtId="0" fontId="0" fillId="0" borderId="1" xfId="0" applyBorder="1"/><xf numFmtId="0" fontId="1" fillId="2" borderId="1" xfId="0" applyFont="1" applyFill="1" applyBorder="1" applyAlignment="1"><alignment horizontal="center" vertical="center" wrapText="1"/></xf><xf numFmtId="0" fontId="0" fillId="3" borderId="1" xfId="0" applyFill="1" applyBorder="1"/></cellXfs>
<cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles>
</styleSheet>'''
        with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("[Content_Types].xml", f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/>
<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>
<Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>{overrides}
<Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>
<Override PartName="/docProps/app.xml" ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"/></Types>''')
            archive.writestr("_rels/.rels", '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/><Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/><Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties" Target="docProps/app.xml"/></Relationships>''')
            archive.writestr("xl/workbook.xml", f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets>{sheet_entries}</sheets></workbook>''')
            archive.writestr("xl/_rels/workbook.xml.rels", f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">{rels}</Relationships>''')
            archive.writestr("xl/styles.xml", styles)
            archive.writestr("docProps/core.xml", f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?><cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><dc:title>Network Technical Review</dc:title><dc:creator>Catalyst Config Collector</dc:creator><dcterms:created xsi:type="dcterms:W3CDTF">{created}</dcterms:created></cp:coreProperties>''')
            archive.writestr("docProps/app.xml", f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties" xmlns:vt="http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes"><Application>Catalyst Config Collector</Application><TitlesOfParts><vt:vector size="{len(self.sheets)}" baseType="lpstr">{''.join(f'<vt:lpstr>{html.escape(name)}</vt:lpstr>' for name,_,_,_ in self.sheets)}</vt:vector></TitlesOfParts></Properties>''')
            for idx, (_, rows, widths, highlight_rows) in enumerate(self.sheets, start=1):
                archive.writestr(f"xl/worksheets/sheet{idx}.xml", self._sheet_xml(rows, widths, highlight_rows))


def rows_for_sheet(records: list[dict[str, Any]], columns: list[tuple[str, str]]) -> list[list[Any]]:
    rows: list[list[Any]] = [[label for _, label in columns]]
    for record in records:
        rows.append([record.get(key, "") for key, _ in columns])
    return rows


def create_technical_review_workbook(job_dir: Path, results: list[DeviceResult]) -> Path:
    data = collect_report_data(results)
    writer = SimpleXlsxWriter()
    success = sum(1 for item in results if item.status == "SUCCESS")
    failed = sum(1 for item in results if item.status == "FAILED")
    summary_rows = [
        ["Metric", "Value"],
        ["Collection date", datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")],
        ["Devices submitted", len(results)],
        ["Successful devices", success],
        ["Failed devices", failed],
        ["Access points parsed", len(data["aps"])],
        ["Interfaces parsed", len(data["interfaces"])],
        ["VLANs parsed", len(data["vlans"])],
        ["Neighbours parsed", len(data["neighbors"])],
        ["Inventory components", len(data["inventory"])],
        ["ARP entries", len(data["arp"])],
        ["MAC address table entries", len(data["mac_table"])],
        ["Commands recorded", len(data["commands"])],
        ["Log alerts detected", len(data["log_alerts"])],
        [],
        ["Review note", "The workbook contains recognised structured data. Full command output remains in each device .log file."],
    ]
    writer.add_sheet("Summary", summary_rows, [28, 70])
    writer.add_sheet("Devices", rows_for_sheet(data["devices"], [
        ("inventory_name", "Inventory Name"), ("hostname", "Hostname"), ("management_ip", "Management IP"),
        ("status", "Collection Status"), ("platform", "Platform"), ("model", "Model"),
        ("serial_number", "Serial Number"), ("software_version", "Software Version"),
        ("access_point_count", "AP Count"), ("log_alert_count", "Log Alerts"),
        ("log_highest_severity", "Highest Log Severity"), ("log_file", "Log File"), ("error", "Error"),
    ]), [22, 24, 18, 18, 30, 20, 20, 18, 12, 12, 20, 30, 35])
    writer.add_sheet("AP Info", rows_for_sheet(data["aps"], [
        ("controller", "Controller"), ("controller_ip", "Controller IP"), ("hostname", "AP Hostname"),
        ("mac_address", "MAC Address"), ("ip_address", "IP Address"), ("serial_number", "Serial Number"),
        ("model", "Model"), ("software_version", "Software Version"), ("location", "Location"),
        ("site_tag", "Site Tag"), ("policy_tag", "Policy Tag"), ("rf_tag", "RF Tag"),
        ("country", "Country"), ("state", "State"), ("uptime", "Uptime"), ("join_time", "Join Time"),
        ("primary_controller", "Primary Controller"), ("secondary_controller", "Secondary Controller"),
        ("neighbor_name", "Neighbor Switch"), ("neighbor_ip", "Neighbor Switch IP"), ("neighbor_port", "Neighbor Port"),
    ]), [24, 18, 26, 20, 18, 20, 18, 18, 28, 24, 24, 24, 14, 16, 22, 24, 24, 24, 26, 20, 20])
    writer.add_sheet("Interfaces", rows_for_sheet(data["interfaces"], [
        ("device", "Device"), ("management_ip", "Management IP"), ("interface", "Interface"),
        ("description", "Description"), ("status", "Status"), ("protocol", "Protocol"),
        ("vlan", "VLAN"), ("duplex", "Duplex"), ("speed", "Speed"), ("type", "Type"),
        ("ip_address", "IP Address"), ("method", "Address Method"),
    ]), [24, 18, 18, 32, 16, 14, 12, 12, 12, 28, 18, 18])
    writer.add_sheet("VLANs", rows_for_sheet(data["vlans"], [
        ("device", "Device"), ("management_ip", "Management IP"), ("vlan_id", "VLAN ID"),
        ("name", "VLAN Name"), ("status", "Status"), ("ports", "Ports"),
    ]), [24, 18, 12, 28, 16, 55])
    writer.add_sheet("Neighbours", rows_for_sheet(data["neighbors"], [
        ("device", "Device"), ("management_ip", "Management IP"), ("protocol", "Protocol"),
        ("neighbor", "Neighbour"), ("neighbor_ip", "Neighbour IP"), ("local_interface", "Local Interface"),
        ("remote_interface", "Remote Interface"), ("platform", "Platform"),
    ]), [24, 18, 12, 30, 18, 20, 24, 24])
    port_channel_highlight_rows = {i for i, record in enumerate(data["port_channels"]) if record.get("has_down_link")}
    writer.add_sheet("Port Channels", rows_for_sheet(data["port_channels"], [
        ("device", "Device"), ("management_ip", "Management IP"), ("group", "Group"),
        ("port_channel", "Port Channel"), ("protocol", "Protocol"), ("member_ports", "Member Ports"),
        ("has_down_link", "Down Link?"),
    ]), [24, 18, 10, 18, 14, 50, 12], highlight_rows=port_channel_highlight_rows)
    route_highlight_rows = {i for i, record in enumerate(data["routes"]) if record.get("is_default")}
    writer.add_sheet("Routes", rows_for_sheet(data["routes"], [
        ("device", "Device"), ("management_ip", "Management IP"), ("code", "Route Code"),
        ("prefix", "Prefix"), ("next_hop", "Next Hop"), ("age", "Age"), ("interface", "Interface"),
        ("is_default", "Default Route?"),
    ]), [24, 18, 14, 22, 18, 16, 20, 14], highlight_rows=route_highlight_rows)
    writer.add_sheet("ARP", rows_for_sheet(data["arp"], [
        ("device", "Device"), ("management_ip", "Management IP"), ("ip_address", "IP Address"),
        ("mac_address", "MAC Address"), ("age", "Age"), ("type", "Type"), ("interface", "Interface"),
    ]), [24, 18, 18, 20, 10, 12, 20])
    writer.add_sheet("MAC Table", rows_for_sheet(data["mac_table"], [
        ("device", "Device"), ("management_ip", "Management IP"), ("vlan", "VLAN"),
        ("mac_address", "MAC Address"), ("type", "Type"), ("port", "Port"),
    ]), [24, 18, 10, 20, 12, 20])
    writer.add_sheet("Hardware Inventory", rows_for_sheet(data["inventory"], [
        ("device", "Device"), ("management_ip", "Management IP"), ("name", "Component Name"),
        ("description", "Description"), ("pid", "Product ID"), ("vid", "Version ID"),
        ("serial_number", "Serial Number"),
    ]), [24, 18, 28, 45, 22, 14, 20])
    writer.add_sheet("Log Alerts", rows_for_sheet(data["log_alerts"], [
        ("device", "Device"), ("management_ip", "Management IP"), ("severity", "Severity"),
        ("severity_number", "Cisco Severity"), ("category", "Category"), ("facility", "Facility"),
        ("mnemonic", "Mnemonic"), ("occurrences", "Occurrences"), ("first_seen", "First Seen"),
        ("last_seen", "Last Seen"), ("message", "Issue Message"), ("raw_example", "Raw Log Example"),
    ]), [24, 18, 14, 14, 20, 18, 22, 12, 25, 25, 65, 75])
    writer.add_sheet("Command Status", rows_for_sheet(data["commands"], [
        ("device", "Device"), ("management_ip", "Management IP"), ("command", "Command"),
        ("status", "Status"), ("output_characters", "Output Characters"),
    ]), [24, 18, 38, 22, 18])
    output = job_dir / "network-technical-review.xlsx"
    writer.save(output)
    return output