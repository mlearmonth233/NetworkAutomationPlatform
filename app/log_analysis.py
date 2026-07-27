from __future__ import annotations

import re
from collections import OrderedDict
from typing import Any

SEVERITY_NAMES = {
    0: "Emergency",
    1: "Alert",
    2: "Critical",
    3: "Error",
    4: "Warning",
    5: "Notification",
    6: "Informational",
    7: "Debugging",
}

SYSLOG_RE = re.compile(
    r"^(?P<prefix>.*?)%(?P<facility>[A-Z0-9_]+)-(?P<severity>[0-7])-(?P<mnemonic>[A-Z0-9_]+):\s*(?P<message>.*)$",
    re.IGNORECASE,
)

RECOVERY_PATTERNS = (
    r"changed state to up\b",
    r"line protocol.*state to up\b",
    r"is now up\b",
    r"recovered\b",
    r"recovery complete\b",
    r"cleared\b",
    r"unblocked\b",
    r"restored\b",
    r"became active\b",
    r"standby hot\b",
    r"authentication succeeded\b",
)

ISSUE_PATTERNS: list[tuple[str, str, int, str]] = [
    (r"crash|core dump|traceback|watchdog|unexpected reload", "System stability", 2, "Critical"),
    (r"power supply.*(?:fail|fault)|fan.*(?:fail|fault)|temperature.*critical", "Hardware", 2, "Critical"),
    (r"memory allocation failure|out of memory|mallocfail", "Resources", 2, "Critical"),
    (r"err-?disabled", "Interface", 3, "Error"),
    (r"authentication failed|auth.*failure|invalid credential", "Authentication", 3, "Error"),
    (r"radius.*(?:not responding|dead|timeout)|tacacs.*(?:not responding|dead|timeout)", "AAA", 3, "Error"),
    (r"bgp.*(?:down|reset|ceased)|ospf.*(?:down|lost|dead)|eigrp.*(?:down|lost)", "Routing", 3, "Error"),
    (r"vpc.*(?:down|failed|inconsistent)|port-channel.*(?:down|failed)", "Port channel", 3, "Error"),
    (r"duplicate (?:ip )?address|ip address conflict", "Addressing", 3, "Error"),
    (r"changed state to down\b|line protocol.*state to down\b|is down\b", "Interface", 4, "Warning"),
    (r"bpduguard|rootguard.*block|loopguard.*block|inconsistent port|loop detected", "Spanning tree", 4, "Warning"),
    (r"flap|flapping|link failure", "Interface", 4, "Warning"),
    (r"high cpu|cpu.*threshold|high memory|memory.*threshold", "Resources", 4, "Warning"),
    (r"temperature.*(?:warning|high)|overheat", "Environment", 4, "Warning"),
    (r"poe.*(?:denied|fault|overload)|power inline.*(?:denied|fault)", "PoE", 4, "Warning"),
    (r"crc error|input error|output error|packet loss|drops exceeded", "Interface errors", 4, "Warning"),
    (r"transceiver.*(?:alarm|low|high|fault)|optic.*(?:alarm|fault)", "Optics", 4, "Warning"),
    (r"license.*(?:expired|failure|error)|smart licensing.*(?:fail|error)", "Licensing", 4, "Warning"),
    (r"dhcp.*(?:fail|error|timeout)|ip helper.*(?:fail|error)", "DHCP", 4, "Warning"),
]


def _is_recovery(message: str) -> bool:
    return any(re.search(pattern, message, re.IGNORECASE) for pattern in RECOVERY_PATTERNS)


def _normalise_message(message: str) -> str:
    value = re.sub(r"\s+", " ", message.strip())
    # Replace volatile counters/timestamps while keeping addresses and interfaces useful.
    value = re.sub(r"\b\d+\s+(?:seconds?|minutes?|hours?)\b", "<duration>", value, flags=re.IGNORECASE)
    return value


def analyze_show_logging(output: str, max_alerts: int = 500) -> list[dict[str, Any]]:
    """Return deduplicated, high-confidence operational alerts from Cisco show logging output."""
    alerts: "OrderedDict[tuple[str, str, str], dict[str, Any]]" = OrderedDict()

    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line:
            continue

        syslog = SYSLOG_RE.match(line)
        facility = mnemonic = ""
        timestamp = ""
        numeric_severity: int | None = None
        message = line

        if syslog:
            timestamp = syslog.group("prefix").strip(" :")
            facility = syslog.group("facility").upper()
            mnemonic = syslog.group("mnemonic").upper()
            numeric_severity = int(syslog.group("severity"))
            message = syslog.group("message").strip()

        if _is_recovery(message):
            continue

        category = "System log"
        severity_number: int | None = None
        severity_name = ""
        matched = False

        for pattern, candidate_category, candidate_severity, candidate_name in ISSUE_PATTERNS:
            if re.search(pattern, message, re.IGNORECASE):
                category = candidate_category
                severity_number = candidate_severity
                severity_name = candidate_name
                matched = True
                break

        # Cisco severities 0-4 are normally actionable. Do not rely on severity alone
        # for known recovery messages, which were filtered above.
        if not matched and numeric_severity is not None and numeric_severity <= 4:
            severity_number = numeric_severity
            severity_name = SEVERITY_NAMES[numeric_severity]
            matched = True

        if not matched or severity_number is None:
            continue

        normalised = _normalise_message(message)
        key = (facility, mnemonic, normalised.lower())
        if key not in alerts:
            alerts[key] = {
                "severity_number": severity_number,
                "severity": severity_name or SEVERITY_NAMES.get(severity_number, "Warning"),
                "category": category,
                "facility": facility,
                "mnemonic": mnemonic,
                "message": normalised,
                "occurrences": 1,
                "first_seen": timestamp,
                "last_seen": timestamp,
                "raw_example": line,
            }
        else:
            alerts[key]["occurrences"] += 1
            if timestamp:
                alerts[key]["last_seen"] = timestamp
            if severity_number < alerts[key]["severity_number"]:
                alerts[key]["severity_number"] = severity_number
                alerts[key]["severity"] = SEVERITY_NAMES.get(severity_number, severity_name)

        if len(alerts) >= max_alerts:
            break

    return sorted(alerts.values(), key=lambda row: (row["severity_number"], -row["occurrences"], row["category"], row["message"]))


def highest_severity(alerts: list[dict[str, Any]]) -> str:
    if not alerts:
        return "None"
    return min(alerts, key=lambda row: row["severity_number"])["severity"]


def format_analysis_section(alerts: list[dict[str, Any]]) -> list[str]:
    parts = [
        "#" * 96,
        "AUTOMATED SHOW LOGGING ANALYSIS",
        "#" * 96,
        "",
        "This is a best-effort technical triage. Review the full `show logging` output before taking action.",
        "",
    ]
    if not alerts:
        parts.extend(["No high-confidence operational issues were detected.", "", ""])
        return parts

    parts.extend([
        f"Unique alerts detected : {len(alerts)}",
        f"Highest severity       : {highest_severity(alerts)}",
        "",
    ])
    for index, alert in enumerate(alerts, start=1):
        identity = "-".join(value for value in (alert["facility"], alert["mnemonic"]) if value) or "Pattern match"
        parts.extend([
            f"[{index}] {alert['severity']} | {alert['category']} | {identity}",
            f"Occurrences: {alert['occurrences']}",
            f"First seen : {alert['first_seen'] or 'Not available'}",
            f"Last seen  : {alert['last_seen'] or 'Not available'}",
            f"Message    : {alert['message']}",
            "",
        ])
    parts.append("")
    return parts
