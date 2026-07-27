from __future__ import annotations

import ipaddress
import platform
import re
import socket
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass
from typing import Iterable


@dataclass
class NetworkTestResult:
    index: int
    target: str
    ping_status: str = "FAILED"
    latency_ms: float | None = None
    resolved_ip: str = ""
    all_addresses: str = ""
    reverse_dns: str = ""
    dns_status: str = "FAILED"
    error: str = ""


def _unique(values: Iterable[str]) -> list[str]:
    return list(dict.fromkeys(value for value in values if value))


def resolve_target(target: str) -> tuple[list[str], str, str]:
    """Return resolved addresses, reverse DNS name, and any DNS error."""
    addresses: list[str] = []
    reverse_name = ""
    errors: list[str] = []

    try:
        ipaddress.ip_address(target)
        addresses = [target]
    except ValueError:
        try:
            info = socket.getaddrinfo(target, None, type=socket.SOCK_STREAM)
            addresses = _unique(item[4][0] for item in info)
        except socket.gaierror as exc:
            errors.append(f"Forward DNS failed: {exc}")

    reverse_target = addresses[0] if addresses else ""
    if reverse_target:
        try:
            reverse_name = socket.gethostbyaddr(reverse_target)[0]
        except (socket.herror, socket.gaierror, OSError) as exc:
            errors.append(f"Reverse DNS failed: {exc}")

    return addresses, reverse_name, "; ".join(errors)


def ping_target(target: str, timeout_seconds: int = 2) -> tuple[bool, float | None, str]:
    system = platform.system().lower()
    if system == "windows":
        command = ["ping", "-n", "1", "-w", str(timeout_seconds * 1000), target]
    elif system == "darwin":
        command = ["ping", "-c", "1", "-W", str(timeout_seconds * 1000), target]
    else:
        command = ["ping", "-c", "1", "-W", str(timeout_seconds), target]

    started = time.perf_counter()
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout_seconds + 2,
            check=False,
            shell=False,
        )
    except subprocess.TimeoutExpired:
        return False, None, "Ping timed out"
    except FileNotFoundError:
        return False, None, "System ping command was not found"
    except OSError as exc:
        return False, None, f"Ping failed: {exc}"

    elapsed_ms = round((time.perf_counter() - started) * 1000, 2)
    output = f"{completed.stdout}\n{completed.stderr}"
    match = re.search(r"time[=<]\s*(\d+(?:\.\d+)?)\s*ms", output, re.IGNORECASE)
    latency = float(match.group(1)) if match else elapsed_ms

    if completed.returncode == 0:
        return True, latency, ""
    return False, None, "No ping reply"


def test_target(index: int, target: str, timeout_seconds: int = 2) -> NetworkTestResult:
    result = NetworkTestResult(index=index, target=target)
    addresses, reverse_name, dns_error = resolve_target(target)
    result.resolved_ip = addresses[0] if addresses else ""
    result.all_addresses = ", ".join(addresses)
    result.reverse_dns = reverse_name
    result.dns_status = "SUCCESS" if addresses or reverse_name else "FAILED"

    ping_ok, latency, ping_error = ping_target(target, timeout_seconds=timeout_seconds)
    result.ping_status = "SUCCESS" if ping_ok else "FAILED"
    result.latency_ms = latency

    errors = [message for message in (dns_error, ping_error) if message]
    result.error = "; ".join(errors)
    return result


def run_bulk_tests(targets: list[str], timeout_seconds: int = 2, workers: int = 20) -> list[dict]:
    results: list[NetworkTestResult | None] = [None] * len(targets)
    worker_count = max(1, min(workers, 50, len(targets) or 1))

    with ThreadPoolExecutor(max_workers=worker_count, thread_name_prefix="network-test") as executor:
        futures = {
            executor.submit(test_target, index, target, timeout_seconds): index
            for index, target in enumerate(targets)
        }
        for future in as_completed(futures):
            index = futures[future]
            try:
                results[index] = future.result()
            except Exception as exc:  # Defensive: preserve every input row.
                results[index] = NetworkTestResult(
                    index=index,
                    target=targets[index],
                    error=f"Unexpected error: {type(exc).__name__}: {exc}",
                )

    return [asdict(result) for result in results if result is not None]
