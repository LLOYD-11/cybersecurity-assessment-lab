#!/usr/bin/env python3
"""
A simple command-line port scanner.

This tool is for learning and authorized security testing only.
Only scan systems you own or have explicit permission to test.
"""

from __future__ import annotations

import argparse
import csv
import json
import socket
import time
from dataclasses import asdict, dataclass
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path


COMMON_SERVICES = {
    20: "FTP-DATA",
    21: "FTP",
    22: "SSH",
    23: "TELNET",
    25: "SMTP",
    53: "DNS",
    67: "DHCP",
    68: "DHCP",
    69: "TFTP",
    80: "HTTP",
    110: "POP3",
    123: "NTP",
    135: "MSRPC",
    137: "NETBIOS-NS",
    138: "NETBIOS-DGM",
    139: "NETBIOS-SSN",
    143: "IMAP",
    161: "SNMP",
    162: "SNMPTRAP",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    587: "SMTP-SUBMISSION",
    631: "IPP",
    993: "IMAPS",
    995: "POP3S",
}

DEFAULT_START_PORT = 1
DEFAULT_END_PORT = 1024
DEFAULT_TIMEOUT_SECONDS = 1.0
DEFAULT_WORKERS = 100


@dataclass(frozen=True)
class ScanResult:
    port: int
    service: str
    status: str = "open"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Scan TCP ports on an authorized target.",
        epilog="Use only on systems you own or have explicit permission to test.",
    )
    parser.add_argument("target", help="Target IP address or domain name.")
    parser.add_argument(
        "--start-port",
        type=int,
        default=DEFAULT_START_PORT,
        help=f"First TCP port to scan. Default: {DEFAULT_START_PORT}.",
    )
    parser.add_argument(
        "--end-port",
        type=int,
        default=DEFAULT_END_PORT,
        help=f"Last TCP port to scan. Default: {DEFAULT_END_PORT}.",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT_SECONDS,
        help=f"Socket timeout in seconds. Default: {DEFAULT_TIMEOUT_SECONDS}.",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=DEFAULT_WORKERS,
        help=f"Maximum concurrent worker threads. Default: {DEFAULT_WORKERS}.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Optional path for saving scan results.",
    )
    parser.add_argument(
        "--format",
        choices=("json", "csv"),
        help="Output file format when --output is used. Default: json.",
    )
    return parser.parse_args()


def validate_scan_options(
    start_port: int,
    end_port: int,
    timeout: float,
    workers: int,
) -> None:
    if not 1 <= start_port <= 65535:
        raise ValueError("start port must be between 1 and 65535")
    if not 1 <= end_port <= 65535:
        raise ValueError("end port must be between 1 and 65535")
    if start_port > end_port:
        raise ValueError("start port must be less than or equal to end port")
    if timeout <= 0:
        raise ValueError("timeout must be greater than 0")
    if workers <= 0:
        raise ValueError("workers must be greater than 0")


def resolve_target(target: str) -> str:
    try:
        return socket.gethostbyname(target)
    except socket.gaierror as exc:
        raise ValueError(f"Could not resolve target: {target}") from exc


def service_name(port: int) -> str:
    if port in COMMON_SERVICES:
        return COMMON_SERVICES[port]

    try:
        return socket.getservbyport(port, "tcp").upper()
    except OSError:
        return "UNKNOWN"


def scan_port(ip_address: str, port: int, timeout: float) -> tuple[int, bool]:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        result = sock.connect_ex((ip_address, port))
        return port, result == 0


def scan_ports(
    ip_address: str,
    start_port: int = DEFAULT_START_PORT,
    end_port: int = DEFAULT_END_PORT,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    workers: int = DEFAULT_WORKERS,
) -> list[int]:
    open_ports: list[int] = []
    ports = range(start_port, end_port + 1)

    with ThreadPoolExecutor(max_workers=workers) as executor:
        future_to_port = {
            executor.submit(scan_port, ip_address, port, timeout): port
            for port in ports
        }

        for future in as_completed(future_to_port):
            port, is_open = future.result()
            if is_open:
                open_ports.append(port)

    return sorted(open_ports)


def build_results(open_ports: list[int]) -> list[ScanResult]:
    return [
        ScanResult(port=port, service=service_name(port))
        for port in open_ports
    ]


def print_results(results: list[ScanResult], elapsed: float) -> None:
    if results:
        print(f"{'Port':<8} {'Status':<8} Service")
        print(f"{'-' * 4:<8} {'-' * 6:<8} {'-' * 7}")
        for result in results:
            print(f"{result.port:<8} {result.status:<8} {result.service}")
    else:
        print("No open ports found.")

    plural = "port" if len(results) == 1 else "ports"
    print(f"\nScan completed in {elapsed:.2f} seconds. {len(results)} open {plural} found.")


def save_results(
    output_path: Path,
    output_format: str,
    target: str,
    ip_address: str,
    start_port: int,
    end_port: int,
    elapsed: float,
    results: list[ScanResult],
) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)

    if output_format == "json":
        payload = {
            "target": target,
            "ip_address": ip_address,
            "port_range": {
                "start": start_port,
                "end": end_port,
            },
            "elapsed_seconds": round(elapsed, 4),
            "open_ports": [asdict(result) for result in results],
        }
        output_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        return

    with output_path.open("w", newline="", encoding="utf-8") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=["port", "status", "service"])
        writer.writeheader()
        for result in results:
            writer.writerow(asdict(result))


def main() -> int:
    args = parse_args()

    target = args.target.strip()
    if not target:
        print("Error: target cannot be empty")
        return 1

    try:
        validate_scan_options(
            args.start_port,
            args.end_port,
            args.timeout,
            args.workers,
        )
    except ValueError as exc:
        print(f"Error: {exc}")
        return 1

    try:
        ip_address = resolve_target(target)
    except ValueError as exc:
        print(f"Error: {exc}")
        return 1

    print("Authorized use only. Scan only systems you own or have permission to test.")
    print(f"Scanning {target} ({ip_address})...")
    print(f"Port range: {args.start_port}-{args.end_port}")
    print(f"Timeout: {args.timeout:.2f}s | Workers: {args.workers}\n")

    started_at = time.perf_counter()

    try:
        open_ports = scan_ports(
            ip_address,
            start_port=args.start_port,
            end_port=args.end_port,
            timeout=args.timeout,
            workers=args.workers,
        )
    except KeyboardInterrupt:
        print("\nScan cancelled.")
        return 130

    elapsed = time.perf_counter() - started_at
    results = build_results(open_ports)
    print_results(results, elapsed)

    if args.format and not args.output:
        print("Warning: --format is ignored without --output.")

    if args.output:
        save_results(
            args.output,
            args.format or "json",
            target,
            ip_address,
            args.start_port,
            args.end_port,
            elapsed,
            results,
        )
        print(f"Results saved to {args.output}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
