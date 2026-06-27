# Port Scanner Explanation

This module is the reconnaissance part of the Personal Cybersecurity Assessment Lab.

## What Problem It Solves

A port scanner checks which TCP ports on a target accept connections. In security assessment, this is a basic reconnaissance step because open ports often reveal exposed services such as SSH, HTTP, HTTPS, or SMB.

## Main Flow

1. Parse command-line arguments with `argparse`.
2. Validate the selected port range, timeout, and worker count.
3. Resolve the target domain or IP address with `socket.gethostbyname`.
4. Scan each TCP port using `socket.connect_ex`.
5. Use `ThreadPoolExecutor` so multiple ports can be checked concurrently.
6. Convert open ports into structured `ScanResult` objects.
7. Print a terminal table and optionally save JSON or CSV output.

## Important Functions

- `parse_args()` defines the command-line interface.
- `validate_scan_options()` rejects unsafe or invalid scan settings.
- `resolve_target()` converts a domain name into an IP address.
- `scan_port()` checks one TCP port.
- `scan_ports()` scans a range of ports concurrently.
- `service_name()` maps ports to common service names.
- `save_results()` writes structured JSON or CSV output.

## Cybersecurity Concept

This module demonstrates reconnaissance. The scanner does not exploit anything. It only identifies visible network services. In real security work, this helps define the attack surface and decide what should be investigated next.

## Technical Summary

This module can be summarized as follows:

> I built a Python TCP port scanner as the reconnaissance module of a larger cybersecurity assessment lab. It accepts a target, validates scan settings, resolves domains to IP addresses, scans ports concurrently with sockets and a thread pool, identifies common services, and exports results to JSON or CSV for later reporting.

## Safety Boundary

Only run this tool against local, owned, or explicitly authorized targets.
