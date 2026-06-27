# Port Scanner

A command-line TCP port scanner written in Python using only the standard library.

## What it does

- Takes a target IP address or domain name as input
- Scans a configurable TCP port range
- Displays each open port and its associated service (e.g. 80 → HTTP, 22 → SSH, 443 → HTTPS)
- Uses multithreading to scan ports concurrently for speed
- Supports JSON and CSV result export
- Shows total scan time when finished

## Usage

From the `cybersecurity_assessment_lab/` project root:

```bash
python3 recon/port_scanner/scanner.py <target> [options]
```

Example:

```bash
python3 recon/port_scanner/scanner.py scanme.nmap.org --start-port 1 --end-port 1024
```

> `scanme.nmap.org` is a legal practice target provided by the Nmap project — safe to scan.

Useful options:

```bash
python3 recon/port_scanner/scanner.py 127.0.0.1 --start-port 1 --end-port 100 --timeout 0.2 --workers 50
python3 recon/port_scanner/scanner.py 127.0.0.1 --start-port 1 --end-port 100 --output reports/generated/scan.json --format json
python3 recon/port_scanner/scanner.py 127.0.0.1 --start-port 1 --end-port 100 --output reports/generated/scan.csv --format csv
```

## Example output

```
Authorized use only. Scan only systems you own or have permission to test.
Scanning scanme.nmap.org (45.33.32.156)...
Port range: 1-1024
Timeout: 1.00s | Workers: 100

Port     Status   Service
----     ------   -------
22       open     SSH
80       open     HTTP

Scan completed in 3.42 seconds. 2 open port(s) found.
```

## Requirements

- Python 3.x
- No external packages needed
- Uses `socket`, `argparse`, and `concurrent.futures` from the standard library

## Run tests

From the `cybersecurity_assessment_lab/` project root:

```bash
python3 -m unittest recon.port_scanner.test_scanner
```

## Project structure

```
port_scanner/
├── scanner.py       # main program
├── test_scanner.py  # unit tests
├── EXPLANATION.md   # study notes for understanding the module
└── README.md        # this file
```

## Safety note

This tool is for learning and authorized security testing only. Only scan systems you own or have explicit permission to test.
