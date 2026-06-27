# Personal Cybersecurity Assessment Lab

This project is a practical cybersecurity assessment lab. It currently demonstrates network reconnaissance and web vulnerability testing, with planned modules for log-based detection and reporting.

The goal is not just to create isolated scripts. The goal is to build a small, explainable security lab where each module connects to a realistic security assessment process.

## Current Modules

- `recon/port_scanner/` - Network reconnaissance module written in Python.
- `vulnerable_web_app/` - Local Flask app demonstrating SQL injection, XSS, and password hashing.

## Implemented Workflows

### Module 1: Network Reconnaissance

- TCP port scanning
- Service identification
- Configurable scan range, timeout, and worker count
- JSON and CSV export

### Module 2: Web Security Demos

- SQL injection: vulnerable query construction vs parameterized queries
- Cross-site scripting: unsafe rendering vs automatic HTML escaping
- Password storage: plaintext password storage vs password hashing

## Planned Modules

- `log_analyzer/` - A simple log analysis and alerting tool.
- `reports/` - Security assessment reports and demo outputs.

## Run Tests

From the project root:

```bash
python3 -m unittest recon.port_scanner.test_scanner
python3 -m unittest discover -s vulnerable_web_app -p 'test_*.py'
```

The web app tests require the dependencies in `vulnerable_web_app/requirements.txt`.

## Project Structure

```text
cybersecurity_assessment_lab/
├── README.md
├── recon/
│   └── port_scanner/
├── vulnerable_web_app/
├── log_analyzer/
└── reports/
```

## Roadmap

- Add a log analyzer for detecting suspicious authentication and web request patterns.
- Add report generation for summarizing findings and remediation guidance.

## Safety Boundary

All security testing in this project must be done only against local, owned, or explicitly authorized targets.
