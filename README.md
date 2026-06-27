# Personal Cybersecurity Assessment Lab

This project is a practical cybersecurity assessment lab that demonstrates core security workflows: reconnaissance, vulnerability testing, log-based detection, remediation, and reporting.

The goal is not just to create isolated scripts. The goal is to build a small, explainable security lab where each module connects to a realistic security assessment process.

## Current Modules

- `recon/port_scanner/` - Network reconnaissance module written in Python.
- `vulnerable_web_app/` - Local Flask app demonstrating SQL injection and remediation.

## Planned Modules

- `log_analyzer/` - A simple log analysis and alerting tool.
- `reports/` - Security assessment reports and demo outputs.

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

## Safety Boundary

All security testing in this project must be done only against local, owned, or explicitly authorized targets.
