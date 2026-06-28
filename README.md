# Personal Cybersecurity Assessment Lab

This project is a practical cybersecurity assessment lab. It currently demonstrates network reconnaissance, web vulnerability testing, log-based detection, and structured report output.

The goal is not just to create isolated scripts. The goal is to build a small, explainable security lab where each module connects to a realistic security assessment process.

## Current Modules

- `recon/port_scanner/` - Network reconnaissance module written in Python.
- `vulnerable_web_app/` - Local Flask app demonstrating SQL injection, XSS, and password hashing.
- `log_analyzer/` - Command-line analyzer for suspicious authentication log patterns.
- `report_generator/` - Automated Markdown report generator for structured lab evidence.

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
- OWASP Top 10 mapping for each web security demo

### Module 3: Log-Based Detection

- Authentication log parsing
- Sliding time-window based repeated failed login detection
- Suspicious username detection
- Success-after-failures detection within the configured time window
- JSON alert export
- Markdown report generation
- MITRE ATT&CK mapping for brute-force style detections

### Module 4: Assessment Reporting

- Final assessment report sample
- Automated report generation from scanner output, log alerts, and curated web findings
- Finding severity, evidence, impact, and remediation
- Security control matrix
- Evidence sources section
- Incident response guidance for suspicious authentication activity
- Consolidated workflow from reconnaissance to reporting

## Reports

- `reports/automated_assessment_report_sample.md` - Generated assessment report created from structured scanner, log, and finding inputs.
- `reports/final_assessment_report_sample.md` - Consolidated assessment report covering reconnaissance, web findings, detection, and response guidance.
- `reports/auth_log_analysis_sample.md` - Authentication log analysis report generated from the sample log dataset.
- `reports/auth_window_demo_report.md` - Authentication log report showing sliding time-window detection behavior.

## Run Tests

From the project root:

```bash
python3 -m unittest recon.port_scanner.test_scanner
python3 -m unittest discover -s vulnerable_web_app -p 'test_*.py'
python3 -m unittest log_analyzer.test_analyzer
python3 -m unittest report_generator.test_generate_report
```

The web app tests require the dependencies in `vulnerable_web_app/requirements.txt`.

## Project Structure

```text
cybersecurity_assessment_lab/
├── README.md
├── recon/
│   └── port_scanner/
│       ├── scanner.py
│       └── README.md
├── vulnerable_web_app/
│   ├── app.py
│   ├── database.py
│   └── docs/
├── log_analyzer/
│   ├── analyzer.py
│   ├── sample_logs/
│   └── docs/
├── report_generator/
│   ├── generate_report.py
│   ├── findings.json
│   └── README.md
└── reports/
    ├── automated_assessment_report_sample.md
    ├── final_assessment_report_sample.md
    ├── auth_log_analysis_sample.md
    └── auth_window_demo_report.md
```

## Roadmap

- Add service fingerprinting to the reconnaissance module.
- Optionally export generated assessment reports to PDF.

## Safety Boundary

All security testing in this project must be done only against local, owned, or explicitly authorized targets.
