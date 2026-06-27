# Auth Log Analyzer

A command-line log analysis tool for detecting suspicious authentication activity in local sample logs.

This module focuses on blue-team detection logic. It parses authentication events, groups activity by IP address, and reports patterns that may indicate brute-force attempts or suspicious login behavior.

## What It Detects

- Repeated failed login attempts from the same IP address.
- Suspicious usernames such as `admin`, `root`, and `test`.
- A successful login after repeated failures from the same IP address.

## Usage

From the `cybersecurity_assessment_lab/` project root:

```bash
python3 log_analyzer/analyzer.py log_analyzer/sample_logs/auth_sample.log
```

Save JSON output:

```bash
python3 log_analyzer/analyzer.py log_analyzer/sample_logs/auth_sample.log --output reports/generated/auth_alerts.json
```

Save Markdown report output:

```bash
python3 log_analyzer/analyzer.py log_analyzer/sample_logs/auth_sample.log --output reports/auth_log_analysis_sample.md --format markdown
```

## Run Tests

From the project root:

```bash
python3 -m unittest log_analyzer.test_analyzer
```

## Project Structure

```text
log_analyzer/
├── analyzer.py
├── test_analyzer.py
├── docs/
│   └── detection_rules.md
└── sample_logs/
    └── auth_sample.log
```

## Safety Boundary

The sample log is synthetic. Use this tool only on logs you own or have permission to analyze.
