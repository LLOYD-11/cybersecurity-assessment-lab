# Assessment Report Generator

Generates a Markdown assessment report from structured lab evidence.

The generator combines:

- Port scanner JSON output.
- Authentication log analyzer JSON output.
- Curated web application findings from `report_generator/findings.json`.

The curated web findings are intentionally structured input for the report. This generator does not automatically discover web vulnerabilities.

## Usage

From the `cybersecurity_assessment_lab/` project root:

```bash
python3 report_generator/generate_report.py \
  --scan reports/generated/localhost_scan.json \
  --auth reports/generated/auth_alerts.json \
  --findings report_generator/findings.json \
  --output reports/generated/final_assessment_report.md
```

Generate a committed sample report:

```bash
python3 report_generator/generate_report.py \
  --scan reports/generated/localhost_scan.json \
  --auth reports/generated/auth_alerts.json \
  --findings report_generator/findings.json \
  --output reports/automated_assessment_report_sample.md
```

## Finding Schema

Each curated finding uses this structure:

```json
{
  "id": "F-001",
  "title": "Finding title",
  "severity": "high",
  "source_module": "vulnerable_web_app",
  "category": "Web Application Security",
  "evidence": "What was observed.",
  "impact": "Why it matters.",
  "risk_summary": "Short risk phrase for matrix tables.",
  "remediation": "How to fix it.",
  "control_summary": "Short control phrase for matrix tables.",
  "verification": "How the fix is validated.",
  "references": ["OWASP Top 10 A03:2021 - Injection"]
}
```

## Run Tests

From the project root:

```bash
python3 -m unittest report_generator.test_generate_report
```
