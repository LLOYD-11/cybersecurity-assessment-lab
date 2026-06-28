import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from generate_report import (
    EvidencePaths,
    auth_alerts_to_findings,
    generate_report,
    load_findings,
    render_report,
)


class ReportGeneratorTests(unittest.TestCase):
    def test_load_findings_requires_list(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "findings.json"
            path.write_text(json.dumps({"id": "F-001"}), encoding="utf-8")

            with self.assertRaises(ValueError):
                load_findings(path)

    def test_load_findings_rejects_missing_required_field(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "findings.json"
            path.write_text(json.dumps([{"id": "F-001"}]), encoding="utf-8")

            with self.assertRaises(ValueError):
                load_findings(path)

    def test_auth_alerts_are_converted_to_findings(self) -> None:
        auth_report = {
            "alerts": [
                {
                    "rule": "success_after_failures",
                    "severity": "critical",
                    "ip": "203.0.113.10",
                    "username": "alice",
                    "count": 5,
                    "message": "Successful login after failures.",
                }
            ]
        }

        findings = auth_alerts_to_findings(auth_report)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "critical")
        self.assertTrue(
            any("T1110.001" in reference for reference in findings[0]["references"])
        )
        self.assertIn("risk_summary", findings[0])
        self.assertIn("control_summary", findings[0])

    def test_suspicious_username_alerts_are_grouped_into_one_finding(self) -> None:
        auth_report = {
            "alerts": [
                {
                    "rule": "suspicious_username",
                    "severity": "medium",
                    "ip": "203.0.113.10",
                    "username": "admin",
                    "count": None,
                    "message": "Suspicious username observed.",
                },
                {
                    "rule": "suspicious_username",
                    "severity": "medium",
                    "ip": "198.51.100.23",
                    "username": "root",
                    "count": None,
                    "message": "Suspicious username observed.",
                },
            ]
        }

        findings = auth_alerts_to_findings(auth_report)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["title"], "Suspicious Username Attempts")
        self.assertIn("203.0.113.10 attempted username 'admin'", findings[0]["evidence"])

    def test_render_report_includes_core_sections(self) -> None:
        scan_report = {
            "target": "127.0.0.1",
            "ip_address": "127.0.0.1",
            "port_range": {"start": 1, "end": 30},
            "open_ports": [],
        }
        auth_report = {
            "detection_window_minutes": 60,
            "alerts": [
                {
                    "rule": "repeated_failed_logins",
                    "severity": "high",
                    "ip": "203.0.113.10",
                    "username": None,
                    "count": 5,
                    "message": "5 failed login attempts.",
                }
            ],
        }
        curated_findings = [
            {
                "id": "F-001",
                "title": "SQL Injection in Vulnerable Login Flow",
                "severity": "high",
                "source_module": "vulnerable_web_app",
                "category": "Web Application Security",
                "evidence": "Injected SQL payload changed query logic.",
                "impact": "Authentication bypass.",
                "risk_summary": "Authentication bypass",
                "remediation": "Use parameterized queries.",
                "control_summary": "Parameterized queries",
                "verification": "Secure route rejects payload.",
                "references": ["OWASP Top 10 A03:2021 - Injection"],
            }
        ]
        paths = EvidencePaths(
            scan=Path("scan.json"),
            auth=Path("auth.json"),
            findings=Path("findings.json"),
        )

        report = render_report(
            scan_report,
            auth_report,
            curated_findings,
            paths,
            generated_at="2026-06-28T00:00:00+00:00",
        )

        self.assertIn("# Automated Cybersecurity Assessment Report", report)
        self.assertIn("## Security Control Matrix", report)
        self.assertIn("## Evidence Sources", report)
        self.assertIn("The generator does not automatically discover web vulnerabilities.", report)

    def test_generate_report_writes_markdown_file(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            scan_path = temp_path / "scan.json"
            auth_path = temp_path / "auth.json"
            findings_path = temp_path / "findings.json"
            output_path = temp_path / "report.md"

            scan_path.write_text(
                json.dumps(
                    {
                        "target": "127.0.0.1",
                        "ip_address": "127.0.0.1",
                        "port_range": {"start": 1, "end": 30},
                        "open_ports": [],
                    }
                ),
                encoding="utf-8",
            )
            auth_path.write_text(
                json.dumps({"detection_window_minutes": 60, "alerts": []}),
                encoding="utf-8",
            )
            findings_path.write_text(
                json.dumps(
                    [
                        {
                            "id": "F-001",
                            "title": "SQL Injection in Vulnerable Login Flow",
                            "severity": "high",
                            "source_module": "vulnerable_web_app",
                            "category": "Web Application Security",
                            "evidence": "Injected SQL payload changed query logic.",
                            "impact": "Authentication bypass.",
                            "risk_summary": "Authentication bypass",
                            "remediation": "Use parameterized queries.",
                            "control_summary": "Parameterized queries",
                            "verification": "Secure route rejects payload.",
                            "references": ["OWASP Top 10 A03:2021 - Injection"],
                        }
                    ]
                ),
                encoding="utf-8",
            )

            generate_report(scan_path, auth_path, findings_path, output_path)
            content = output_path.read_text(encoding="utf-8")

        self.assertIn("Automated Cybersecurity Assessment Report", content)
        self.assertIn("F-001", content)


if __name__ == "__main__":
    unittest.main()
