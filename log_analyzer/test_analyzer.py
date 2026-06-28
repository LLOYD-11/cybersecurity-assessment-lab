import tempfile
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from analyzer import (
    Alert,
    AuthEvent,
    analyze_events,
    build_report_payload,
    demo_notes_for_log,
    detect_repeated_failures,
    detect_success_after_failures,
    load_events,
    parse_log_line,
    parse_timestamp,
    render_markdown_report,
    save_json,
    save_markdown,
)


class AnalyzerTests(unittest.TestCase):
    SAMPLE_DIR = Path(__file__).resolve().parent / "sample_logs"

    def test_parse_log_line_accepts_valid_line(self) -> None:
        event = parse_log_line(
            "2026-06-27T10:00:01Z ip=203.0.113.10 user=admin action=failed"
        )

        self.assertEqual(
            event,
            AuthEvent(
                timestamp="2026-06-27T10:00:01Z",
                ip="203.0.113.10",
                username="admin",
                action="failed",
            ),
        )

    def test_parse_log_line_rejects_invalid_line(self) -> None:
        self.assertIsNone(parse_log_line("invalid log line"))

    def test_parse_log_line_rejects_invalid_timestamp(self) -> None:
        self.assertIsNone(
            parse_log_line("bad-time ip=203.0.113.10 user=admin action=failed")
        )

    def test_parse_timestamp_rejects_invalid_timestamp(self) -> None:
        self.assertIsNone(parse_timestamp("not-a-timestamp"))

    def test_analyze_events_detects_repeated_failures_and_success_after_failures(self) -> None:
        events = [
            AuthEvent("2026-06-27T10:00:01Z", "203.0.113.10", "admin", "failed"),
            AuthEvent("2026-06-27T10:00:04Z", "203.0.113.10", "admin", "failed"),
            AuthEvent("2026-06-27T10:00:07Z", "203.0.113.10", "admin", "failed"),
            AuthEvent("2026-06-27T10:00:11Z", "203.0.113.10", "admin", "failed"),
            AuthEvent("2026-06-27T10:00:15Z", "203.0.113.10", "admin", "failed"),
            AuthEvent("2026-06-27T10:00:22Z", "203.0.113.10", "alice", "success"),
        ]

        alerts = analyze_events(events)
        rules = {alert.rule for alert in alerts}

        self.assertIn("repeated_failed_logins", rules)
        self.assertIn("suspicious_username", rules)
        self.assertIn("success_after_failures", rules)

    def test_repeated_failures_trigger_within_time_window(self) -> None:
        events = [
            AuthEvent("2026-06-27T10:00:01Z", "203.0.113.10", "admin", "failed"),
            AuthEvent("2026-06-27T10:05:01Z", "203.0.113.10", "admin", "failed"),
            AuthEvent("2026-06-27T10:10:01Z", "203.0.113.10", "admin", "failed"),
            AuthEvent("2026-06-27T10:15:01Z", "203.0.113.10", "admin", "failed"),
            AuthEvent("2026-06-27T10:20:01Z", "203.0.113.10", "admin", "failed"),
        ]

        alerts = detect_repeated_failures(events, window_minutes=60)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].count, 5)
        self.assertIn("within 60 minutes", alerts[0].message)

    def test_repeated_failures_sort_events_before_window_detection(self) -> None:
        events = [
            AuthEvent("2026-06-27T10:20:01Z", "203.0.113.10", "admin", "failed"),
            AuthEvent("2026-06-27T10:00:01Z", "203.0.113.10", "admin", "failed"),
            AuthEvent("2026-06-27T10:15:01Z", "203.0.113.10", "admin", "failed"),
            AuthEvent("2026-06-27T10:05:01Z", "203.0.113.10", "admin", "failed"),
            AuthEvent("2026-06-27T10:10:01Z", "203.0.113.10", "admin", "failed"),
        ]

        alerts = detect_repeated_failures(events, window_minutes=60)

        self.assertEqual(len(alerts), 1)

    def test_repeated_failures_do_not_trigger_outside_time_window(self) -> None:
        events = [
            AuthEvent("2026-06-27T10:00:01Z", "203.0.113.10", "admin", "failed"),
            AuthEvent("2026-06-27T10:30:01Z", "203.0.113.10", "admin", "failed"),
            AuthEvent("2026-06-27T11:00:02Z", "203.0.113.10", "admin", "failed"),
            AuthEvent("2026-06-27T11:30:03Z", "203.0.113.10", "admin", "failed"),
            AuthEvent("2026-06-27T12:00:04Z", "203.0.113.10", "admin", "failed"),
        ]

        alerts = detect_repeated_failures(events, window_minutes=60)

        self.assertEqual(alerts, [])

    def test_success_after_failures_uses_time_window(self) -> None:
        events = [
            AuthEvent("2026-06-27T10:00:01Z", "203.0.113.10", "admin", "failed"),
            AuthEvent("2026-06-27T10:01:01Z", "203.0.113.10", "admin", "failed"),
            AuthEvent("2026-06-27T10:02:01Z", "203.0.113.10", "admin", "failed"),
            AuthEvent("2026-06-27T10:03:01Z", "203.0.113.10", "admin", "failed"),
            AuthEvent("2026-06-27T10:04:01Z", "203.0.113.10", "admin", "failed"),
            AuthEvent("2026-06-27T10:05:01Z", "203.0.113.10", "alice", "success"),
        ]

        alerts = detect_success_after_failures(events, window_minutes=10)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].rule, "success_after_failures")
        self.assertIn("within 10 minutes", alerts[0].message)

    def test_success_after_failures_ignores_failures_outside_time_window(self) -> None:
        events = [
            AuthEvent("2026-06-27T10:00:01Z", "203.0.113.10", "admin", "failed"),
            AuthEvent("2026-06-27T10:10:01Z", "203.0.113.10", "admin", "failed"),
            AuthEvent("2026-06-27T10:20:01Z", "203.0.113.10", "admin", "failed"),
            AuthEvent("2026-06-27T10:30:01Z", "203.0.113.10", "admin", "failed"),
            AuthEvent("2026-06-27T11:30:02Z", "203.0.113.10", "admin", "failed"),
            AuthEvent("2026-06-27T11:31:01Z", "203.0.113.10", "alice", "success"),
        ]

        alerts = detect_success_after_failures(events, window_minutes=60)

        self.assertEqual(alerts, [])

    def test_load_events_ignores_invalid_lines(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            log_file = Path(temp_dir) / "auth.log"
            log_file.write_text(
                "\n".join(
                    [
                        "2026-06-27T10:00:01Z ip=203.0.113.10 user=admin action=failed",
                        "invalid line",
                    ]
                ),
                encoding="utf-8",
            )

            events = load_events(log_file)

        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].username, "admin")

    def test_window_demo_log_shows_windowed_detection_behavior(self) -> None:
        events = load_events(self.SAMPLE_DIR / "auth_window_demo.log")

        alerts = analyze_events(events)
        repeated_alert_ips = {
            alert.ip for alert in alerts if alert.rule == "repeated_failed_logins"
        }
        critical_alert_ips = {
            alert.ip for alert in alerts if alert.rule == "success_after_failures"
        }

        self.assertIn("203.0.113.50", repeated_alert_ips)
        self.assertIn("192.0.2.77", repeated_alert_ips)
        self.assertNotIn("198.51.100.80", repeated_alert_ips)
        self.assertIn("192.0.2.77", critical_alert_ips)

    def test_demo_notes_are_available_for_window_demo_log(self) -> None:
        notes = demo_notes_for_log(self.SAMPLE_DIR / "auth_window_demo.log")

        self.assertTrue(notes)
        self.assertIn("198.51.100.80", notes[1])

    def test_render_markdown_report_includes_optional_demo_notes(self) -> None:
        events = [AuthEvent("2026-06-27T10:00:01Z", "203.0.113.10", "admin", "failed")]
        alerts = [
            Alert(
                rule="suspicious_username",
                severity="medium",
                ip="203.0.113.10",
                username="admin",
                message="Suspicious username observed.",
            )
        ]

        report = render_markdown_report(events, alerts, demo_notes=["Example note."])

        self.assertIn("## Demo Notes", report)
        self.assertIn("- Example note.", report)

    def test_save_json_writes_alert_report(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "alerts.json"
            events = [
                AuthEvent("2026-06-27T10:00:01Z", "203.0.113.10", "admin", "failed")
            ]
            alerts = [
                Alert(
                    rule="suspicious_username",
                    severity="medium",
                    ip="203.0.113.10",
                    username="admin",
                    message="Suspicious username observed.",
                )
            ]

            save_json(output_path, events, alerts, window_minutes=30)

            content = output_path.read_text(encoding="utf-8")

        self.assertIn('"events_analyzed": 1', content)
        self.assertIn('"detection_window_minutes": 30', content)
        self.assertIn('"suspicious_username"', content)

    def test_build_report_payload_counts_alerts_by_severity_and_rule(self) -> None:
        events = [
            AuthEvent("2026-06-27T10:00:01Z", "203.0.113.10", "admin", "failed"),
            AuthEvent("2026-06-27T10:00:04Z", "203.0.113.10", "alice", "success"),
        ]
        alerts = [
            Alert(
                rule="suspicious_username",
                severity="medium",
                ip="203.0.113.10",
                username="admin",
                message="Suspicious username observed.",
            ),
            Alert(
                rule="success_after_failures",
                severity="critical",
                ip="203.0.113.10",
                username="alice",
                count=5,
                message="Successful login after failures.",
            ),
        ]

        payload = build_report_payload(events, alerts, window_minutes=15)

        self.assertEqual(payload["events_analyzed"], 2)
        self.assertEqual(payload["alerts_generated"], 2)
        self.assertEqual(payload["detection_window_minutes"], 15)
        self.assertEqual(payload["severity_counts"], {"critical": 1, "medium": 1})
        self.assertEqual(
            payload["rule_counts"],
            {"success_after_failures": 1, "suspicious_username": 1},
        )

    def test_render_markdown_report_includes_summary_and_alert_table(self) -> None:
        events = [AuthEvent("2026-06-27T10:00:01Z", "203.0.113.10", "admin", "failed")]
        alerts = [
            Alert(
                rule="suspicious_username",
                severity="medium",
                ip="203.0.113.10",
                username="admin",
                message="Suspicious username observed.",
            )
        ]

        report = render_markdown_report(events, alerts, window_minutes=45)

        self.assertIn("# Authentication Log Analysis Report", report)
        self.assertIn("- Events analyzed: 1", report)
        self.assertIn("- Detection window: 45 minutes", report)
        self.assertIn("| medium | `suspicious_username` | 203.0.113.10 | admin | - |", report)

    def test_save_markdown_writes_report_file(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "auth_report.md"
            events = [
                AuthEvent("2026-06-27T10:00:01Z", "203.0.113.10", "admin", "failed")
            ]
            alerts = [
                Alert(
                    rule="suspicious_username",
                    severity="medium",
                    ip="203.0.113.10",
                    username="admin",
                    message="Suspicious username observed.",
                )
            ]

            save_markdown(output_path, events, alerts, window_minutes=20)
            content = output_path.read_text(encoding="utf-8")

        self.assertIn("Authentication Log Analysis Report", content)
        self.assertIn("Detection window: 20 minutes", content)
        self.assertIn("Suspicious username observed.", content)


if __name__ == "__main__":
    unittest.main()
