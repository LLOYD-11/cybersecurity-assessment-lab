import tempfile
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from analyzer import (
    Alert,
    AuthEvent,
    analyze_events,
    load_events,
    parse_log_line,
    save_json,
)


class AnalyzerTests(unittest.TestCase):
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

    def test_analyze_events_detects_repeated_failures_and_success_after_failures(self) -> None:
        events = [
            AuthEvent("t1", "203.0.113.10", "admin", "failed"),
            AuthEvent("t2", "203.0.113.10", "admin", "failed"),
            AuthEvent("t3", "203.0.113.10", "admin", "failed"),
            AuthEvent("t4", "203.0.113.10", "admin", "failed"),
            AuthEvent("t5", "203.0.113.10", "admin", "failed"),
            AuthEvent("t6", "203.0.113.10", "alice", "success"),
        ]

        alerts = analyze_events(events)
        rules = {alert.rule for alert in alerts}

        self.assertIn("repeated_failed_logins", rules)
        self.assertIn("suspicious_username", rules)
        self.assertIn("success_after_failures", rules)

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

    def test_save_json_writes_alert_report(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "alerts.json"
            events = [AuthEvent("t1", "203.0.113.10", "admin", "failed")]
            alerts = [
                Alert(
                    rule="suspicious_username",
                    severity="medium",
                    ip="203.0.113.10",
                    username="admin",
                    message="Suspicious username observed.",
                )
            ]

            save_json(output_path, events, alerts)

            content = output_path.read_text(encoding="utf-8")

        self.assertIn('"events_analyzed": 1', content)
        self.assertIn('"suspicious_username"', content)


if __name__ == "__main__":
    unittest.main()
