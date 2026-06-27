from __future__ import annotations

import argparse
import json
import re
from collections import defaultdict
from dataclasses import asdict, dataclass
from pathlib import Path


FAILED_THRESHOLD = 5
SUSPICIOUS_USERNAMES = {"admin", "root", "test", "guest"}
SEVERITY_ORDER = ["critical", "high", "medium", "low"]

LOG_PATTERN = re.compile(
    r"^(?P<timestamp>\S+)\s+"
    r"ip=(?P<ip>\S+)\s+"
    r"user=(?P<username>\S+)\s+"
    r"action=(?P<action>failed|success)$"
)


@dataclass(frozen=True)
class AuthEvent:
    timestamp: str
    ip: str
    username: str
    action: str


@dataclass(frozen=True)
class Alert:
    rule: str
    severity: str
    ip: str
    message: str
    count: int | None = None
    username: str | None = None


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Analyze authentication logs for suspicious activity."
    )
    parser.add_argument("log_file", type=Path, help="Path to an authentication log file.")
    parser.add_argument("--output", type=Path, help="Optional report output path.")
    parser.add_argument(
        "--format",
        choices=["json", "markdown"],
        default="json",
        help="Report output format used with --output. Default: json.",
    )
    return parser.parse_args()


def parse_log_line(line: str) -> AuthEvent | None:
    match = LOG_PATTERN.match(line.strip())
    if not match:
        return None

    return AuthEvent(
        timestamp=match.group("timestamp"),
        ip=match.group("ip"),
        username=match.group("username"),
        action=match.group("action"),
    )


def load_events(log_file: Path) -> list[AuthEvent]:
    events: list[AuthEvent] = []

    for line in log_file.read_text(encoding="utf-8").splitlines():
        event = parse_log_line(line)
        if event is not None:
            events.append(event)

    return events


def detect_repeated_failures(events: list[AuthEvent]) -> list[Alert]:
    failed_by_ip: dict[str, int] = defaultdict(int)

    for event in events:
        if event.action == "failed":
            failed_by_ip[event.ip] += 1

    alerts: list[Alert] = []
    for ip, count in sorted(failed_by_ip.items()):
        if count >= FAILED_THRESHOLD:
            alerts.append(
                Alert(
                    rule="repeated_failed_logins",
                    severity="high",
                    ip=ip,
                    count=count,
                    message=f"{count} failed login attempts from {ip}.",
                )
            )

    return alerts


def detect_suspicious_usernames(events: list[AuthEvent]) -> list[Alert]:
    seen: set[tuple[str, str]] = set()
    alerts: list[Alert] = []

    for event in events:
        if event.username not in SUSPICIOUS_USERNAMES:
            continue

        key = (event.ip, event.username)
        if key in seen:
            continue
        seen.add(key)

        alerts.append(
            Alert(
                rule="suspicious_username",
                severity="medium",
                ip=event.ip,
                username=event.username,
                message=f"Suspicious username '{event.username}' observed from {event.ip}.",
            )
        )

    return alerts


def detect_success_after_failures(events: list[AuthEvent]) -> list[Alert]:
    failed_count_by_ip: dict[str, int] = defaultdict(int)
    alerted_ips: set[str] = set()
    alerts: list[Alert] = []

    for event in events:
        if event.action == "failed":
            failed_count_by_ip[event.ip] += 1
            continue

        if (
            event.action == "success"
            and failed_count_by_ip[event.ip] >= FAILED_THRESHOLD
            and event.ip not in alerted_ips
        ):
            alerted_ips.add(event.ip)
            alerts.append(
                Alert(
                    rule="success_after_failures",
                    severity="critical",
                    ip=event.ip,
                    username=event.username,
                    count=failed_count_by_ip[event.ip],
                    message=(
                        f"Successful login for '{event.username}' after "
                        f"{failed_count_by_ip[event.ip]} failures from {event.ip}."
                    ),
                )
            )

    return alerts


def analyze_events(events: list[AuthEvent]) -> list[Alert]:
    alerts = []
    alerts.extend(detect_repeated_failures(events))
    alerts.extend(detect_suspicious_usernames(events))
    alerts.extend(detect_success_after_failures(events))
    return alerts


def print_summary(events: list[AuthEvent], alerts: list[Alert]) -> None:
    print(f"Events analyzed: {len(events)}")
    print(f"Alerts generated: {len(alerts)}\n")

    if not alerts:
        print("No alerts found.")
        return

    print(f"{'Severity':<10} {'Rule':<26} {'IP':<15} Message")
    print(f"{'-' * 8:<10} {'-' * 4:<26} {'-' * 2:<15} {'-' * 7}")
    for alert in alerts:
        print(f"{alert.severity:<10} {alert.rule:<26} {alert.ip:<15} {alert.message}")


def count_by_alert_field(alerts: list[Alert], field_name: str) -> dict[str, int]:
    counts: dict[str, int] = defaultdict(int)
    for alert in alerts:
        value = getattr(alert, field_name)
        counts[value] += 1
    return dict(sorted(counts.items()))


def build_report_payload(events: list[AuthEvent], alerts: list[Alert]) -> dict[str, object]:
    severity_counts = count_by_alert_field(alerts, "severity")
    ordered_severity_counts = {
        severity: severity_counts[severity]
        for severity in SEVERITY_ORDER
        if severity in severity_counts
    }

    return {
        "events_analyzed": len(events),
        "alerts_generated": len(alerts),
        "severity_counts": ordered_severity_counts,
        "rule_counts": count_by_alert_field(alerts, "rule"),
        "alerts": [asdict(alert) for alert in alerts],
    }


def alert_sort_key(alert: Alert) -> tuple[int, str, str]:
    try:
        severity_rank = SEVERITY_ORDER.index(alert.severity)
    except ValueError:
        severity_rank = len(SEVERITY_ORDER)

    return severity_rank, alert.rule, alert.ip


def escape_markdown_table_value(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", " ")


def render_markdown_report(events: list[AuthEvent], alerts: list[Alert]) -> str:
    payload = build_report_payload(events, alerts)
    lines = [
        "# Authentication Log Analysis Report",
        "",
        "## Summary",
        "",
        f"- Events analyzed: {payload['events_analyzed']}",
        f"- Alerts generated: {payload['alerts_generated']}",
        "",
        "## Alerts by Severity",
        "",
    ]

    severity_counts = payload["severity_counts"]
    if severity_counts:
        for severity, count in severity_counts.items():
            lines.append(f"- {severity}: {count}")
    else:
        lines.append("- No alerts found.")

    lines.extend(["", "## Alerts by Rule", ""])
    rule_counts = payload["rule_counts"]
    if rule_counts:
        for rule, count in rule_counts.items():
            lines.append(f"- `{rule}`: {count}")
    else:
        lines.append("- No alerts found.")

    lines.extend(
        [
            "",
            "## Alert Details",
            "",
        ]
    )

    if alerts:
        lines.extend(
            [
                "| Severity | Rule | IP | Username | Count | Message |",
                "| --- | --- | --- | --- | --- | --- |",
            ]
        )
        for alert in sorted(alerts, key=alert_sort_key):
            username = alert.username if alert.username else "-"
            count = str(alert.count) if alert.count is not None else "-"
            lines.append(
                "| "
                f"{escape_markdown_table_value(alert.severity)} | "
                f"`{escape_markdown_table_value(alert.rule)}` | "
                f"{escape_markdown_table_value(alert.ip)} | "
                f"{escape_markdown_table_value(username)} | "
                f"{escape_markdown_table_value(count)} | "
                f"{escape_markdown_table_value(alert.message)} |"
            )
    else:
        lines.append("No alerts found.")

    lines.extend(
        [
            "",
            "## Rule Notes",
            "",
            "- `repeated_failed_logins` flags IP addresses with repeated failed login attempts.",
            "- `suspicious_username` flags commonly targeted usernames.",
            "- `success_after_failures` flags a successful login after repeated failures from the same IP.",
            "",
            "## Scope",
            "",
            "This report was generated from synthetic local authentication logs.",
        ]
    )

    return "\n".join(lines) + "\n"


def save_json(output_path: Path, events: list[AuthEvent], alerts: list[Alert]) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    payload = build_report_payload(events, alerts)
    output_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def save_markdown(output_path: Path, events: list[AuthEvent], alerts: list[Alert]) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(render_markdown_report(events, alerts), encoding="utf-8")


def save_report(
    output_path: Path, output_format: str, events: list[AuthEvent], alerts: list[Alert]
) -> None:
    if output_format == "json":
        save_json(output_path, events, alerts)
        return

    save_markdown(output_path, events, alerts)


def main() -> int:
    args = parse_args()

    if not args.log_file.exists():
        print(f"Error: log file not found: {args.log_file}")
        return 1

    events = load_events(args.log_file)
    alerts = analyze_events(events)
    print_summary(events, alerts)

    if args.output:
        save_report(args.output, args.format, events, alerts)
        print(f"\n{args.format.title()} report saved to {args.output}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
