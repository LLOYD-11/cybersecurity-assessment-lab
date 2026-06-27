# Authentication Log Analysis Report

## Summary

- Events analyzed: 9
- Alerts generated: 5

## Alerts by Severity

- critical: 1
- high: 1
- medium: 3

## Alerts by Rule

- `repeated_failed_logins`: 1
- `success_after_failures`: 1
- `suspicious_username`: 3

## Alert Details

| Severity | Rule | IP | Username | Count | Message |
| --- | --- | --- | --- | --- | --- |
| critical | `success_after_failures` | 203.0.113.10 | alice | 5 | Successful login for 'alice' after 5 failures from 203.0.113.10. |
| high | `repeated_failed_logins` | 203.0.113.10 | - | 5 | 5 failed login attempts from 203.0.113.10. |
| medium | `suspicious_username` | 198.51.100.23 | root | - | Suspicious username 'root' observed from 198.51.100.23. |
| medium | `suspicious_username` | 198.51.100.23 | test | - | Suspicious username 'test' observed from 198.51.100.23. |
| medium | `suspicious_username` | 203.0.113.10 | admin | - | Suspicious username 'admin' observed from 203.0.113.10. |

## Rule Notes

- `repeated_failed_logins` flags IP addresses with repeated failed login attempts.
- `suspicious_username` flags commonly targeted usernames.
- `success_after_failures` flags a successful login after repeated failures from the same IP.

## Scope

This report was generated from synthetic local authentication logs.
