# Authentication Log Analysis Report

## Summary

- Events analyzed: 17
- Alerts generated: 6
- Detection window: 60 minutes

## Alerts by Severity

- critical: 1
- high: 2
- medium: 3

## Alerts by Rule

- `repeated_failed_logins`: 2
- `success_after_failures`: 1
- `suspicious_username`: 3

## Alert Details

| Severity | Rule | IP | Username | Count | Message |
| --- | --- | --- | --- | --- | --- |
| critical | `success_after_failures` | 192.0.2.77 | service | 5 | Successful login for 'service' after 5 failures from 192.0.2.77 within 60 minutes. |
| high | `repeated_failed_logins` | 192.0.2.77 | - | 5 | 5 failed login attempts from 192.0.2.77 within 60 minutes. |
| high | `repeated_failed_logins` | 203.0.113.50 | - | 5 | 5 failed login attempts from 203.0.113.50 within 60 minutes. |
| medium | `suspicious_username` | 192.0.2.77 | admin | - | Suspicious username 'admin' observed from 192.0.2.77. |
| medium | `suspicious_username` | 198.51.100.80 | guest | - | Suspicious username 'guest' observed from 198.51.100.80. |
| medium | `suspicious_username` | 203.0.113.50 | admin | - | Suspicious username 'admin' observed from 203.0.113.50. |

## Rule Notes

- `repeated_failed_logins` flags IP addresses with repeated failed login attempts inside the configured time window.
- `suspicious_username` flags commonly targeted usernames.
- `success_after_failures` flags a successful login after repeated failures from the same IP inside the configured time window.

## Scope

This report was generated from synthetic local authentication logs.

## Demo Notes

- `203.0.113.50` has five failed logins within 60 minutes and triggers `repeated_failed_logins`.
- `198.51.100.80` has five failed logins spread across more than 60 minutes, so it does not trigger `repeated_failed_logins`.
- `192.0.2.77` has five failed logins followed by a successful login within 60 minutes and triggers `success_after_failures`.
