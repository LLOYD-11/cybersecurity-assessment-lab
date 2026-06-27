# Detection Rules

This module uses simple rule-based detection on synthetic authentication logs.

## Log Format

Each valid log line uses this format:

```text
2026-06-27T10:00:01Z ip=203.0.113.10 user=admin action=failed
```

Fields:

- `timestamp` - ISO-like timestamp string.
- `ip` - source IP address.
- `user` - attempted username.
- `action` - either `failed` or `success`.

Invalid lines are ignored.

## Rule: Repeated Failed Logins

Trigger:

- Same IP address has at least five failed login attempts.

Severity:

- `high`

Reason:

- Repeated failures from one IP can indicate brute-force or password guessing activity.

## Rule: Suspicious Username

Trigger:

- Login attempt uses a commonly targeted username:
  - `admin`
  - `root`
  - `test`
  - `guest`

Severity:

- `medium`

Reason:

- These usernames are commonly targeted during automated scanning or credential attacks.

## Rule: Success After Failures

Trigger:

- Same IP address has at least five failures followed by a successful login.

Severity:

- `critical`

Reason:

- A success after repeated failures can indicate a password guessing attempt that eventually found valid credentials.

## Current Limitations

The first version counts failed logins across the entire input file. It does not apply a sliding time window.

For example, five failed attempts from the same IP address will trigger the repeated-failures rule even if those failures are spread across a long time range.

A production-style detector would usually apply a time window, such as "five failed logins from the same IP within one hour." This can be added in a later version by parsing timestamps and grouping events by time range.
