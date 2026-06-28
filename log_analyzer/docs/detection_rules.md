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

Invalid lines and invalid timestamps are ignored.

## Rule: Repeated Failed Logins

Trigger:

- Same IP address has at least five failed login attempts within the configured time window.
- Default window: 60 minutes.

Severity:

- `high`

Reason:

- Repeated failures from one IP can indicate brute-force or password guessing activity.

Framework mapping:

- [MITRE ATT&CK T1110 - Brute Force](https://attack.mitre.org/techniques/T1110/).

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

Framework mapping:

- This rule supports brute-force and credential-guessing triage but is not mapped to a standalone ATT&CK technique by itself.

## Rule: Success After Failures

Trigger:

- Same IP address has at least five failures followed by a successful login within the configured time window.
- Default window: 60 minutes.

Severity:

- `critical`

Reason:

- A success after repeated failures can indicate a password guessing attempt that eventually found valid credentials.

Framework mapping:

- [MITRE ATT&CK T1110 - Brute Force](https://attack.mitre.org/techniques/T1110/).
- [MITRE ATT&CK T1110.001 - Password Guessing](https://attack.mitre.org/techniques/T1110/001/).

## Time Window Behavior

Repeated-failure detections use a sliding time window. By default, the analyzer checks for five failed login attempts from the same IP address within 60 minutes.

The `success_after_failures` rule uses the same window and only considers failures that occurred before the successful login.

The window can be changed with the `--window-minutes` command-line option.
