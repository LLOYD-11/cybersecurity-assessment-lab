# Vulnerable Web App

A small Flask application for demonstrating common web security issues in a local, controlled environment.

The demos focus on SQL injection in a login form, cross-site scripting in a comment preview, and weak password storage. Each demo includes an intentionally vulnerable implementation and a secure implementation.

## What It Demonstrates

- How unsafe SQL string formatting can create authentication bypasses.
- How parameterized queries prevent user input from changing SQL query structure.
- How unescaped user input can create cross-site scripting risk.
- How default HTML escaping prevents user input from being interpreted as markup or script.
- Why plaintext password storage is dangerous.
- How password hashing protects credentials if a database is exposed.
- How to document a vulnerability with impact, evidence, and remediation.
- How local findings can be mapped to OWASP Top 10 categories.

## Demo Routes

| Topic | Vulnerable Route | Secure Route | Secure Control |
| --- | --- | --- | --- |
| SQL injection | `/vulnerable-login` | `/secure-login` | Parameterized queries |
| Cross-site scripting | `/vulnerable-comment` | `/secure-comment` | HTML escaping |
| Password storage | `/weak-auth-login` | `/secure-auth-login` | Password hashing |

## Framework Mapping

| Demo | Reference Category |
| --- | --- |
| SQL injection | [OWASP Top 10 A03:2021 - Injection](https://owasp.org/Top10/A03_2021-Injection/) |
| Cross-site scripting | [OWASP Top 10 A03:2021 - Injection](https://owasp.org/Top10/A03_2021-Injection/) |
| Weak password storage | [OWASP Top 10 A07:2021 - Identification and Authentication Failures](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/) |

## Setup

Create and activate a virtual environment from the project root:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r vulnerable_web_app/requirements.txt
```

Initialize the demo database:

```bash
python3 vulnerable_web_app/database.py
```

Run the app:

```bash
python3 vulnerable_web_app/app.py
```

Open:

```text
http://127.0.0.1:5000
```

## Demo Accounts

```text
username: alice
password: password123
```

```text
username: carol
password: letmein123
```

## Safe Local Demo

The vulnerable login form can be tested locally with this SQL injection payload:

```text
username: ' OR '1'='1' --
password: anything
```

The secure login form should reject the same input.

The vulnerable comment form can be tested locally with this XSS payload:

```html
<script>alert('xss')</script>
```

The secure comment form should display the payload as text instead of interpreting it as HTML.

The weak authentication form can be tested locally with:

```text
username: carol
password: letmein123
```

The weak route displays the stored plaintext password. The secure route displays a password hash instead.

## Project Structure

```text
vulnerable_web_app/
├── app.py
├── database.py
├── requirements.txt
├── test_app.py
├── test_database.py
├── docs/
│   ├── demo_outputs.md
│   ├── sql_injection_walkthrough.md
│   ├── weak_auth_walkthrough.md
│   └── xss_walkthrough.md
├── static/
│   └── style.css
└── templates/
    ├── auth_login.html
    ├── auth_result.html
    ├── comment.html
    ├── index.html
    ├── login.html
    └── result.html
```

## Run Tests

From the `cybersecurity_assessment_lab/` project root:

```bash
python3 -m unittest discover -s vulnerable_web_app -p 'test_*.py'
```

## Safety Boundary

This application is intentionally vulnerable. Run it locally only. Do not deploy it to a public network.
