# Vulnerable Web App

A small Flask application for demonstrating common web security issues in a local, controlled environment.

The first demos focus on SQL injection in a login form and cross-site scripting in a comment preview. Each demo includes an intentionally vulnerable implementation and a secure implementation.

## What It Demonstrates

- How unsafe SQL string formatting can create authentication bypasses.
- How parameterized queries prevent user input from changing SQL query structure.
- How unescaped user input can create cross-site scripting risk.
- How default HTML escaping prevents user input from being interpreted as markup or script.
- How to document a vulnerability with impact, evidence, and remediation.

## Setup

Create and activate a virtual environment from the project root:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r vulnerable_web_app/requirements.txt
```

Initialize the demo database:

```bash
python vulnerable_web_app/database.py
```

Run the app:

```bash
python vulnerable_web_app/app.py
```

Open:

```text
http://127.0.0.1:5000
```

## Demo Account

```text
username: alice
password: password123
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

## Project Structure

```text
vulnerable_web_app/
├── app.py
├── database.py
├── requirements.txt
├── test_app.py
├── test_database.py
├── docs/
│   ├── sql_injection_walkthrough.md
│   └── xss_walkthrough.md
├── static/
│   └── style.css
└── templates/
    ├── comment.html
    ├── index.html
    ├── login.html
    └── result.html
```

## Run Tests

From the `cybersecurity_assessment_lab/` project root:

```bash
python -m unittest discover -s vulnerable_web_app -p 'test_*.py'
```

## Safety Boundary

This application is intentionally vulnerable. Run it locally only. Do not deploy it to a public network.
