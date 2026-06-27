# SQL Injection Walkthrough

This walkthrough explains the SQL injection demo in the local vulnerable web app.

## Scope

This demo must be run locally only:

```text
http://127.0.0.1:5000
```

Do not deploy the intentionally vulnerable route to a public network.

## Vulnerable Behavior

The vulnerable login route builds a SQL query by directly inserting user input into the query string:

```python
query = (
    "SELECT id, username FROM users "
    f"WHERE username = '{username}' AND password = '{password}'"
)
```

Because the input becomes part of the SQL syntax, a crafted username can change the query logic.

## Local Test Payload

Use this payload in the vulnerable login form:

```text
username: ' OR '1'='1' --
password: anything
```

The resulting query becomes logically true and comments out the password check:

```sql
SELECT id, username FROM users WHERE username = '' OR '1'='1' --' AND password = 'anything'
```

## Impact

In a real application, this pattern can allow authentication bypass, unauthorized data access, data modification, or data deletion.

## Framework Mapping

This demo maps to [OWASP Top 10 A03:2021 - Injection](https://owasp.org/Top10/A03_2021-Injection/). OWASP lists SQL injection as a common injection weakness and recommends keeping user input separate from commands and queries.

## Remediation

The secure login route uses parameterized queries:

```python
query = (
    "SELECT id, username FROM users "
    "WHERE username = ? AND password = ?"
)
user = connection.execute(query, (username, password)).fetchone()
```

Parameterized queries keep user input as data rather than SQL syntax. The same payload is treated as a literal username and should fail to log in.

## Key Lesson

Never build SQL queries by concatenating or formatting untrusted user input. Use parameterized queries or a well-configured ORM.
