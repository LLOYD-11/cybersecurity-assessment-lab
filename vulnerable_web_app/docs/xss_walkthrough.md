# Cross-Site Scripting Walkthrough

This walkthrough explains the cross-site scripting demo in the local vulnerable web app.

## Scope

This demo must be run locally only:

```text
http://127.0.0.1:5000
```

Do not deploy the intentionally vulnerable route to a public network.

## Vulnerable Behavior

The vulnerable comment route renders user input with Jinja's `safe` filter:

```html
<div class="rendered-comment">{{ comment|safe }}</div>
```

The `safe` filter tells the template engine that the value should not be escaped. If the value comes from untrusted user input, the browser may interpret it as HTML or script.

## Local Test Payload

Use this payload in the vulnerable comment form:

```html
<script>alert('xss')</script>
```

The vulnerable page renders the raw script tag. The secure page renders the same payload as escaped text.

## Impact

In a real application, cross-site scripting can allow attackers to run JavaScript in another user's browser, steal session data, modify page content, or perform actions as the victim.

## Remediation

The secure comment route uses Jinja's default escaping:

```html
<div class="rendered-comment">{{ comment }}</div>
```

With default escaping, characters such as `<`, `>`, and quotes are encoded before being sent to the browser. The browser displays the payload as text instead of executing it.

## Key Lesson

Do not mark untrusted user input as safe. Keep template autoescaping enabled and only allow trusted, sanitized HTML when there is a clear requirement.
