# Rule: Cross-Site Scripting (XSS) Prevention

## Description
Always escape output rendered in HTML contexts. Use template engines with auto-escaping or explicitly escape user input before rendering.

## Severity
High

## Vulnerability Class
XSS

## Pattern
```python
# VULNERABLE
html = f"<div>{user_input}</div>"
return html

# VULNERABLE
return f"<script>var data = '{user_data}';</script>"
```

## Fix
```python
# SECURE (using template engine auto-escaping)
return render_template("template.html", data=user_input)

# SECURE (explicit escaping)
from markupsafe import escape
html = f"<div>{escape(user_input)}</div>"
```

## References
- CWE-79: Cross-site Scripting
- OWASP: XSS Prevention Cheat Sheet
