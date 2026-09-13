# Rule: SQL Injection Prevention

## Description
Always use parameterized queries or ORM methods for database operations. Never construct SQL queries via string concatenation with user input.

## Severity
Critical

## Vulnerability Class
SQLi

## Pattern
```python
# VULNERABLE
query = f"SELECT * FROM users WHERE id = {user_id}"
cursor.execute(query)

# VULNERABLE
query = "SELECT * FROM users WHERE id = " + user_id
cursor.execute(query)
```

## Fix
```python
# SECURE
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))

# SECURE (ORM)
User.objects.filter(id=user_id)
```

## References
- CWE-89: SQL Injection
- OWASP: SQL Injection Prevention Cheat Sheet
