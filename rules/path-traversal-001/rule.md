# Rule: Path Traversal Prevention

## Description
Validate and sanitize all file paths before use. Use allowlists for permitted directories and resolve paths to prevent traversal attacks.

## Severity
High

## Vulnerability Class
PathTraversal

## Pattern
```python
# VULNERABLE
file_path = f"/uploads/{user_input}"
open(file_path)

# VULNERABLE
file_path = os.path.join("/uploads", user_input)
open(file_path)
```

## Fix
```python
# SECURE: Validate against allowlist
import os
ALLOWED_DIR = "/uploads"
file_path = os.path.join(ALLOWED_DIR, user_input)
real_path = os.path.realpath(file_path)
if not real_path.startswith(os.path.realpath(ALLOWED_DIR)):
    raise ValueError("Invalid path")
open(real_path)
```

## References
- CWE-22: Path Traversal
- OWASP: Path Traversal
