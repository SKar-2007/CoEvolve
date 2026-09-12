# Security Rules

This directory contains distilled security rules organized by unique IDs.

## Structure

```
rules/
  {rule-id}/
    rule.md          # Rule definition
    metadata.json    # Rule metadata (class, severity, etc.)
    examples/        # Example vulnerable and fixed code
```

## Rule ID Format

Rule IDs follow the pattern: `{class}-{number}`

Examples:
- `sqli-001` - SQL injection rule
- `xss-001` - XSS rule
- `path-traversal-001` - Path traversal rule

## Adding Rules

Rules are automatically created when the distiller agent extracts new patterns from vulnerability reports.
