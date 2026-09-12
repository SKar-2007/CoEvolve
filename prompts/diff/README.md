# Prompt Diff Utility

Compare different versions of agent prompts to track changes over time.

## Usage

```bash
# Compare current prompts against a specific version
python prompts/diff/diff.py v1_2026-09-12

# Compare two specific versions
python prompts/diff/diff.py v1_2026-09-12 v1_2026-09-13
```

## Output

The diff utility produces unified diff output showing:
- Lines prefixed with `-` were removed
- Lines prefixed with `+` were added
- Lines prefixed with ` ` are unchanged

## Examples

```bash
# See what changed since initial version
python prompts/diff/diff.py v1_2026-09-12

# Compare two historical versions
python prompts/diff/diff.py v1_2026-09-12 v1_2026-09-14
```
