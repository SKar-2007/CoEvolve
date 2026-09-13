"""
Security regression tests for Bugs 4, 5, 6.
Run with:  python scripts/test_security_bugs.py
"""

from __future__ import annotations
import ast, inspect, os, subprocess, sys, tempfile
import unittest.mock as mock
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
os.environ.setdefault("DATABASE_URL", "sqlite:///coevolve.db")
os.environ.setdefault("SECRET_KEY", "dev-secret")

results = []

def check(label, condition, detail=""):
    mark = "PASS" if condition else "FAIL"
    results.append((mark, label))
    suffix = f"  ({detail})" if detail else ""
    print(f"  [{mark}] {label}{suffix}")

# ===========================================================
# BUG 4 - validate_command return enforced in exec_run
# ===========================================================
print("=" * 65)
print("BUG 4: validate_command enforced in SandboxManager.exec_run")
print("=" * 65)

from packages.sandbox.manager import SandboxError, SandboxManager, validate_command

# 4a - validate_command blocks known-bad tokens
for cmd in ["rm -rf /", "shutdown now", "mkfs /dev/sda", "reboot"]:
    allowed, reason = validate_command(cmd)
    check(f"validate_command blocks '{cmd}'", not allowed, reason)

for cmd in ["ls -la", "python -m pytest tests/", "echo hello"]:
    allowed, reason = validate_command(cmd)
    check(f"validate_command allows '{cmd}'", allowed, reason)

# 4b - exec_run raises SandboxError for blocked command
mgr = SandboxManager()
mgr._client = mock.MagicMock()
try:
    mgr.exec_run("fake-id", "rm -rf /")
    check("exec_run raises SandboxError for blocked command", False, "no exception raised")
except SandboxError as e:
    check("exec_run raises SandboxError for blocked command", True, str(e))

# 4c - validate_command result is not ignored
with mock.patch("packages.sandbox.manager.validate_command", return_value=(False, "mocked")):
    try:
        mgr.exec_run("fake-id", "echo hello")
        check("exec_run cannot bypass validate_command", False, "no exception raised")
    except SandboxError:
        check("exec_run cannot bypass validate_command", True)

print()

# ===========================================================
# BUG 5 - Path traversal blocked in ReadFileTool / WriteFileTool
# ===========================================================
print("=" * 65)
print("BUG 5: Path traversal in ReadFileTool / WriteFileTool")
print("=" * 65)

from packages.agents.developer.tools import ReadFileTool, WriteFileTool

with tempfile.TemporaryDirectory() as tmp:
    ws = Path(tmp)
    (ws / "safe.txt").write_text("hello world")
    (ws / "subdir").mkdir()
    (ws / "subdir" / "nested.py").write_text("x = 1")
    r = ReadFileTool(ws)
    w = WriteFileTool(ws)

    # Legitimate reads
    out = r.execute(path="safe.txt")
    check("ReadFileTool: normal read succeeds", "hello world" in out, out[:50])
    out = r.execute(path="subdir/nested.py")
    check("ReadFileTool: nested read succeeds", "x = 1" in out, out[:50])

    # Must be blocked
    for path, label in [
        ("../../etc/passwd",              "classic ../.."),
        ("../../../windows/system32/cmd", "deep ../.."),
        ("/etc/passwd",                   "absolute path"),
        ("subdir/../../etc/hosts",        "traversal via subdir"),
    ]:
        out = r.execute(path=path)
        check(f"ReadFileTool blocks: {label}", "path traversal detected" in out, out[:60])

    # Legitimate writes
    out = w.execute(path="output.txt", content="safe")
    check("WriteFileTool: normal write succeeds", "Wrote" in out, out)
    out = w.execute(path="subdir/out.py", content="y = 2")
    check("WriteFileTool: nested write succeeds", "Wrote" in out, out)

    # Must be blocked
    for path, label in [
        ("../../tmp/evil.sh", "classic ../.. write"),
        ("/tmp/evil.sh",      "absolute path write"),
    ]:
        out = w.execute(path=path, content="malicious")
        check(f"WriteFileTool blocks: {label}", "path traversal detected" in out, out[:60])

print()

# ===========================================================
# BUG 6 - RunTestsTool: shell=False, no user input in cmd
# ===========================================================
print("=" * 65)
print("BUG 6: Command injection in RunTestsTool (shell=False)")
print("=" * 65)

from packages.agents.developer.tools import RunTestsTool

# 6a - static analysis: no shell=True
src = inspect.getsource(RunTestsTool.execute)
tree = ast.parse(src)
shell_true_found = any(
    isinstance(n, ast.keyword) and n.arg == "shell"
    and isinstance(n.value, ast.Constant) and n.value.value is True
    for n in ast.walk(tree)
)
check("RunTestsTool: shell=False in source", not shell_true_found)

# 6b - injection attempt doesn't run system commands
with tempfile.TemporaryDirectory() as tmp2:
    tool = RunTestsTool(Path(tmp2), timeout=5)
    out = tool.execute(path="tests; id")
    injection_succeeded = "uid=" in out and "root" in out
    check("RunTestsTool: injection attempt safely fails", not injection_succeeded, out[:80])

# 6c - subprocess called with list, not string
with mock.patch("subprocess.run") as mock_run:
    mock_run.return_value = mock.MagicMock(returncode=0, stdout="ok", stderr="")
    RunTestsTool(Path("."), timeout=5).execute(path="tests/")
    cmd_arg = mock_run.call_args[0][0]
    check("RunTestsTool: subprocess called with list", isinstance(cmd_arg, list), repr(cmd_arg))

# 6d - shell kwarg is falsy
with mock.patch("subprocess.run") as mock_run:
    mock_run.return_value = mock.MagicMock(returncode=0, stdout="ok", stderr="")
    RunTestsTool(Path("."), timeout=5).execute(path="tests/")
    shell_val = mock_run.call_args[1].get("shell", False)
    check("RunTestsTool: shell kwarg is falsy", not shell_val, f"shell={shell_val!r}")

# ===========================================================
# Summary
# ===========================================================
print()
print("=" * 65)
passed = sum(1 for m, _ in results if m == "PASS")
failed = sum(1 for m, _ in results if m == "FAIL")
print(f"RESULT: {passed} PASSED  |  {failed} FAILED")
if failed:
    print("\nFAILURES:")
    for m, label in results:
        if m == "FAIL":
            print(f"  - {label}")
else:
    print("All security checks passed.")
sys.exit(0 if failed == 0 else 1)
