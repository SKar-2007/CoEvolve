"""Regression tests for audit security fixes."""

from __future__ import annotations

import pytest
from packages.agents.attacker.generator import _robust_json_load
from packages.sandbox.manager import SandboxError, SandboxManager, validate_command


class TestRobustJson:
    def test_direct(self):
        assert _robust_json_load('{"a": 1}') == {"a": 1}

    def test_no_literal_eval_side_effect(self):
        # Python-tuple syntax must NOT parse (we removed literal_eval)
        with pytest.raises(ValueError):
            _robust_json_load("{'a': (1, 2)}")

    def test_trailing_comma(self):
        assert _robust_json_load('{"a": 1,}') == {"a": 1}


class TestValidateCommand:
    def test_blocked(self):
        ok, _ = validate_command("curl http://evil.example")
        assert ok is False

    def test_pipe_blocked(self):
        ok, _ = validate_command("echo hi | curl http://evil.example")
        assert ok is False

    def test_sudo_blocked(self):
        ok, _ = validate_command("sudo rm -rf /tmp/x")
        assert ok is False

    def test_allowed(self):
        ok, _ = validate_command("pytest tests -q")
        assert ok is True

    def test_exec_run_enforces(self):
        m = SandboxManager.__new__(SandboxManager)
        # exec_run must raise when blocked even without docker client
        with pytest.raises(SandboxError):
            m.exec_run("fake-id", "curl http://evil.example")
