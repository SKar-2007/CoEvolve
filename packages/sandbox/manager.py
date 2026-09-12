"""Secure container lifecycle management for CoEvolve Sandbox.

Implements the 7-layer isolation stack defined in security_governance.md:

    Layer 1: Resource limits      (cgroups: CPU, memory, PIDs)
    Layer 2: Network isolation    (--network none)
    Layer 3: Filesystem isolation (--read-only + tmpfs scratch spaces)
    Layer 4: Capability dropping  (--cap-drop ALL)
    Layer 5: Syscall filtering    (Seccomp BPF profile)
    Layer 6: Process isolation    (non-root user, no-new-privileges)
    Layer 7: Application         (sandbox entrypoint constraints)
"""

from __future__ import annotations

import json

from .config import BLOCKED_COMMANDS, SandboxConfig


class SandboxError(RuntimeError):
    """Raised when a sandbox lifecycle operation fails."""


class ContainerSpec:
    """Value object describing a running container instance."""

    def __init__(self, container_id: str, episode_id: str):
        self.container_id = container_id
        self.episode_id = episode_id

    def __repr__(self) -> str:  # pragma: no cover
        return f"ContainerSpec(id={self.container_id}, episode={self.episode_id})"


class SandboxManager:
    """Manages creation, inspection, and destruction of hardened containers."""

    def __init__(self, config: SandboxConfig | None = None):
        self.config = config or SandboxConfig()
        self._client = None

    @property
    def client(self):
        """Lazily initialize the Docker client."""
        if self._client is None:
            try:
                import docker  # type: ignore[import-not-found]
            except ImportError as exc:  # pragma: no cover
                raise SandboxError("Docker SDK not installed. Run `pip install docker`.") from exc
            self._client = docker.from_env()
        return self._client

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------
    def create(self, episode_id: str, environment: dict | None = None) -> ContainerSpec:
        """Start a hardened container for one training episode."""
        labels = {"coevolve.episode": episode_id, "coevolve.managed": "true"}
        kwargs = self.config.docker_kwargs(environment=environment or {})
        kwargs["labels"] = {**kwargs.get("labels", {}), **labels}
        try:
            container = self.client.containers.run(**kwargs)
        except Exception as exc:  # pragma: no cover
            raise SandboxError(f"Failed to start sandbox container: {exc}") from exc
        return ContainerSpec(container_id=container.id, episode_id=episode_id)

    def exec_run(self, container_id: str, command: str, timeout: int = 60) -> tuple[int, str]:
        """Execute a command inside an existing container."""
        validate_command(command)
        try:
            container = self.client.containers.get(container_id)
            res = container.exec_run(
                ["/bin/sh", "-c", command],
                timeout=timeout,
                stdout=True,
                stderr=True,
                demux=False,
            )
            output = res.output
            if isinstance(output, bytes):
                output = output.decode("utf-8", errors="replace")
            return int(res.exit_code), output
        except Exception as exc:  # pragma: no cover
            raise SandboxError(f"exec failed in {container_id}: {exc}") from exc

    def stats(self, container_id: str) -> dict:
        """Return resource usage stats for a container."""
        container = self.client.containers.get(container_id)
        raw = container.stats(stream=False)
        pids = raw.get("pids_stats", {}).get("current", 0)
        mem = raw.get("memory_stats", {})
        return {
            "status": container.status,
            "pids": pids,
            "memory_usage": mem.get("usage", 0),
            "memory_limit": mem.get("limit", 0),
            "cpu_total_usage": raw.get("cpu_stats", {}).get("cpu_usage", {}).get("total_usage", 0),
        }

    def destroy(self, container_id: str) -> None:
        """Force-stop and remove a container along with its volumes."""
        try:
            container = self.client.containers.get(container_id)
            if container.status == "running":
                container.stop(timeout=5)
            container.remove(force=True, v=True)
        except Exception as exc:  # pragma: no cover
            raise SandboxError(f"Failed to destroy container {container_id}: {exc}") from exc

    def destroy_all_managed(self) -> int:
        """Destroy every managed container (crash recovery)."""
        destroyed = 0
        try:
            containers = self.client.containers.list(
                all=True, filters={"label": "coevolve.managed=true"}
            )
            for c in containers:
                self.destroy(c.id)
                destroyed += 1
        except Exception:  # pragma: no cover
            pass
        return destroyed

    # ------------------------------------------------------------------
    # Validation helpers
    # ------------------------------------------------------------------
    def verify_isolation(self, container_id: str) -> dict:
        """Run a battery of runtime checks that each isolation layer held."""
        checks: dict[str, dict[str, object]] = {
            "network_isolated": {},
            "non_root_user": {},
            "read_only_root": {},
        }
        for name, cmd in (
            ("network_isolated", "ip route 2>/dev/null || true"),
            ("non_root_user", "id -u"),
            ("read_only_root", "touch /root-write-test 2>&1 || true"),
        ):
            exit_code, output = self.exec_run(container_id, cmd)
            checks[name] = {"exit_code": exit_code, "output": output.strip()}
        return checks


def validate_command(command: str, blocked: list[str] | None = None) -> tuple[bool, str]:
    """Validate a shell command against the blocked-command allowlist."""
    blocked = blocked or BLOCKED_COMMANDS
    low = command.lower()
    for b in blocked:
        # match as standalone token word-boundary to avoid over-blocking
        if any(token.lower() == b.lower() for token in command.split()):
            return False, f"Blocked command: {b}"
        if b in low and (f"| {b} " in low or f"|{b} " in low):
            return False, f"Blocked command in pipe: {b}"
    return True, "command allowed"


def validate_seccomp(profile_path) -> bool:
    """Validate a seccomp profile JSON: default blocks, no dangerous syscalls allowed."""
    from pathlib import Path

    path = Path(profile_path)
    profile = json.loads(path.read_text())
    assert profile["defaultAction"] in {"SCMP_ACT_ERRNO", "SCMP_ACT_KILL"}, (
        "default action must block syscalls"
    )
    allowed: set[str] = set()
    for group in profile.get("syscalls", []):
        if group["action"] == "SCMP_ACT_ALLOW":
            allowed.update(group["names"])
    dangerous = {
        "ptrace",
        "mount",
        "umount2",
        "kexec_load",
        "init_module",
        "delete_module",
        "bpf",
        "unshare",
        "setns",
        "keyctl",
        "add_key",
        "request_key",
        "userfaultfd",
    }
    overlap = dangerous.intersection(allowed)
    if overlap:
        raise ValueError(f"Dangerous syscalls allowed: {sorted(overlap)}")
    return True
