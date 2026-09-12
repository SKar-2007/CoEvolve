"""Sandbox runtime configuration.

Centralizes the hardening parameters for the per-episode Docker containers.
"""

from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel, Field

DOCKER_DIR = Path(__file__).resolve().parent / "docker"
SECCOMP_PROFILE_PATH = DOCKER_DIR / "seccomp-profile.json"
BASE_IMAGE = "coevolve-sandbox:latest"

#: Paths that must never be writable inside a container.
BLOCKED_WRITABLE_PATHS = [
    "/",
    "/etc",
    "/usr",
    "/bin",
    "/sbin",
    "/lib",
    "/var",
    "/root",
    "/home",
    "/app",
]

#: Shell binaries that the Developer agent must never invoke.
BLOCKED_COMMANDS = [
    "curl",
    "wget",
    "nc",
    "ncat",
    "socat",
    "ssh",
    "scp",
    "rsync",
    "rclone",
    "docker",
    "kubectl",
    "helm",
    "sudo",
    "su",
    "passwd",
    "mount",
    "umount",
    "fdisk",
    "iptables",
    "nftables",
    "crontab",
    "at",
    "systemctl",
    "service",
]


class ContainerLimits(BaseModel):
    """Resource limits applied via cgroups."""

    nano_cpus: int = Field(default=2 * 10**9, ge=0, description="CPU limit in nanocores")
    mem_limit: str = "2g"
    memswap_limit: str = "2g"
    pids_limit: int = Field(default=256, ge=0)
    cpu_shares: int = 512


class WorkspaceConfig(BaseModel):
    """tmpfs scratch space configuration."""

    tmp_size: str = "100M"
    workspace_size: str = "500M"
    tmpfs_options: str = "mode=1777,noexec,nosuid"


class SandboxConfig(BaseModel):
    """Full per-episode container configuration."""

    image: str = BASE_IMAGE
    limits: ContainerLimits = Field(default_factory=ContainerLimits)
    workspace: WorkspaceConfig = Field(default_factory=WorkspaceConfig)
    seccomp_profile: Path = SECCOMP_PROFILE_PATH
    read_only: bool = True
    network_mode: str = "none"
    cap_drop: list[str] = Field(default_factory=lambda: ["ALL"])
    cap_add: list[str] = Field(default_factory=list)
    user: str = "1000:1000"
    no_new_privileges: bool = True
    auto_remove: bool = True
    init: bool = True
    labels: dict[str, str] = Field(default_factory=dict)

    def docker_kwargs(self, environment: dict | None = None) -> dict:
        """Translate the config into Docker SDK / docker run kwargs."""
        return {
            "image": self.image,
            "detach": True,
            "auto_remove": self.auto_remove,
            "network_mode": self.network_mode,
            "read_only": self.read_only,
            "user": self.user,
            "init": self.init,
            "cap_drop": list(self.cap_drop),
            "cap_add": list(self.cap_add),
            "nano_cpus": self.limits.nano_cpus,
            "mem_limit": self.limits.mem_limit,
            "memswap_limit": self.limits.memswap_limit,
            "pids_limit": self.limits.pids_limit,
            "cpu_shares": self.limits.cpu_shares,
            "tmpfs": {
                "/tmp": f"size={self.workspace.tmp_size},{self.workspace.tmpfs_options}",
                "/workspace": (
                    f"size={self.workspace.workspace_size},{self.workspace.tmpfs_options}"
                ),
            },
            "security_opt": [
                "no-new-privileges" if self.no_new_privileges else None,
                f"seccomp={self.seccomp_profile}",
            ],
            "environment": environment or {},
            "labels": self.labels,
        }


def default_sandbox_config() -> SandboxConfig:
    """Return the recommended hardened configuration."""
    return SandboxConfig()
