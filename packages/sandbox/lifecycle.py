"""Episode lifecycle orchestration for the sandbox.

Coordinates container create -> agent execution -> destroy for a single
training episode, matching the 7-step lifecycle in blueprint.md.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable

from .config import SandboxConfig
from .manager import SandboxManager, ContainerSpec

logger = logging.getLogger(__name__)


class EpisodeStatus(str, Enum):
    PENDING = "pending"
    CREATING = "creating"
    EXECUTING = "executing"
    EVALUATING = "evaluating"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass
class EpisodeResult:
    episode_id: str
    container_id: str | None = None
    status: EpisodeStatus = EpisodeStatus.PENDING
    output: str = ""
    error: str = ""
    metadata: dict = field(default_factory=dict)


class EpisodeOrchestrator:
    """Runs a single training episode inside a hardened container."""

    def __init__(
        self,
        manager: SandboxManager | None = None,
        config: SandboxConfig | None = None,
    ):
        self.manager = manager or SandboxManager(config=config)

    def run(
        self,
        episode_id: str,
        entrypoint: Callable[[str], str],
        environment: dict | None = None,
    ) -> EpisodeResult:
        """Create a container, run ``entrypoint(container_id)``, always destroy.

        The container is destroyed even when the entrypoint raises, so no
        sandbox survives a failed episode.
        """
        result = EpisodeResult(episode_id=episode_id)
        spec: ContainerSpec | None = None
        try:
            result.status = EpisodeStatus.CREATING
            spec = self.manager.create(episode_id, environment=environment)
            result.container_id = spec.container_id

            result.status = EpisodeStatus.EXECUTING
            result.output = entrypoint(spec.container_id)

            result.status = EpisodeStatus.COMPLETED
        except Exception as exc:  # pragma: no cover
            result.status = EpisodeStatus.FAILED
            result.error = str(exc)
            logger.exception("Episode %s failed", episode_id)
        finally:
            if spec is not None:
                try:
                    self.manager.destroy(spec.container_id)
                except Exception:  # pragma: no cover
                    logger.exception("Failed to destroy container %s", spec.container_id)
            else:
                # Containers created outside the orchestrator may still linger
                self.manager.destroy_all_managed()
        return result