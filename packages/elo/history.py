"""Rating history tracker with persistence hook."""

from __future__ import annotations

import time
from dataclasses import asdict, dataclass, field

from .calculator import Ratings


@dataclass
class RatingSnapshot:
    attacker: float
    developer: float
    timestamp: float = field(default_factory=time.time)
    episode_k: int | None = None

    def as_dict(self) -> dict:
        return asdict(self)


class RatingHistory:
    """Appends rating snapshots and produces time-series summaries."""

    def __init__(self) -> None:
        self._snapshots: list[RatingSnapshot] = []

    def record(self, ratings: Ratings, episode_k: int | None = None) -> RatingSnapshot:
        snap = RatingSnapshot(
            attacker=ratings.attacker,
            developer=ratings.developer,
            episode_k=episode_k,
        )
        self._snapshots.append(snap)
        return snap

    def series(self) -> list[dict]:
        return [s.as_dict() for s in self._snapshots]

    def latest(self) -> RatingSnapshot | None:
        return self._snapshots[-1] if self._snapshots else None

    def trend(self, window: int = 50) -> dict:
        """Return deltas over the last ``window`` snapshots (or all if fewer)."""
        recent = self._snapshots[-window:]
        if len(recent) < 2:
            return {"attacker_delta": 0.0, "developer_delta": 0.0, "samples": len(recent)}
        first, last = recent[0], recent[-1]
        return {
            "attacker_delta": last.attacker - first.attacker,
            "developer_delta": last.developer - first.developer,
            "samples": len(recent),
        }
