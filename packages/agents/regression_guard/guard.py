"""Regression Guard - validates rules against historical task archive."""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from ..distiller.pipeline import DistilledRule


@dataclass
class TaskRecord:
    task: dict[str, Any]
    outcome: int  # 0 = secure, 1 = vulnerable
    prompt_version: int | None = None


class HistoricalArchive:
    """Stores episode outcomes for retroactive rule validation."""

    def __init__(self) -> None:
        self._tasks: dict[str, TaskRecord] = {}

    def add(self, task: dict[str, Any], outcome: int, prompt_version: int | None = None) -> None:
        task_id = task.get("task_id") or self._hash(task)
        self._tasks[task_id] = TaskRecord(
            task=task, outcome=outcome, prompt_version=prompt_version
        )

    def passing_tasks(self) -> list[TaskRecord]:
        return [t for t in self._tasks.values() if t.outcome == 0]

    def all_tasks(self) -> list[TaskRecord]:
        return list(self._tasks.values())

    @staticmethod
    def _hash(task: dict[str, Any]) -> str:
        raw = json_dumps_stable(task)
        return hashlib.sha256(raw.encode()).hexdigest()[:16]


def json_dumps_stable(obj: Any) -> str:
    import json

    return json.dumps(obj, sort_keys=True, default=str)


class RegressionGuard:
    """Detects whether a candidate rule regresses previously-passing tasks.

    The caller supplies an ``evaluate`` callable that runs the developer agent
    with the candidate prompt and returns the judge outcome (0/1).
    """

    def __init__(
        self,
        archive: HistoricalArchive,
        evaluate: Callable[[dict[str, Any], list[str]], int],
        max_retries: int = 3,
    ):
        self.archive = archive
        self.evaluate = evaluate
        self.max_retries = max_retries

    def check(self, candidate_rules: list[str]) -> dict:
        """Run all passing tasks against the candidate prompt; find regressions."""
        passing = self.archive.passing_tasks()
        regressions = []
        for rec in passing:
            outcome = self.evaluate(rec.task, candidate_rules)
            if outcome == 1:  # previously secure task now vulnerable -> regression
                regressions.append(rec)
        return {
            "passed": not regressions,
            "regressed_tasks": [r.task.get("task_id", "unknown") for r in regressions],
            "tested": len(passing),
            "regressions": len(regressions),
        }

    def approve(self, rule: DistilledRule, all_rules: list[str]) -> tuple[bool, dict]:
        """Check a candidate rule bundle; returns (approved, report)."""
        report = self.check(all_rules + [rule.rule_text])
        return report["passed"], report
