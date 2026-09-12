"""Unit tests for the RegressionGuard module."""

from __future__ import annotations

from packages.agents.distiller.pipeline import DistilledRule
from packages.agents.regression_guard.guard import HistoricalArchive, RegressionGuard


class TestHistoricalArchive:
    def test_add_and_retrieve(self) -> None:
        archive = HistoricalArchive()
        archive.add(task={"task_id": "t1", "desc": "test"}, outcome=0)
        assert len(archive.all_tasks()) == 1

    def test_passing_tasks(self) -> None:
        archive = HistoricalArchive()
        archive.add(task={"task_id": "t1"}, outcome=0)
        archive.add(task={"task_id": "t2"}, outcome=1)
        archive.add(task={"task_id": "t3"}, outcome=0)
        assert len(archive.passing_tasks()) == 2

    def test_duplicate_task_id(self) -> None:
        archive = HistoricalArchive()
        archive.add(task={"task_id": "t1"}, outcome=0)
        archive.add(task={"task_id": "t1"}, outcome=1)
        assert len(archive.all_tasks()) == 1
        assert archive.all_tasks()[0].outcome == 1

    def test_hash_based_id(self) -> None:
        archive = HistoricalArchive()
        archive.add(task={"desc": "no id"}, outcome=0)
        assert len(archive.all_tasks()) == 1


class TestRegressionGuard:
    def test_no_regressions(self) -> None:
        archive = HistoricalArchive()
        archive.add(task={"task_id": "t1"}, outcome=0)
        archive.add(task={"task_id": "t2"}, outcome=0)

        def evaluate(task: dict, rules: list[str]) -> int:
            return 0  # always secure

        guard = RegressionGuard(archive=archive, evaluate=evaluate, max_retries=2)
        rule = DistilledRule(
            rule_text="always sanitize inputs",
            vulnerability_class="SQLi",
            source_pattern="",
            recommended_fix="",
            source_trace_id="",
        )
        approved, report = guard.approve(rule=rule, all_rules=[])
        assert approved is True
        assert report["passed"] is True

    def test_detects_regression(self) -> None:
        archive = HistoricalArchive()
        archive.add(task={"task_id": "t1"}, outcome=0)

        def evaluate(task: dict, rules: list[str]) -> int:
            return 1  # always vulnerable

        guard = RegressionGuard(archive=archive, evaluate=evaluate, max_retries=2)
        rule = DistilledRule(
            rule_text="bad rule",
            vulnerability_class="SQLi",
            source_pattern="",
            recommended_fix="",
            source_trace_id="",
        )
        approved, report = guard.approve(rule=rule, all_rules=[])
        assert approved is False
        assert report["passed"] is False
        assert len(report["regressed_tasks"]) > 0
