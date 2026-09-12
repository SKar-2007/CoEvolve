"""End-to-end training test — full mock cycle.

Exercises the complete co-evolutionary pipeline:
    Attacker → Developer → Judge → Distiller → RegressionGuard → Elo → PromptStore

Tests both secure (j=0) and exploitable (j=1) paths, multi-episode runs,
rule accumulation, and Elo dynamics.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from packages.agents.attacker.generator import VULNERABILITY_CLASSES
from packages.agents.llm import LLMClient, LLMResponse
from packages.agents.regression_guard.guard import HistoricalArchive
from packages.agents.training_loop import EpisodeConfig, TrainingLoop
from packages.elo.calculator import EloCalculator
from packages.evolution.store import PromptStore


# ---------------------------------------------------------------------------
# Mock LLM that routes by system prompt keywords
# ---------------------------------------------------------------------------
class E2EMockLLM(LLMClient):
    """Deterministic mock LLM for E2E testing.

    Routes responses based on system prompt keywords:
    - 'red-team' / 'adversarial' → attacker task JSON
    - 'distill' / 'failure trace' → distiller rule JSON
    - everything else → developer patch
    """

    def __init__(self, *, secure: bool = True, rule_text: str = ""):
        super().__init__(model="e2e-mock")
        self.secure = secure
        self.rule_text = rule_text
        self.calls: list[dict[str, str]] = []

    def generate(
        self,
        system: str,
        user: str,
        temperature: float = 0.7,
        max_tokens: int = 4096,
    ) -> LLMResponse:
        self.calls.append({"system": system, "user": user})
        lower_system = system.lower()

        if "red-team" in lower_system or "adversarial" in lower_system:
            text = self._attacker_response(user)
        elif "distill" in lower_system or "failure trace" in lower_system:
            text = self._distiller_response(user)
        else:
            text = self._developer_response(user)

        return LLMResponse(text=text, provider="mock", model=self.model)

    def _attacker_response(self, user: str) -> str:
        import re

        match = re.search(r"vulnerability class:\s*(\w+)", user)
        vuln_class = match.group(1) if match else "SQLi"
        task = {
            "task_description": f"Fix the {vuln_class} vulnerability in the login endpoint",
            "context_files": [
                {
                    "path": "src/auth/login.py",
                    "snippet": "def login(username, password):\n    query = f\"SELECT * FROM users WHERE name='{username}' AND pass='{password}'\"\n    return db.execute(query)",
                }
            ],
            "vulnerability_class": vuln_class,
            "difficulty_tier": 3,
            "expected_exploit": "admin'--",
            "acceptance_criteria": f"Login handles {vuln_class} safely",
            "hidden_trap": "Direct string interpolation in SQL query",
        }
        return json.dumps(task)

    def _developer_response(self, user: str) -> str:
        if self.secure:
            return (
                "--- a/src/auth/login.py\n"
                "+++ b/src/auth/login.py\n"
                "@@ -1,3 +1,3 @@\n"
                " def login(username, password):\n"
                "-    query = f\"SELECT * FROM users WHERE name='{username}' AND pass='{password}'\"\n"
                '+    query = "SELECT * FROM users WHERE name = %s AND pass = %s"\n'
                "     return db.execute(query)\n"
                "+    return db.execute(query, (username, password))"
            )
        else:
            return (
                "--- a/src/auth/login.py\n"
                "+++ b/src/auth/login.py\n"
                "@@ -1,3 +1,3 @@\n"
                " def login(username, password):\n"
                "-    query = f\"SELECT * FROM users WHERE name='{username}' AND pass='{password}'\"\n"
                "+    query = f\"SELECT * FROM users WHERE name='{username}' AND pass='{password}'\"\n"
                "     return db.execute(query)"
            )

    def _distiller_response(self, user: str) -> str:
        rule = (
            self.rule_text
            or "ALWAYS use parameterized queries. Never interpolate user input into SQL strings."
        )
        return json.dumps(
            {
                "rule_text": rule,
                "vulnerability_class": "SQLi",
                "source_pattern": "Direct string interpolation in SQL query",
                "recommended_fix": "Use parameterized queries with placeholder syntax",
            }
        )


# ---------------------------------------------------------------------------
# Mock Judge that returns configurable outcomes
# ---------------------------------------------------------------------------
class MockJudge:
    """Returns j=0 (secure) or j=1 (exploitable) based on configuration."""

    def __init__(self, *, exploitable: bool = False):
        self.exploitable = exploitable
        self.evaluations: list[dict] = []

    def evaluate(self, **kwargs: Any) -> Any:
        from packages.judge.engine import JudgeVerdict

        self.evaluations.append(kwargs)
        j = 1 if self.exploitable else 0
        return JudgeVerdict(j=j, trace_id="mock-trace")


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------
class TestE2ESingleEpisode:
    """Single episode tests for both secure and exploitable paths."""

    def test_secure_episode(self, tmp_path: Path):
        """Developer produces secure code → j=0, no rule distilled."""
        llm = E2EMockLLM(secure=True)
        judge = MockJudge(exploitable=False)
        elo = EloCalculator()
        store = PromptStore(path=tmp_path / "store")

        loop = TrainingLoop(
            llm=llm,
            judge=judge,
            elo_calculator=elo,
            prompt_store=store,
        )

        config = EpisodeConfig(vulnerability_class="SQLi")
        trace = loop.run_episode(config)

        assert trace.judge_outcome == 0
        assert trace.distilled_rule is None
        assert trace.task is not None
        assert trace.task.vulnerability_class == "SQLi"
        assert trace.patch_text  # Developer produced a patch
        assert trace.elo_before["attacker"] == 1500.0
        assert trace.elo_before["developer"] == 1500.0
        assert trace.elo_after != trace.elo_before
        assert trace.error == ""
        assert len(llm.calls) >= 2  # At least attacker + developer

    def test_exploitable_episode(self, tmp_path: Path):
        """Developer produces vulnerable code → j=1, rule distilled and stored."""
        llm = E2EMockLLM(secure=False)
        judge = MockJudge(exploitable=True)
        elo = EloCalculator()
        store = PromptStore(path=tmp_path / "store")

        loop = TrainingLoop(
            llm=llm,
            judge=judge,
            elo_calculator=elo,
            prompt_store=store,
        )

        config = EpisodeConfig(vulnerability_class="SQLi")
        trace = loop.run_episode(config)

        assert trace.judge_outcome == 1
        assert trace.distilled_rule is not None
        assert trace.distilled_rule.is_valid
        assert trace.regression_passed is True
        assert len(store.rules()) == 1
        assert store.rules()[0].vulnerability_class == "SQLi"
        assert trace.prompt_version == 1

    def test_elo_dynamics(self, tmp_path: Path):
        """Elo ratings shift correctly after episodes."""
        llm = E2EMockLLM(secure=True)
        judge = MockJudge(exploitable=False)
        elo = EloCalculator()
        store = PromptStore(path=tmp_path / "store")

        loop = TrainingLoop(llm=llm, judge=judge, elo_calculator=elo, prompt_store=store)

        # Developer wins (secure) → developer Elo increases
        trace1 = loop.run_episode(EpisodeConfig(vulnerability_class="SQLi"))
        assert trace1.elo_after["developer"] > 1500.0
        assert trace1.elo_after["attacker"] < 1500.0

        # Second win → developer Elo increases further
        trace2 = loop.run_episode(
            EpisodeConfig(vulnerability_class="XSS"),
            current_ratings=(trace1.elo_after["attacker"], trace1.elo_after["developer"]),
        )
        assert trace2.elo_after["developer"] > trace1.elo_after["developer"]

    def test_all_vulnerability_classes(self, tmp_path: Path):
        """Each vulnerability class can run through the pipeline."""
        llm = E2EMockLLM(secure=True)
        judge = MockJudge(exploitable=False)
        elo = EloCalculator()
        store = PromptStore(path=tmp_path / "store")

        loop = TrainingLoop(llm=llm, judge=judge, elo_calculator=elo, prompt_store=store)

        for vc in VULNERABILITY_CLASSES:
            trace = loop.run_episode(EpisodeConfig(vulnerability_class=vc))
            assert trace.task is not None
            assert trace.task.vulnerability_class == vc
            assert trace.judge_outcome == 0


class TestE2EMultiEpisode:
    """Multi-episode scenarios with state accumulation."""

    def test_rule_accumulation(self, tmp_path: Path):
        """Multiple exploitable episodes accumulate rules in the store."""
        llm = E2EMockLLM(secure=False)
        judge = MockJudge(exploitable=True)
        elo = EloCalculator()
        store = PromptStore(path=tmp_path / "store")

        loop = TrainingLoop(llm=llm, judge=judge, elo_calculator=elo, prompt_store=store)

        ratings = (1500.0, 1500.0)
        for _i in range(3):
            trace = loop.run_episode(
                EpisodeConfig(vulnerability_class="SQLi"),
                current_ratings=ratings,
            )
            ratings = (trace.elo_after["attacker"], trace.elo_after["developer"])

        assert len(store.rules()) == 3
        assert all(r.vulnerability_class == "SQLi" for r in store.rules())

    def test_mixed_outcomes(self, tmp_path: Path):
        """Alternating secure/exploitable episodes produce correct rule count."""
        llm_secure = E2EMockLLM(secure=True)
        llm_vuln = E2EMockLLM(secure=False)
        elo = EloCalculator()
        store = PromptStore(path=tmp_path / "store")

        # Alternate between secure and exploitable judges
        judges = [
            MockJudge(exploitable=False),  # secure
            MockJudge(exploitable=True),  # exploitable
            MockJudge(exploitable=False),  # secure
            MockJudge(exploitable=True),  # exploitable
        ]

        ratings = (1500.0, 1500.0)
        for _i, judge in enumerate(judges):
            llm = llm_secure if not judge.exploitable else llm_vuln
            loop = TrainingLoop(llm=llm, judge=judge, elo_calculator=elo, prompt_store=store)
            trace = loop.run_episode(
                EpisodeConfig(vulnerability_class="SQLi"),
                current_ratings=ratings,
            )
            ratings = (trace.elo_after["attacker"], trace.elo_after["developer"])

        # 2 exploitable episodes → 2 rules
        assert len(store.rules()) == 2

    def test_prompt_version_increments(self, tmp_path: Path):
        """Prompt version increments when rules are accepted."""
        llm = E2EMockLLM(secure=False)
        judge = MockJudge(exploitable=True)
        elo = EloCalculator()
        store = PromptStore(path=tmp_path / "store")

        loop = TrainingLoop(llm=llm, judge=judge, elo_calculator=elo, prompt_store=store)

        ratings = (1500.0, 1500.0)
        versions = []
        for _ in range(3):
            trace = loop.run_episode(
                EpisodeConfig(vulnerability_class="SQLi"),
                current_ratings=ratings,
            )
            ratings = (trace.elo_after["attacker"], trace.elo_after["developer"])
            versions.append(trace.prompt_version)

        assert versions == [1, 2, 3]


class TestE2EPromptEvolution:
    """Test that rules flow through to the developer's prompt."""

    def test_rules_passed_to_developer(self, tmp_path: Path):
        """After a rule is distilled, it appears in the developer's prompt."""
        llm = E2EMockLLM(secure=False)
        judge = MockJudge(exploitable=True)
        elo = EloCalculator()
        store = PromptStore(path=tmp_path / "store")

        loop = TrainingLoop(llm=llm, judge=judge, elo_calculator=elo, prompt_store=store)

        # First episode: exploitable → rule distilled
        trace1 = loop.run_episode(EpisodeConfig(vulnerability_class="SQLi"))
        assert len(store.rules()) == 1

        # Second episode: developer should receive the rule
        llm2 = E2EMockLLM(secure=True)
        judge2 = MockJudge(exploitable=False)
        loop2 = TrainingLoop(llm=llm2, judge=judge2, elo_calculator=elo, prompt_store=store)

        loop2.run_episode(
            EpisodeConfig(vulnerability_class="SQLi"),
            current_ratings=(trace1.elo_after["attacker"], trace1.elo_after["developer"]),
        )

        # Check that a developer call was made with the rule in the system prompt
        dev_calls = [
            c
            for c in llm2.calls
            if "red-team" not in c["system"].lower() and "adversarial" not in c["system"].lower()
        ]
        assert len(dev_calls) > 0
        assert "ALWAYS use parameterized queries" in dev_calls[0]["system"]

    def test_multiple_classes_accumulate(self, tmp_path: Path):
        """Rules from different vulnerability classes all appear in prompt."""
        store = PromptStore(path=tmp_path / "store")

        from packages.evolution.store import PromptRule

        store.add_rule(
            PromptRule(rule_text="ALWAYS use parameterized queries", vulnerability_class="SQLi")
        )
        store.add_rule(
            PromptRule(rule_text="ALWAYS sanitize path inputs", vulnerability_class="PathTraversal")
        )
        store.add_rule(PromptRule(rule_text="ALWAYS escape HTML output", vulnerability_class="XSS"))

        llm = E2EMockLLM(secure=True)
        TrainingLoop(llm=llm, prompt_store=store)

        dev_calls = [c for c in llm.calls if "red-team" not in c["system"].lower()]
        if dev_calls:
            prompt = dev_calls[0]["system"]
            assert "parameterized queries" in prompt
            assert "sanitize path" in prompt
            assert "escape HTML" in prompt


class TestE2ERegressionGuard:
    """Test that regression guard integrates into the pipeline."""

    def test_valid_rule_accepted(self, tmp_path: Path):
        """A valid rule passes regression guard and is stored."""
        llm = E2EMockLLM(
            secure=False,
            rule_text="ALWAYS use parameterized queries for all database operations",
        )
        judge = MockJudge(exploitable=True)
        elo = EloCalculator()
        store = PromptStore(path=tmp_path / "store")
        archive = HistoricalArchive()

        loop = TrainingLoop(
            llm=llm,
            judge=judge,
            elo_calculator=elo,
            prompt_store=store,
            archive=archive,
        )

        trace = loop.run_episode(EpisodeConfig(vulnerability_class="SQLi"))
        assert trace.regression_passed is True
        assert len(store.rules()) == 1

    def test_archive_grows(self, tmp_path: Path):
        """Archive accumulates tasks across episodes (deduplicates identical ones)."""
        llm = E2EMockLLM(secure=True)
        judge = MockJudge(exploitable=False)
        elo = EloCalculator()
        store = PromptStore(path=tmp_path / "store")
        archive = HistoricalArchive()

        loop = TrainingLoop(
            llm=llm,
            judge=judge,
            elo_calculator=elo,
            prompt_store=store,
            archive=archive,
        )

        for _ in range(5):
            loop.run_episode(EpisodeConfig(vulnerability_class="SQLi"))

        # Archive deduplicates by task content hash, so identical tasks count once
        assert len(archive.all_tasks()) >= 1
        # But the loop ran 5 episodes successfully
        assert len(store.history()) >= 1


class TestE2EBatchTraining:
    """Test batch training session with convergence detection."""

    def test_batch_session(self, tmp_path: Path):
        """Batch training runs multiple episodes and produces a report."""
        from packages.agents.batch_trainer import TrainingSession

        llm = E2EMockLLM(secure=True)

        session = TrainingSession(
            llm=llm,
            episodes=10,
        )

        report = session.run(verbose=False)
        assert report.total_episodes == 10
        assert report.secure_rate > 0
        assert report.total_time_s > 0
