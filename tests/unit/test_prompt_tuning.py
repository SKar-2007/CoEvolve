"""Regression tests for cybersecurity prompt tuning (wording may evolve,
contracts must not)."""

from __future__ import annotations

from packages.agents.attacker.generator import ATTACKER_SYSTEM_PROMPT
from packages.agents.developer.executor import BASE_DEVELOPER_PROMPT, DeveloperAgent
from packages.agents.distiller.pipeline import DISTILLER_SYSTEM_PROMPT
from packages.agents.llm import MockClient
from packages.agents.training_loop import TrainingLoop


class TestAttackerTuning:
    def test_json_contract_intact(self):
        for key in (
            "task_description",
            "context_files",
            "vulnerability_class",
            "difficulty_tier",
            "expected_exploit",
            "acceptance_criteria",
            "hidden_trap",
        ):
            assert key in ATTACKER_SYSTEM_PROMPT

    def test_tier_calibration_present(self):
        assert "DIFFICULTY CALIBRATION" in ATTACKER_SYSTEM_PROMPT
        assert "Tiers 1-3" in ATTACKER_SYSTEM_PROMPT
        assert "Tiers 7" in ATTACKER_SYSTEM_PROMPT


class TestDeveloperTuning:
    def test_per_class_checklist(self):
        for marker in (
            "SQLi:",
            "PathTraversal:",
            "SSRF/OpenRedirect:",
            "Deserialization/SSTI/XXE:",
            "CommandInjection:",
            "PrototypePollution:",
            "__proto__",
            "allowlist",
        ):
            assert marker in BASE_DEVELOPER_PROMPT

    def test_rules_block_format_unchanged(self):
        agent = DeveloperAgent(MockClient())
        prompt = agent.build_system_prompt(["ALWAYS x"])
        assert "EVOLVED SECURITY RULES (must be followed):\n- ALWAYS x" in prompt


class TestDistillerTuning:
    def test_contract_and_scope(self):
        for key in ("rule_text", "vulnerability_class", "source_pattern", "recommended_fix"):
            assert key in DISTILLER_SYSTEM_PROMPT
        assert "ALWAYS or NEVER" in DISTILLER_SYSTEM_PROMPT
        assert "does not apply when" in DISTILLER_SYSTEM_PROMPT
        for cls in ("SQLi", "SSTI", "XXE", "PrototypePollution"):
            assert cls in DISTILLER_SYSTEM_PROMPT


class TestSmallLLMRouting:
    def test_distiller_uses_small_llm(self):
        main, small = MockClient("main"), MockClient("small")
        loop = TrainingLoop(llm=main, small_llm=small)
        assert loop.distiller.client is small
        assert loop.attacker.client is main

    def test_default_falls_back_to_main(self):
        main = MockClient("main")
        loop = TrainingLoop(llm=main)
        assert loop.distiller.client is main
