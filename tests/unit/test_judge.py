"""Unit tests for the Hybrid Judge Engine."""

from __future__ import annotations

from packages.judge.dast.executor import (
    SUCCESS_PATTERNS,
    ExploitExecutor,
    StaticPayloadLibrary,
)
from packages.judge.engine import HybridJudge, JudgeVerdict


class TestJudgeVerdict:
    """Test the JudgeVerdict data class."""

    def test_defaults(self):
        verdict = JudgeVerdict(j=0)
        assert verdict.j == 0
        assert verdict.exploitable is False

    def test_exploitable_true(self):
        verdict = JudgeVerdict(j=1)
        assert verdict.exploitable is True


class TestStaticPayloadLibrary:
    """Test the in-memory payload library."""

    def test_static_payloads_loaded(self):
        lib = StaticPayloadLibrary()
        assert "SQLi" in lib.classes()
        assert "XSS" in lib.classes()

    def test_get_payload(self):
        lib = StaticPayloadLibrary()
        payload = lib.get("SQLi")
        assert payload.payload == "' OR '1'='1' --"
        assert payload.class_id == "SQLi"


class TestExploitExecutor:
    """Test exploit execution (lightweight mock)."""

    def test_execute_returns_dast_result(self):
        lib = StaticPayloadLibrary()
        executor = ExploitExecutor(lib)
        result = executor.execute("SQLi")
        assert result.exploit_class == "SQLi"
        assert isinstance(result.success, bool)

    def test_success_patterns(self):
        """Test that success patterns are defined."""
        for class_id in StaticPayloadLibrary.STATIC_PAYLOADS:
            assert class_id in SUCCESS_PATTERNS


class TestHybridJudgeBasics:
    """Basic sanity checks for the Hybrid Judge."""

    def test_evaluates_to_judgment(self):
        judge = HybridJudge()
        # A plain string patch should be "secure" since there's no app to exploit
        verdict = judge.evaluate(
            patch_text="def fix(): pass",
            vulnerability_class="SQLi",
            episode_k=1,
        )
        # Even with no SAST match and no exploit success, verdict should be structured
        assert isinstance(verdict, JudgeVerdict)
