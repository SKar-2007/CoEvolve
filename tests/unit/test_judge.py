"""Unit tests for the Hybrid Judge Engine."""

from __future__ import annotations

from packages.judge.dast.executor import (
    SUCCESS_PATTERNS,
    ExploitExecutor,
    PayloadLibrary,
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


class TestPayloadLibrary:
    """Test the JSON-backed payload library (default path)."""

    EXPECTED_CLASSES = {
        "SQLi",
        "PathTraversal",
        "CommandInjection",
        "XSS",
        "SSRF",
        "Deserialization",
        "SSTI",
        "XXE",
        "OpenRedirect",
        "PrototypePollution",
    }

    def test_default_path_loads_all_classes(self):
        lib = PayloadLibrary()
        assert set(lib.classes()) >= self.EXPECTED_CLASSES

    def test_minimum_depth_per_class(self):
        lib = PayloadLibrary()
        for class_id in self.EXPECTED_CLASSES:
            assert len(lib.all(class_id)) >= 3, f"{class_id} needs >= 3 payloads"

    def test_rotation_wraps(self):
        lib = PayloadLibrary()
        n = len(lib.all("SQLi"))
        assert lib.get("SQLi", 0).payload == lib.get("SQLi", n).payload

    def test_missing_file_falls_back_to_static(self, tmp_path):
        lib = StaticPayloadLibrary(path=tmp_path / "nope.json")
        assert "SQLi" in lib.classes()
        assert lib.get("SQLi").payload == "' OR '1'='1' --"

    def test_unknown_class_raises(self):
        lib = PayloadLibrary()
        try:
            lib.get("NoSuchClass")
        except KeyError:
            pass
        else:
            raise AssertionError("expected KeyError")


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
