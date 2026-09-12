"""Unit tests for semantic deduplication module."""

from __future__ import annotations

from packages.evolution.dedupe import (
    _jaccard_duplicate,
    _tokens,
    is_duplicate,
    semantic_similarity,
    validate_rule_mandate,
)


class TestJaccardDedup:
    def test_exact_duplicate(self) -> None:
        assert _jaccard_duplicate("always use parameterized queries", ["always use parameterized queries"]) is True

    def test_similar_not_duplicate(self) -> None:
        assert _jaccard_duplicate("always sanitize input", ["never trust user input"]) is False

    def test_empty_existing(self) -> None:
        assert _jaccard_duplicate("rule", []) is False

    def test_threshold(self) -> None:
        # Exact match should always be detected
        assert _jaccard_duplicate("always sanitize user input", ["always sanitize user input"], threshold=0.9) is True


class TestIsDuplicate:
    def test_no_existing(self) -> None:
        assert is_duplicate("rule", []) is False

    def test_with_existing(self) -> None:
        assert is_duplicate("always use parameterized queries", ["always use parameterized queries"]) is True


class TestTokens:
    def test_basic(self) -> None:
        tokens = _tokens("Hello, World! 123")
        assert "hello" in tokens
        assert "world" in tokens
        assert "123" in tokens


class TestValidateRuleMandate:
    def test_valid_always(self) -> None:
        class Rule:
            rule_text = "always use parameterized queries for database access"

        assert validate_rule_mandate(Rule()) is True

    def test_valid_never(self) -> None:
        class Rule:
            rule_text = "never trust user input without validation"

        assert validate_rule_mandate(Rule()) is True

    def test_invalid_short(self) -> None:
        class Rule:
            rule_text = "always"

        assert validate_rule_mandate(Rule()) is False

    def test_invalid_not_imperative(self) -> None:
        class Rule:
            rule_text = "use parameterized queries for safety"

        assert validate_rule_mandate(Rule()) is False


class TestSemanticSimilarity:
    def test_identical(self) -> None:
        sim = semantic_similarity("hello world", "hello world")
        # Jaccard fallback: identical tokens => 1.0
        assert sim == 1.0

    def test_different(self) -> None:
        sim = semantic_similarity("cat dog", "quantum physics")
        assert sim < 0.5
