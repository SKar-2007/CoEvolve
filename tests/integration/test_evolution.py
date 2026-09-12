"""Integration tests for the prompt evolution store."""

from __future__ import annotations

import pytest
from packages.evolution.store import PromptRule, PromptStore


@pytest.fixture
def store(tmp_path):
    return PromptStore(path=tmp_path / "prompt_store", base_prompt="You are a developer.")


class TestPromptStore:
    def test_initial_version(self, store):
        v = store.current()
        assert v.version == 1
        assert len(v.rules) == 0
        assert "developer" in v.full_prompt()

    def test_add_rule(self, store):
        rule = PromptRule(
            rule_text="ALWAYS use parameterized queries",
            vulnerability_class="SQLi",
        )
        v = store.add_rule(rule)
        assert v.version == 2
        assert len(v.rules) == 1
        assert "ALWAYS use parameterized queries" in v.full_prompt()

    def test_add_multiple_rules(self, store):
        for i in range(3):
            rule = PromptRule(
                rule_text=f"Rule {i}: NEVER do thing {i}",
                vulnerability_class="SQLi",
            )
            store.add_rule(rule)
        v = store.current()
        assert v.version == 4
        assert len(v.rules) == 3

    def test_history(self, store):
        store.add_rule(PromptRule(rule_text="Rule 1", vulnerability_class="SQLi"))
        history = store.history()
        assert len(history) == 2  # v1 + v2
        assert history[0]["version"] == 1
        assert history[1]["version"] == 2

    def test_get_version(self, store):
        store.add_rule(PromptRule(rule_text="Rule 1", vulnerability_class="XSS"))
        v1 = store.get(1)
        v2 = store.get(2)
        assert v1 is not None
        assert v2 is not None
        assert len(v1.rules) == 0
        assert len(v2.rules) == 1

    def test_get_nonexistent(self, store):
        assert store.get(999) is None

    def test_diff(self, store):
        store.add_rule(PromptRule(rule_text="Rule A", vulnerability_class="SQLi"))
        store.add_rule(PromptRule(rule_text="Rule B", vulnerability_class="XSS"))
        d = store.diff(1, 3)
        assert d["from"] == 1
        assert d["to"] == 3
        assert len(d["added"]) == 2
        assert len(d["removed"]) == 0

    def test_diff_invalid_version(self, store):
        with pytest.raises(KeyError):
            store.diff(1, 999)

    def test_full_prompt_composition(self, store):
        store.add_rule(PromptRule(rule_text="NEVER interpolate SQL", vulnerability_class="SQLi"))
        full = store.current().full_prompt()
        assert "You are a developer" in full
        assert "EVOLVED SECURITY RULES" in full
        assert "NEVER interpolate SQL" in full

    def test_persistence(self, tmp_path):
        path = tmp_path / "persist_store"
        store1 = PromptStore(path=path, base_prompt="Base prompt")
        store1.add_rule(PromptRule(rule_text="Rule 1", vulnerability_class="SQLi"))

        # Reload from disk
        store2 = PromptStore(path=path, base_prompt="Base prompt")
        assert store2.current().version == 2
        assert len(store2.current().rules) == 1
        assert store2.current().rules[0].rule_text == "Rule 1"
