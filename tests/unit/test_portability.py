"""Tests for rule portability (export/import)."""

from __future__ import annotations

from pathlib import Path

import pytest
from packages.evolution.portability import (
    RulePackage,
    diff_packages,
    export_rules,
    import_rules,
    load_package,
    save_package,
)
from packages.evolution.store import PromptRule, PromptStore


@pytest.fixture
def store_with_rules(tmp_path: Path) -> PromptStore:
    """Create a PromptStore with some rules."""
    store = PromptStore(path=tmp_path / "store")
    rules = [
        PromptRule(rule_text="NEVER use eval()", vulnerability_class="Deserialization"),
        PromptRule(rule_text="ALWAYS use parameterized queries", vulnerability_class="SQLi"),
        PromptRule(rule_text="ALWAYS sanitize path inputs", vulnerability_class="PathTraversal"),
    ]
    for r in rules:
        store.add_rule(r)
    return store


@pytest.fixture
def sample_package() -> RulePackage:
    """Create a sample RulePackage."""
    rules = [
        PromptRule(rule_text="ALWAYS validate URLs", vulnerability_class="SSRF"),
        PromptRule(
            rule_text="NEVER redirect to untrusted URLs", vulnerability_class="OpenRedirect"
        ),
    ]
    return RulePackage(
        name="test-package",
        description="Test rules",
        version="1.0.0",
        author="tester",
        rules=rules,
        tags=["test", "security"],
    )


class TestRulePackage:
    def test_as_dict(self, sample_package: RulePackage):
        d = sample_package.as_dict()
        assert d["name"] == "test-package"
        assert len(d["rules"]) == 2
        assert d["rules"][0]["rule_text"] == "ALWAYS validate URLs"

    def test_from_dict(self, sample_package: RulePackage):
        d = sample_package.as_dict()
        restored = RulePackage.from_dict(d)
        assert restored.name == sample_package.name
        assert len(restored.rules) == 2
        assert restored.rules[1].vulnerability_class == "OpenRedirect"

    def test_roundtrip(self, sample_package: RulePackage):
        d = sample_package.as_dict()
        restored = RulePackage.from_dict(d)
        assert d == restored.as_dict()


class TestExportImport:
    def test_export_rules(self, store_with_rules: PromptStore):
        pkg = export_rules(store_with_rules, name="test-export")
        assert pkg.name == "test-export"
        assert len(pkg.rules) == 3
        assert pkg.source_version > 0

    def test_import_merge(self, tmp_path: Path, sample_package: RulePackage):
        store = PromptStore(path=tmp_path / "store")
        # Import first package
        count = import_rules(store, sample_package)
        assert count == 2
        assert len(store.rules()) == 2

        # Import same package again (merge should skip duplicates)
        count = import_rules(store, sample_package, merge=True)
        assert count == 0
        assert len(store.rules()) == 2

    def test_import_replace(self, tmp_path: Path, sample_package: RulePackage):
        store = PromptStore(path=tmp_path / "store")
        # Add some existing rules
        store.add_rule(PromptRule(rule_text="OLD rule", vulnerability_class="XSS"))
        assert len(store.rules()) == 1

        # Import with merge=False
        count = import_rules(store, sample_package, merge=False)
        assert count == 2
        # New rules added, old one still there (import adds, doesn't remove)
        assert len(store.rules()) == 3


class TestSaveLoad:
    def test_save_load_roundtrip(self, sample_package: RulePackage, tmp_path: Path):
        path = save_package(sample_package, tmp_path / "test.json")
        assert path.exists()

        loaded = load_package(path)
        assert loaded.name == sample_package.name
        assert len(loaded.rules) == 2
        assert loaded.package_id == sample_package.package_id

    def test_save_creates_parent_dirs(self, sample_package: RulePackage, tmp_path: Path):
        path = save_package(sample_package, tmp_path / "sub" / "dir" / "rules.json")
        assert path.exists()


class TestDiff:
    def test_diff_packages(self):
        pkg1 = RulePackage(
            name="base",
            rules=[
                PromptRule(rule_text="rule A", vulnerability_class="SQLi"),
                PromptRule(rule_text="rule B", vulnerability_class="XSS"),
            ],
        )
        pkg2 = RulePackage(
            name="target",
            rules=[
                PromptRule(rule_text="rule B", vulnerability_class="XSS"),
                PromptRule(rule_text="rule C", vulnerability_class="SSRF"),
            ],
        )
        diff = diff_packages(pkg1, pkg2)
        assert diff["added"] == ["rule C"]
        assert diff["removed"] == ["rule A"]
        assert diff["unchanged"] == ["rule B"]

    def test_diff_empty(self):
        pkg1 = RulePackage(name="a", rules=[])
        pkg2 = RulePackage(name="b", rules=[])
        diff = diff_packages(pkg1, pkg2)
        assert diff["added"] == []
        assert diff["removed"] == []
        assert diff["unchanged"] == []
