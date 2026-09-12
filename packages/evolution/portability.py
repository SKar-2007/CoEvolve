"""Rule portability - export/import trained rules as JSON packages.

A rule package is a self-contained JSON file containing:
- Metadata (name, version, description, created_at)
- Rules (all distilled rules with full provenance)
- Base prompt (optional)
- Git history summary (optional)

Usage:
    from packages.evolution.portability import export_rules, import_rules

    # Export
    pkg = export_rules(store, name="my-rules", description="SQLi rules v2")
    save_package(pkg, Path("rules.json"))

    # Import
    pkg = load_package(Path("rules.json"))
    count = import_rules(store, pkg)
"""

from __future__ import annotations

import json
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path

from .store import PromptRule, PromptStore


@dataclass
class RulePackage:
    """A portable, self-contained rule package."""

    package_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = "unnamed"
    description: str = ""
    version: str = "1.0.0"
    created_at: float = field(default_factory=time.time)
    author: str = ""

    rules: list[PromptRule] = field(default_factory=list)
    base_prompt: str = ""
    source_version: int = 0
    source_branch: str = "main"

    tags: list[str] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {
            "package_id": self.package_id,
            "name": self.name,
            "description": self.description,
            "version": self.version,
            "created_at": self.created_at,
            "author": self.author,
            "rules": [asdict(r) for r in self.rules],
            "base_prompt": self.base_prompt,
            "source_version": self.source_version,
            "source_branch": self.source_branch,
            "tags": self.tags,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict) -> RulePackage:
        rules = []
        for r in data.get("rules", []):
            rules.append(
                PromptRule(
                    rule_text=r.get("rule_text", ""),
                    vulnerability_class=r.get("vulnerability_class", ""),
                    source_pattern=r.get("source_pattern", ""),
                    recommended_fix=r.get("recommended_fix", ""),
                    source_trace_id=r.get("source_trace_id", ""),
                    rule_id=r.get("rule_id", str(uuid.uuid4())),
                    version=r.get("version", 1),
                )
            )
        return cls(
            package_id=data.get("package_id", str(uuid.uuid4())),
            name=data.get("name", "unnamed"),
            description=data.get("description", ""),
            version=data.get("version", "1.0.0"),
            created_at=data.get("created_at", time.time()),
            author=data.get("author", ""),
            rules=rules,
            base_prompt=data.get("base_prompt", ""),
            source_version=data.get("source_version", 0),
            source_branch=data.get("source_branch", "main"),
            tags=data.get("tags", []),
            metadata=data.get("metadata", {}),
        )


def export_rules(
    store: PromptStore,
    name: str = "exported-rules",
    description: str = "",
    version: str = "1.0.0",
    author: str = "",
    tags: list[str] | None = None,
) -> RulePackage:
    """Export all rules from a PromptStore into a portable package."""
    current = store.current()
    return RulePackage(
        name=name,
        description=description,
        version=version,
        author=author,
        rules=list(current.rules),
        base_prompt=current.base_prompt,
        source_version=current.version,
        source_branch=current.branch,
        tags=tags or [],
    )


def import_rules(
    store: PromptStore,
    package: RulePackage,
    merge: bool = True,
) -> int:
    """Import rules from a package into a PromptStore.

    Args:
        store: Target PromptStore to import into.
        package: The RulePackage to import from.
        merge: If True, add rules that don't already exist (by rule_text).
               If False, replace all rules with the package rules.

    Returns:
        Number of rules imported.
    """
    imported = 0
    existing_texts = {r.rule_text for r in store.rules()}

    for rule in package.rules:
        if merge and rule.rule_text in existing_texts:
            continue
        store.add_rule(rule)
        imported += 1

    return imported


def save_package(package: RulePackage, path: Path) -> Path:
    """Save a RulePackage to a JSON file."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(package.as_dict(), indent=2, default=str))
    return path


def load_package(path: Path) -> RulePackage:
    """Load a RulePackage from a JSON file."""
    path = Path(path)
    data = json.loads(path.read_text())
    return RulePackage.from_dict(data)


def diff_packages(base: RulePackage, target: RulePackage) -> dict[str, list[str]]:
    """Compare two packages, returning added/removed rule texts."""
    base_texts = {r.rule_text for r in base.rules}
    target_texts = {r.rule_text for r in target.rules}
    return {
        "added": sorted(target_texts - base_texts),
        "removed": sorted(base_texts - target_texts),
        "unchanged": sorted(base_texts & target_texts),
    }
