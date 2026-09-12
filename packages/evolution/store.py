"""Versioned store for the evolving developer system prompt P_D(k).

Prompt evolution follows blueprint.md §3.3:

    P_D(k+1) = P_D(k) U {rho_k}   when J = 1
    P_D(k+1) = P_D(k)             when J = 0

Rules are appended monotonically; the store keeps full history and diffs.
"""

from __future__ import annotations

import json
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path


@dataclass
class PromptRule:
    rule_text: str
    vulnerability_class: str
    source_pattern: str = ""
    recommended_fix: str = ""
    source_trace_id: str = ""
    rule_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    version: int = 1

    def as_dict(self) -> dict:
        return asdict(self)


@dataclass
class PromptVersion:
    version: int
    base_prompt: str
    rules: list[PromptRule]
    commit_message: str = ""
    parent_version: int | None = None
    created_at: float = field(default_factory=time.time)

    def full_prompt(self) -> str:
        """Compose the effective system prompt P_D for this version."""
        if not self.rules:
            return self.base_prompt
        block = "\n\nEVOLVED SECURITY RULES (must be followed):\n"
        block += "\n".join(f"- {r.rule_text}" for r in self.rules)
        return self.base_prompt + block

    def as_dict(self) -> dict:
        return {
            "version": self.version,
            "base_prompt": self.base_prompt,
            "rules": [r.as_dict() for r in self.rules],
            "commit_message": self.commit_message,
            "parent_version": self.parent_version,
            "created_at": self.created_at,
        }


class PromptStore:
    """Append-only, on-disk prompt evolution store."""

    def __init__(self, path: Path | None = None, base_prompt: str = ""):
        self.path = Path(path) if path else Path(".prompt_store")
        self.path.mkdir(parents=True, exist_ok=True)
        self._versions: list[PromptVersion] = []
        self._load()
        if not self._versions:
            self._commit(PromptVersion(version=1, base_prompt=base_prompt, rules=[]))

    def current(self) -> PromptVersion:
        return self._versions[-1]

    def rules(self) -> list[PromptRule]:
        return list(self.current().rules)

    def add_rule(
        self,
        rule: PromptRule,
        commit_message: str = "distilled from failure trace",
    ) -> PromptVersion:
        """Append a rule and create a new version."""
        version = self.current().version + 1
        new = PromptVersion(
            version=version,
            base_prompt=self.current().base_prompt,
            rules=self.current().rules + [rule],
            commit_message=commit_message,
            parent_version=self.current().version,
        )
        self._commit(new)
        return new

    def history(self) -> list[dict]:
        return [v.as_dict() for v in self._versions]

    def get(self, version: int) -> PromptVersion | None:
        for v in self._versions:
            if v.version == version:
                return v
        return None

    def diff(self, v1: int, v2: int) -> dict:
        """Return added/removed rules between two versions."""
        a = self.get(v1)
        b = self.get(v2)
        if a is None or b is None:
            raise KeyError(f"unknown version {v1 if a is None else v2}")
        a_text = {r.rule_text for r in a.rules}
        b_text = {r.rule_text for r in b.rules}
        return {
            "from": v1,
            "to": v2,
            "added": sorted(b_text - a_text),
            "removed": sorted(a_text - b_text),
        }

    def _commit(self, version: PromptVersion) -> None:
        self._versions.append(version)
        self._write(version)

    def _write(self, version: PromptVersion) -> None:
        dest = self.path / f"v{version.version:04d}.json"
        dest.write_text(json.dumps(version.as_dict(), indent=2, default=str))

    def _load(self) -> None:
        for f in sorted(self.path.glob("v*.json")):
            raw = json.loads(f.read_text())
            rules = [PromptRule(**r) for r in raw.get("rules", [])]
            self._versions.append(
                PromptVersion(
                    version=raw["version"],
                    base_prompt=raw["base_prompt"],
                    rules=rules,
                    commit_message=raw.get("commit_message", ""),
                    parent_version=raw.get("parent_version"),
                    created_at=raw.get("created_at", 0.0),
                )
            )
