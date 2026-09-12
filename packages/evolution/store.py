"""Git-backed prompt store with branch and rollback support.

Extends the basic PromptStore with Git versioning:
- Each prompt version is a Git commit
- Branches track parallel evolution paths
- Rollback restores a previous version
- Full diff history via Git log
"""

from __future__ import annotations

import json
import logging
import subprocess
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)


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
    branch: str = "main"

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
            "branch": self.branch,
        }


class PromptStore:
    """Prompt store with Git-backed versioning.

    Each version is persisted as a JSON file AND committed to Git.
    Branches track parallel evolution paths.
    """

    MAIN_BRANCH = "main"

    def __init__(self, path: Path | None = None, base_prompt: str = ""):
        self.path = Path(path) if path else Path(".prompt_store")
        self.path.mkdir(parents=True, exist_ok=True)
        self._versions: list[PromptVersion] = []
        self._current_branch: str = self.MAIN_BRANCH
        self._branches: dict[str, int] = {}  # branch_name -> latest version number
        self._init_git()
        self._load()
        if not self._versions:
            v = PromptVersion(version=1, base_prompt=base_prompt, rules=[], branch=self.MAIN_BRANCH)
            self._commit(v)

    # ------------------------------------------------------------------
    # Git operations
    # ------------------------------------------------------------------

    def _init_git(self) -> None:
        """Initialize a Git repo in the store directory if needed."""
        if not (self.path / ".git").exists():
            self._git("init")
            self._git("config", "user.email", "coevolve@local")
            self._git("config", "user.name", "CoEvolve Store")
            # Write .gitignore to exclude nothing — we want full history
            (self.path / ".gitignore").write_text("")
            self._git("add", ".gitignore")
            self._git("commit", "-m", "init prompt store")

    def _git(self, *args: str) -> str:
        """Run a Git command in the store directory."""
        try:
            result = subprocess.run(
                ["git", *args],
                cwd=str(self.path),
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode != 0:
                logger.debug("git %s failed: %s", args[0], result.stderr.strip())
            return result.stdout.strip()
        except Exception as exc:
            logger.warning("git command failed: %s", exc)
            return ""

    def _git_commit_version(self, version: PromptVersion) -> str:
        """Commit a version file to Git and return the commit hash."""
        filename = f"v{version.version:04d}.json"
        self._git("add", filename)
        msg = f"v{version.version}: {version.commit_message or 'update'}"
        self._git("commit", "-m", msg, "--allow-empty")
        return self._git("rev-parse", "HEAD")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def current(self) -> PromptVersion:
        return self._versions[-1]

    def rules(self) -> list[PromptRule]:
        return list(self.current().rules)

    def add_rule(
        self,
        rule: PromptRule,
        commit_message: str = "distilled from failure trace",
    ) -> PromptVersion:
        """Append a rule and create a new version on the current branch."""
        version = self.current().version + 1
        new = PromptVersion(
            version=version,
            base_prompt=self.current().base_prompt,
            rules=self.current().rules + [rule],
            commit_message=commit_message,
            parent_version=self.current().version,
            branch=self._current_branch,
        )
        self._commit(new)
        return new

    def history(self, branch: str | None = None) -> list[dict]:
        """Return version history, optionally filtered by branch."""
        versions = self._versions
        if branch:
            versions = [v for v in versions if v.branch == branch]
        return [v.as_dict() for v in versions]

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

    # ------------------------------------------------------------------
    # Branch operations
    # ------------------------------------------------------------------

    def branches(self) -> list[str]:
        """List all branches."""
        return list(self._branches.keys())

    def create_branch(self, name: str, from_version: int | None = None) -> None:
        """Create a new branch from a specific version (or current)."""
        if name in self._branches:
            raise ValueError(f"branch '{name}' already exists")
        source = from_version if from_version is not None else self.current().version
        self._branches[name] = source
        logger.info("Created branch '%s' from version %d", name, source)

    def switch_branch(self, name: str) -> None:
        """Switch to a different branch."""
        if name not in self._branches:
            raise ValueError(f"branch '{name}' does not exist")
        self._current_branch = name

    def merge_branch(self, source_branch: str, target_branch: str | None = None) -> PromptVersion:
        """Merge rules from source branch into target (or current)."""
        target = target_branch or self._current_branch
        source_ver_num = self._branches.get(source_branch)
        target_ver_num = self._branches.get(target)
        if source_ver_num is None:
            raise ValueError(f"source branch '{source_branch}' not found")
        if target_ver_num is None:
            raise ValueError(f"target branch '{target}' not found")

        source_ver = self.get(source_ver_num)
        target_ver = self.get(target_ver_num)
        if not source_ver or not target_ver:
            raise ValueError("version not found for branch")

        # Merge: take all unique rules from both
        existing_texts = {r.rule_text for r in target_ver.rules}
        new_rules = list(target_ver.rules)
        for r in source_ver.rules:
            if r.rule_text not in existing_texts:
                new_rules.append(r)
                existing_texts.add(r.rule_text)

        version = self.current().version + 1
        merged = PromptVersion(
            version=version,
            base_prompt=target_ver.base_prompt,
            rules=new_rules,
            commit_message=f"merge '{source_branch}' into '{target}'",
            parent_version=self.current().version,
            branch=target,
        )
        self._commit(merged)
        self._branches[target] = version
        return merged

    # ------------------------------------------------------------------
    # Rollback
    # ------------------------------------------------------------------

    def rollback(self, to_version: int) -> PromptVersion:
        """Roll back to a previous version, creating a new version with the old state."""
        target = self.get(to_version)
        if not target:
            raise KeyError(f"version {to_version} not found")

        version = self.current().version + 1
        rolled = PromptVersion(
            version=version,
            base_prompt=target.base_prompt,
            rules=list(target.rules),
            commit_message=f"rollback to v{to_version}",
            parent_version=self.current().version,
            branch=self._current_branch,
        )
        self._commit(rolled)
        return rolled

    def git_log(self, limit: int = 20) -> list[dict]:
        """Return recent Git commits for the store."""
        raw = self._git("log", f"--max-count={limit}", "--format=%H|%s|%ai")
        commits: list[dict] = []
        for line in raw.splitlines():
            parts = line.split("|", 2)
            if len(parts) == 3:
                commits.append({
                    "hash": parts[0],
                    "message": parts[1],
                    "date": parts[2],
                })
        return commits

    def git_diff(self, v1: int, v2: int) -> str:
        """Return the raw Git diff between two version files."""
        f1 = f"v{v1:04d}.json"
        f2 = f"v{v2:04d}.json"
        return self._git("diff", f1, f2)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _commit(self, version: PromptVersion) -> None:
        self._versions.append(version)
        self._write(version)
        self._git_commit_version(version)
        self._branches[version.branch] = version.version

    def _write(self, version: PromptVersion) -> None:
        dest = self.path / f"v{version.version:04d}.json"
        dest.write_text(json.dumps(version.as_dict(), indent=2, default=str))

    def _load(self) -> None:
        for f in sorted(self.path.glob("v*.json")):
            raw = json.loads(f.read_text())
            rules = [PromptRule(**r) for r in raw.get("rules", [])]
            branch = raw.get("branch", self.MAIN_BRANCH)
            v = PromptVersion(
                version=raw["version"],
                base_prompt=raw["base_prompt"],
                rules=rules,
                commit_message=raw.get("commit_message", ""),
                parent_version=raw.get("parent_version"),
                created_at=raw.get("created_at", 0.0),
                branch=branch,
            )
            self._versions.append(v)
            self._branches[branch] = v.version
