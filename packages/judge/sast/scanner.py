"""Semgrep SAST integration.

Runs Semgrep over the developer's patch (or a repository checkout) with
vulnerability-specific rule packs and returns structured findings.
"""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

RULES_DIR = Path(__file__).resolve().parent / "semgrep_rules"


@dataclass
class SASTFinding:
    rule_id: str
    file: str
    line: int
    severity: str
    confidence: str
    message: str
    metadata: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "file": self.file,
            "line": self.line,
            "severity": self.severity,
            "confidence": self.confidence,
            "message": self.message,
        }


@dataclass
class SASTResult:
    findings: list[SASTFinding] = field(default_factory=list)

    @property
    def matched(self) -> bool:
        return len(self.findings) > 0

    def as_dict(self) -> dict:
        return {"rules_matched": [f.as_dict() for f in self.findings], "total_matches": len(self.findings)}


class SemgrepScanner:
    """Thin wrapper around the semgrep CLI."""

    def __init__(
        self,
        rules_dir: Path = RULES_DIR,
        timeout: int = 120,
        binary: str = "semgrep",
    ):
        self.rules_dir = Path(rules_dir)
        self.timeout = timeout
        self.binary = binary

    def scan_directory(self, target: Path, config: str | None = None) -> SASTResult:
        """Scan a directory with the bundled rules; return structured findings."""
        rules = config or str(self.rules_dir)
        cmd = [
            self.binary,
            "--config",
            rules,
            "--json",
            "--severity",
            "ERROR,WARNING",
            "--no-rewrite-rule-ids",
            str(target),
        ]
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=self.timeout, check=False
        )
        return self._parse(proc.stdout)

    def scan_patch(self, patch_text: str, syntax: str = "python") -> SASTResult:
        """Scan a code patch string directly (best-effort heuristic).

        Full patch scanning requires a checkout; this fallback greps rule
        patterns against the patch text for fast pre-screening.
        """
        findings: list[SASTFinding] = []
        for rule_file in sorted(self.rules_dir.glob("*.yml")):
            rule_id = rule_file.stem
            text = patch_text.lower()
            if self._rule_hits_patch(rule_file, text):
                findings.append(
                    SASTFinding(
                        rule_id=rule_id,
                        file="<patch>",
                        line=0,
                        severity="WARNING",
                        confidence="MEDIUM",
                        message="Candidate pattern matched in patch text (pre-screened)",
                    )
                )
        return SASTResult(findings=findings)

    def _rule_hits_patch(self, rule_file: Path, text: str) -> bool:
        """Very small heuristic: keywords from rule metadata vs patch text."""
        keywords = {
            "sql": ("execute", "cursor", "query", "select"),
            "path-traversal": ("open(", "read_file", "join", "getcwd"),
            "ssrf": ("requests.", "urlopen", "http.get", "fetch("),
            "command-injection": ("os.system", "subprocess", "shell=True", "exec("),
            "xss": ("mark_safe", "innerhtml", "render_template_string"),
            "deserialization": ("pickle", "yaml.load", "readobject"),
            "ssti": ("template(", "from_string", "jinja"),
            "xxe": ("etree", "lxml", "parsedocumentbuilderfactory"),
        }
        matched = [kw for kw in keywords.get(rule_file.stem, ()) if kw in text]
        return bool(matched)

    @staticmethod
    def _parse(stdout: str) -> SASTResult:
        if not stdout.strip():
            return SASTResult()
        try:
            payload = json.loads(stdout)
        except json.JSONDecodeError:
            return SASTResult()
        findings = []
        for result in payload.get("results", []):
            extra = result.get("extra", {})
            findings.append(
                SASTFinding(
                    rule_id=result.get("check_id", ""),
                    file=result.get("path", ""),
                    line=int(result.get("start", {}).get("line", 0)),
                    severity=extra.get("severity", "UNKNOWN"),
                    confidence=extra.get("metadata", {}).get("confidence", "UNKNOWN"),
                    message=extra.get("message", ""),
                    metadata=extra.get("metadata", {}),
                )
            )
        return SASTResult(findings=findings)