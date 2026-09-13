"""Semgrep SAST integration.

Runs Semgrep over the developer's patch (or a repository checkout) with
vulnerability-specific rule packs and returns structured findings.
"""

from __future__ import annotations

import json
import shutil
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
        return {
            "rules_matched": [f.as_dict() for f in self.findings],
            "total_matches": len(self.findings),
        }


class SemgrepScanner:
    """Thin wrapper around the semgrep CLI."""

    def __init__(
        self,
        rules_dir: Path = RULES_DIR,
        timeout: int = 120,
        binary: str | None = None,
    ):
        self.rules_dir = Path(rules_dir)
        self.timeout = timeout
        self.binary = binary or self._find_semgrep()

    @staticmethod
    def _find_semgrep() -> str:
        found = shutil.which("semgrep")
        if found:
            return found
        import os
        candidates = [
            os.path.expanduser("~/Library/Python/3.9/bin/semgrep"),
            "/usr/local/bin/semgrep",
            "/usr/bin/semgrep",
        ]
        for c in candidates:
            if os.path.isfile(c) and os.access(c, os.X_OK):
                return c
        return "semgrep"

    def scan_directory(self, target: Path, config: str | None = None) -> SASTResult:
        """Scan a directory with the bundled rules; return structured findings."""
        if not shutil.which(self.binary) and not Path(self.binary).is_file():
            # Semgrep not available — fall back to keyword heuristic on all files
            return self._scan_directory_heuristic(target)
        # Scan with each rule file individually to avoid semgrep rule selection issues
        all_findings: list[SASTFinding] = []
        for rule_file in sorted(self.rules_dir.glob("*.yml")):
            # Skip Java/JS rules for Python-only targets
            stem = rule_file.stem
            if stem.endswith("-java") or stem.endswith("-js"):
                continue
            cmd = [
                self.binary,
                "--config",
                str(rule_file),
                "--json",
                str(target),
            ]
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=self.timeout, check=False
            )
            result = self._parse(proc.stdout)
            all_findings.extend(result.findings)
        return SASTResult(findings=all_findings)

    def _scan_directory_heuristic(self, target: Path) -> SASTResult:
        """Keyword-based scan of all files in a directory (no semgrep needed)."""
        findings: list[SASTFinding] = []
        py_files = list(target.rglob("*.py"))
        # Limit to 10 files max to avoid timeout on free tier
        for code_file in py_files[:10]:
            try:
                text = code_file.read_text(errors="ignore").lower()
            except Exception:
                continue
            for rule_file in sorted(self.rules_dir.glob("*.yml")):
                stem = rule_file.stem
                if stem.endswith("-java") or stem.endswith("-js"):
                    continue
                if self._rule_hits_patch(rule_file, text):
                    findings.append(
                        SASTFinding(
                            rule_id=stem,
                            file=str(code_file),
                            line=0,
                            severity="WARNING",
                            confidence="MEDIUM",
                            message="Keyword pattern matched in source file (heuristic scan)",
                        )
                    )
                    break  # One finding per file is enough
        return SASTResult(findings=findings)

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
        """Heuristic: broad keyword/pattern matching for vulnerability detection."""
        keywords = {
            "sql": ("execute", "cursor", "query", "select", "insert", "update", "delete",
                    "where", "from", "database", "db.", "raw_sql", "text(", "sql",
                    "connection", "commit", "fetchone", "fetchall"),
            "sql-injection": ("execute", "cursor", "query", "select", "insert", "update",
                              "delete", "where", "from", "database", "db.", "raw_sql",
                              "text(", "sql", "connection", "commit", "fetchone", "fetchall"),
            "path-traversal": ("open(", "read_file", "join", "getcwd", "path.",
                               "os.path", "read_bytes", "read_text", "write(",
                               "file_path", "filename", "../", "..\\"),
            "ssrf": ("requests.", "urlopen", "http.get", "fetch(", "http.request",
                     "urlretrieve", "urllib", "httplib", "aiohttp", "httpx",
                     "requests.get", "requests.post", "webbrowser"),
            "command-injection": ("os.system", "subprocess", "shell=True", "exec(",
                                  "eval(", "os.popen", "commands.getoutput",
                                  "commands.getstatusoutput", "shell=False",
                                  "popen", "system("),
            "xss": ("mark_safe", "innerhtml", "render_template_string", "res.send",
                    "dangerouslysetinnerhtml", "document.write", "innerHTML",
                    "render_template", "jinja2", "template", "markup",
                    "escape(", "html.escape", "bleach.clean"),
            "deserialization": ("pickle", "yaml.load", "readobject", "eval(",
                                "marshal", "shelve", "jsonpickle", "serialize",
                                "deserialize", "loads(", "unpickle", "yaml.safe_load",
                                "json.loads", "xmltodict"),
            "ssti": ("template(", "from_string", "jinja", "render(",
                     "template.render", "template.from_string", "jinja2",
                     "environment", "environment.from_string",
                     "render_template_string", "template_string"),
            "xxe": ("etree", "lxml", "parsedocumentbuilderfactory", "domparser",
                    "xml.etree", "xml.dom", "xml.sax", "defusedxml",
                    "xmlrpc", "dtd", "entity", "external entity",
                    "parseString", "parse("),
            "open-redirect": ("redirect", "sendredirect", "redirect(",
                              "location.href", "window.location", "302",
                              " HttpResponseRedirect", "redirect_uri"),
            "prototype-pollution": ("__proto__", "constructor", "merge(",
                                    "assign", "extend", "deepmerge",
                                    "object.assign", "hasownproperty",
                                    "prototype", "proto"),
        }
        stem = rule_file.stem
        # Strip language suffix (-js, -java) for keyword lookup
        base = stem.rsplit("-", 1)[0] if stem.endswith(("-js", "-java")) else stem
        kw_tuple = keywords.get(stem) or keywords.get(base, ())
        matched = [kw for kw in kw_tuple if kw in text]
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
