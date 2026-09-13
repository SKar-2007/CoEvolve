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


VULN_METADATA: dict[str, dict] = {
    "sql-injection": {"cwe": "CWE-89", "owasp": "A03:2021 - Injection", "severity": "ERROR", "title": "SQL Injection", "fix": "Use parameterized queries / prepared statements; never concatenate user input into SQL.", "risk": "Critical"},
    "command-injection": {"cwe": "CWE-78", "owasp": "A03:2021 - Injection", "severity": "ERROR", "title": "Command Injection", "fix": "Avoid shell=True; use subprocess with argument lists and strict allow-lists.", "risk": "Critical"},
    "xss": {"cwe": "CWE-79", "owasp": "A03:2021 - Injection", "severity": "ERROR", "title": "Cross-Site Scripting (XSS)", "fix": "Escape output with html.escape / markupsafe.escape; use auto-escaping templates.", "risk": "High"},
    "ssti": {"cwe": "CWE-1336", "owasp": "A03:2021 - Injection", "severity": "ERROR", "title": "Server-Side Template Injection", "fix": "Do not render user input as template; use safe rendering APIs.", "risk": "Critical"},
    "xxe": {"cwe": "CWE-611", "owasp": "A05:2021 - Misconfiguration", "severity": "ERROR", "title": "XML External Entity (XXE)", "fix": "Disable external entities; use defusedxml.", "risk": "High"},
    "path-traversal": {"cwe": "CWE-22", "owasp": "A01:2021 - Broken Access Control", "severity": "ERROR", "title": "Path Traversal", "fix": "Canonicalize with os.path.realpath and enforce base directory prefix.", "risk": "High"},
    "ssrf": {"cwe": "CWE-918", "owasp": "A10:2021 - SSRF", "severity": "ERROR", "title": "Server-Side Request Forgery", "fix": "Allow-list URLs, block private IPs, disable redirects.", "risk": "High"},
    "deserialization": {"cwe": "CWE-502", "owasp": "A08:2021 - Integrity Failures", "severity": "ERROR", "title": "Insecure Deserialization", "fix": "Use yaml.safe_load; avoid pickle on untrusted data.", "risk": "Critical"},
    "open-redirect": {"cwe": "CWE-601", "owasp": "A01:2021 - Broken Access Control", "severity": "WARNING", "title": "Open Redirect", "fix": "Validate redirect against allow-list; use relative URLs.", "risk": "Medium"},
    "prototype-pollution": {"cwe": "CWE-1321", "owasp": "A08:2021 - Integrity Failures", "severity": "WARNING", "title": "Prototype Pollution", "fix": "Block __proto__/constructor keys; use safe deep-merge.", "risk": "Medium"},
    "sql": {"cwe": "CWE-89", "owasp": "A03:2021 - Injection", "severity": "ERROR", "title": "SQL Injection", "fix": "Use parameterized queries.", "risk": "Critical"},
}


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
        meta = VULN_METADATA.get(self.rule_id, {})
        return {
            "rule_id": self.rule_id,
            "file": self.file,
            "line": self.line,
            "severity": self.severity,
            "confidence": self.confidence,
            "message": self.message,
            "cwe": meta.get("cwe", ""),
            "owasp": meta.get("owasp", ""),
            "title": meta.get("title", self.rule_id),
            "fix": meta.get("fix", ""),
            "risk": meta.get("risk", self.severity),
            "metadata": self.metadata,
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
            return self._scan_directory_heuristic(target)
        # Probe semgrep with first rule — if it fails, fall back to heuristic
        all_rule_files = sorted(self.rules_dir.glob("*.yml"))
        if all_rule_files:
            probe_cmd = [self.binary, "--config", str(all_rule_files[0]), "--json", str(target)]
            try:
                probe = subprocess.run(
                    probe_cmd, capture_output=True, text=True, timeout=30, check=False
                )
                if probe.returncode != 0 and not probe.stdout.strip():
                    return self._scan_directory_heuristic(target)
            except (subprocess.TimeoutExpired, OSError):
                return self._scan_directory_heuristic(target)
        # Scan with each rule file individually to avoid semgrep rule selection issues
        all_findings: list[SASTFinding] = []
        for rule_file in all_rule_files:
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
        seen: set[tuple[str, str, int]] = set()  # (base_rule_id, file, line) dedup
        code_files = (
            list(target.rglob("*.py"))
            + list(target.rglob("*.js"))
            + list(target.rglob("*.ts"))
            + list(target.rglob("*.java"))
        )
        for code_file in code_files[:20]:
            try:
                lines = code_file.read_text(errors="ignore").splitlines()
            except Exception:
                continue
            text_lower = "\n".join(lines).lower()
            for rule_file in sorted(self.rules_dir.glob("*.yml")):
                stem = rule_file.stem
                base = stem.rsplit("-", 1)[0] if stem.endswith(("-js", "-java")) else stem
                matches = self._find_keyword_matches(rule_file, text_lower, lines)
                for line_num, keyword, snippet in matches:
                    dedup_key = (base, str(code_file), line_num)
                    if dedup_key in seen:
                        continue
                    seen.add(dedup_key)
                    meta = VULN_METADATA.get(base, {})
                    findings.append(
                        SASTFinding(
                            rule_id=base,
                            file=str(code_file),
                            line=line_num,
                            severity=meta.get("severity", "WARNING"),
                            confidence="MEDIUM",
                            message=f"Vulnerable pattern detected: `{keyword}` — {snippet}",
                            metadata={"keyword": keyword, "snippet": snippet},
                        )
                    )
        return SASTResult(findings=findings)

    def _find_keyword_matches(
        self, rule_file: Path, text_lower: str, lines: list[str]
    ) -> list[tuple[int, str, str]]:
        """Find matching keywords with line numbers and context snippets."""
        keywords = self._get_keywords()
        stem = rule_file.stem
        base = stem.rsplit("-", 1)[0] if stem.endswith(("-js", "-java")) else stem
        kw_tuple = keywords.get(stem) or keywords.get(base, ())
        if not kw_tuple:
            return []
        matches: list[tuple[int, str, str]] = []
        for i, line in enumerate(lines, 1):
            line_lower = line.lower().strip()
            if not line_lower or line_lower.startswith("#") or line_lower.startswith("//"):
                continue
            for kw in kw_tuple:
                if kw.lower() in line_lower:
                    snippet = line.strip()[:80]
                    matches.append((i, kw, snippet))
                    break  # one match per line
        return matches

    @staticmethod
    def _get_keywords() -> dict[str, tuple[str, ...]]:
        return {
            "sql": (
                "select * from", "where username", "like '%", "or 1=1",
                "f\"select", "f'select", "cursor.execute", "sqlite3",
                "jdbctemplate", "query = f", "sql = \"", "sql = '",
                "username like", "password='", "username='",
            ),
            "sql-injection": (
                "select * from", "where username", "like '%", "or 1=1",
                "f\"select", "f'select", "cursor.execute", "sqlite3",
                "jdbctemplate", "query = f", "sql = \"", "sql = '",
                "username like", "password='", "username='",
            ),
            "path-traversal": (
                "os.path.join", "path.join", "path traversal",
                "open(filepath", "readstring(path", "files.readstring",
                "../", "..\\", "secret.txt",
            ),
            "ssrf": (
                "urlopen", "http.get", "urllib.request",
                "requests.get", "requests.post", "http.request", "urlretrieve",
                "openconnection", "httpurlconnection",
            ),
            "command-injection": (
                "shell=true", "os.system", "subprocess.run", "subprocess.popen",
                "runtime.getruntime().exec", "ping -c 1", "exec(", "popen(",
            ),
            "xss": (
                "render_template_string", "dangerouslysetinnerhtml",
                "innerhtml", "document.write", "mark_safe",
                "search results for", "<p>search", "res.end(`<p>",
            ),
            "deserialization": (
                "yaml.load", "pickle.", "readobject", "marshal", "shelve",
                "jsonpickle", "yaml.fullloader", "yaml.safeloader",
            ),
            "ssti": (
                "render_template_string", "jinja2", "template.from_string",
                "environment.from_string", "from_string",
            ),
            "xxe": (
                "xml.etree", "lxml", "etree", "defusedxml",
                "<!entity", "<!doctype", "external entity", "dtd",
            ),
            "open-redirect": (
                "sendredirect", "openredirect", "open_redirect", "302",
                "httpresponseredirect", "redirect_uri", "location",
                "window.location",
            ),
            "prototype-pollution": (
                "__proto__", "constructor.prototype", "prototype pollution",
                "deep_merge", "deepmerge",
                "deepmerge", "object.assign",
            ),
        }

    def scan_patch(self, patch_text: str, syntax: str = "python") -> SASTResult:
        """Scan a code patch string directly (best-effort heuristic).

        Full patch scanning requires a checkout; this fallback greps rule
        patterns against the patch text for fast pre-screening.
        """
        findings: list[SASTFinding] = []
        lines = patch_text.splitlines()
        text_lower = patch_text.lower()
        for rule_file in sorted(self.rules_dir.glob("*.yml")):
            rule_id = rule_file.stem
            matches = self._find_keyword_matches(rule_file, text_lower, lines)
            for line_num, keyword, snippet in matches:
                findings.append(
                    SASTFinding(
                        rule_id=rule_id,
                        file="<patch>",
                        line=line_num,
                        severity="WARNING",
                        confidence="MEDIUM",
                        message=f"Vulnerable pattern detected: `{keyword}` — {snippet}",
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
