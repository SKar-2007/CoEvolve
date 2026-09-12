"""Attacker Agent - adversarial task generator with rich context."""

from __future__ import annotations

import json
import random
import re
from typing import Any

from pydantic import BaseModel, Field

from ..llm import LLMClient, ModelConfig

VULNERABILITY_CLASSES = [
    "SQLi",
    "PathTraversal",
    "CommandInjection",
    "XSS",
    "SSRF",
    "Deserialization",
    "SSTI",
    "XXE",
    "OpenRedirect",
    "PrototypePollution",
]

TIER_INSTRUCTIONS = {
    1: "Single obvious bug in a single line. No input validation needed. Trivial fix.",
    2: "One obvious vulnerability with minimal surrounding code. Clearly visible pattern.",
    3: "Standard textbook vulnerability with some surrounding context to read.",
    4: "Vulnerability hidden among multiple code paths; requires reading 2-3 functions.",
    5: "Indirect vulnerability via indirect object reference or implicit trust boundary.",
    6: "Multi-function interaction where trust is propagated across module boundaries.",
    7: "Vulnerability requires chaining two code paths; subtle type confusion or race.",
    8: "Vulnerability in a callback or async path; easy to miss during code review.",
    9: "Novel attack vector: prototype pollution, deserialization gadget chain, or SSTI with filters.",
    10: "Expert-level adversarial edge case requiring deep language runtime knowledge.",
}

LANG_TEMPLATES = {
    "python": {
        "extensions": [".py"],
        "frameworks": ["Flask", "Django", "FastAPI"],
        "imports": ["import os", "import json", "from flask import request, jsonify"],
    },
    "javascript": {
        "extensions": [".js", ".ts"],
        "frameworks": ["Express", "Koa", "Next.js"],
        "imports": ["const express = require('express')", "const fs = require('fs')"],
    },
    "java": {
        "extensions": [".java"],
        "frameworks": ["Spring Boot", "Jakarta EE"],
        "imports": ["import java.sql.*", "import javax.servlet.*"],
    },
}

# Per-class attack techniques that the attacker should use to create subtle traps.
ATTACK_TECHNIQUES = {
    "SQLi": [
        "Use string formatting (f-strings, .format(), +) in SQL queries instead of parameterized queries",
        "Hide the injection in a secondary query triggered by error handling or logging",
        "Use double encoding or unicode tricks to bypass input filters",
        "Embed injection in a subquery or JOIN clause",
        "Use CASE-based blind injection that changes query logic",
        "Exploit ORDER BY or GROUP BY clauses with injection",
        "Use stored procedures that internally concatenate strings",
    ],
    "PathTraversal": [
        "Use os.path.join() with user-controlled input (path traversal still works)",
        "Bypass basic sanitization by using double-encoded sequences (%252e%252e)",
        "Exploit symlink following with user-created symlinks",
        "Use path concatenation in file download endpoints without canonicalization",
        "Bypass allowlist by using null bytes or extension tricks",
        "Exploit zip/tar extraction with ../ in archive entries",
        "Use glob patterns that expand to traverse directories",
    ],
    "CommandInjection": [
        "Pass user input to os.system(), subprocess.call(shell=True), or eval()",
        "Use string formatting to build shell commands: f'ping {host}'",
        "Exploit pipe operators: user input contains '; cat /etc/passwd'",
        "Inject through environment variables that are used in shell commands",
        "Use backtick execution in shell-interpolated strings",
        "Chain commands via && or || operators in user input",
        "Exploit command substitution: $(command) or `command`",
    ],
    "XSS": [
        "Reflect user input directly in HTML response without escaping",
        "Use event handlers: <img src=x onerror=alert(1)>",
        "Inject in JavaScript context: user input inside <script> tags",
        "Bypass basic filters using case variation: <ScRiPt>",
        "Use SVG onload handlers for stored XSS",
        "Exploit template literals in JavaScript: ${alert(1)}",
        "Inject through CSS expressions or url() values",
    ],
    "SSRF": [
        "Fetch user-provided URLs without validating against internal networks",
        "Bypass URL validation using DNS rebinding or IP encoding",
        "Use redirect chains to access internal services",
        "Exploit URL parsing differences: http://evil.com@internal-host",
        "Use IPv6 addresses: http://[::1]/ or http://[0:0:0:0::1]/",
        "Bypass allowlist by registering domains that resolve to internal IPs",
        "Exploit URL scheme confusion: file:///etc/passwd, gopher://",
    ],
    "Deserialization": [
        "Use pickle.loads() or yaml.load() on untrusted data",
        "Deserialize JSON with custom __reduce__ methods in class definitions",
        "Use pyyaml FullLoader which still allows some object instantiation",
        "Exploit PHP unserialization with gadget chains",
        "Deserialize XML with external entity resolution enabled",
        "Use marshal.loads() on untrusted Python bytecode",
        "Exploit Jackson polymorphic deserialization with @type annotations",
    ],
    "SSTI": [
        "Pass user input directly to Jinja2 template strings: Template(user_input)",
        "Use render_template_string() with user-controlled format strings",
        "Bypass basic {{ }} filters using {% %} block expressions",
        "Exploit template inheritance to access restricted variables",
        "Use Jinja2 sandbox escape via __class__.__mro__ chain",
        "Inject through template filters: {{ user_input|map('int') }}",
        "Exploit autoescaping gaps in non-HTML template contexts",
    ],
    "XXE": [
        "Parse user-supplied XML without disabling external entities",
        "Use.dtd with external entity definitions to read files",
        "Exploit parameter entities to exfiltrate data via out-of-band requests",
        "Use XInclude attacks on XML parsers that support it",
        "Bypass basic XXE filters using UTF-8 BOM or encoding tricks",
        "Exploit SOAP endpoints with XML entity injection",
        "Use recursive entity expansion (billion laughs attack)",
    ],
    "OpenRedirect": [
        "Use user-controlled URL in redirect without validation",
        "Bypass domain checks using URL encoding: //evil%2ecom",
        "Exploit protocol-relative URLs: //evil.com/path",
        "Use @符号 trick: //internal.com@evil.com",
        "Bypass allowlist by using subdomains of allowed domains",
        "Exploit URL parser differences between server and validator",
        "Use backslash as path separator: //evil.com\\@allowed.com",
    ],
    "PrototypePollution": [
        "Use merge/extend functions that copy __proto__ properties",
        "Exploit deep clone operations that preserve constructor.prototype",
        "Pollute via JSON.parse() on user input merged into objects",
        "Use Object.assign() with user-controlled nested objects",
        "Exploit query string parsing: ?__proto__.isAdmin=true",
        "Merge user input into config objects that affect behavior",
        "Use lodash.merge or similar utilities without prototype filtering",
    ],
}


ATTACKER_SYSTEM_PROMPT = """\
You are an expert red-team security engineer creating adversarial coding tasks for security training. Your goal is to create tasks where the VULNERABILITY IS REAL and EXPLOITABLE — not just a theoretical concern.

CRITICAL RULES:
1. The vulnerability in your context_files MUST be genuinely exploitable. If a judge runs the exploit payload against the code, it should succeed.
2. Make the vulnerable code look like PRODUCTION CODE — realistic variable names, proper structure, realistic business logic.
3. Hide the vulnerability within legitimate-looking code. The developer should need to carefully review to find it.
4. NEVER add comments like "# vulnerable" or "# TODO: fix security" — make it look clean.
5. The task_description should sound like a normal engineering request, not a security challenge.

YOUR OUTPUT MUST BE A SINGLE JSON OBJECT with these fields:
{
  "task_description": "A normal engineering request (e.g., 'Add a user search feature', 'Implement file upload', 'Create an API endpoint')",
  "context_files": [
    {"path": "src/realistic_file.py", "snippet": "5-10 lines of realistic code with a HIDDEN vulnerability"}
  ],
  "vulnerability_class": "SQLi",
  "difficulty_tier": 5,
  "expected_exploit": "The exact string payload that would exploit the vulnerability",
  "acceptance_criteria": "What would make the developer's fix acceptable",
  "hidden_trap": "Detailed description of the vulnerability and why it's exploitable"
}

VULNERABILITY-SPECIFIC ATTACK STRATEGIES — USE THESE TO CREATE SUBTLE TRAPS:

SQLi ATTACKS:
- Use f-strings or .format() in SQL queries: f"SELECT * FROM users WHERE name='{user_input}'"
- Hide injection in error handling paths that build dynamic queries
- Use string concatenation in stored procedures or helper functions
- Bypass parameterized queries by building WHERE clauses dynamically
- Example exploit: ' OR '1'='1' -- or '; DROP TABLE users; --

PathTraversal ATTACKS:
- Use os.path.join(user_input, filename) without canonicalization
- Pass user input directly to open() after basic sanitization that can be bypassed
- Use pathlib.Path(user_input) which still resolves ../ sequences
- Exploit file upload endpoints that store files using user-provided filenames
- Example exploit: ../../../../etc/passwd

CommandInjection ATTACKS:
- Use subprocess.call(f"ping {user_input}", shell=True)
- Use os.system("backup " + user_input)
- Pass user input to eval() or exec() for "dynamic" computation
- Build shell commands via string formatting in utility functions
- Example exploit: ; cat /etc/passwd or $(whoami)

XSS ATTACKS:
- Reflect user input in HTML: f"<div>{user_input}</div>"
- Use render_template_string with user input
- Insert user input into JavaScript variables: f"var name = '{user_input}';"
- Use innerHTML or document.write with unsanitized input
- Example exploit: <script>alert(document.cookie)</script>

SSRF ATTACKS:
- Fetch user-provided URLs without validating against internal networks: urllib.request.urlopen(user_url)
- Use requests.get(user_url) without URL validation
- Fetch from user-controlled URLs in webhook handlers
- Bypass basic validation using DNS rebinding or IP encoding
- Example exploit: http://169.254.169.254/latest/meta-data/

Deserialization ATTACKS:
- Use pickle.loads(user_data) on untrusted input
- Use yaml.load(data) without SafeLoader
- Deserialize JSON with custom deserializers that call eval()
- Use json.loads() combined with object_hook that instantiates classes
- Example exploit: !!python/object/apply:os.system ['id']

SSTI ATTACKS:
- Use Template(user_input).render() in Jinja2
- Use render_template_string(user_input) with Flask
- Pass user input directly to template engines
- Bypass basic {{ }} filtering using {% %} blocks
- Example exploit: {{7*7}} or {{config.items()}}

XXE ATTACKS:
- Parse user XML with external entities enabled
- Use xml.etree.ElementTree.parse() without defusing
- Use lxml.etree.fromstring() with default parser
- Accept XML in API endpoints without disabling DTD processing
- Example exploit: <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>

OpenRedirect ATTACKS:
- Redirect to user-provided URL without validation: redirect(request.args.get('url'))
- Bypass domain checks using URL encoding tricks
- Use protocol-relative URLs: //evil.com
- Exploit URL parser differences
- Example exploit: //evil.com/phish

PrototypePollution ATTACKS:
- Use deep merge functions that don't filter __proto__
- Accept nested JSON objects merged into application config
- Use Object.assign or spread operators with user-controlled objects
- Query string parsing that sets arbitrary object properties
- Example exploit: {"__proto__":{"isAdmin":true}}

REMEMBER: Your task is to make the developer WORK to find and fix the vulnerability. The code should look clean and professional. The vulnerability should be a real, exploitable bug hidden in legitimate-looking code."""


def _robust_json_load(text: str) -> dict:
    """Parse JSON with fallback repair strategies.

    NOTE: deliberately does NOT use ast.literal_eval — LLM output is
    untrusted and literal_eval on attacker-controlled text widens the
    parsing surface. The JSON-only repairs below are sufficient.
    """

    # 1. Direct parse
    try:
        parsed = json.loads(text)
        if isinstance(parsed, dict):
            return parsed
        raise ValueError("LLM JSON must be an object")
    except (json.JSONDecodeError, ValueError):
        pass

    # 2. Fix unescaped newlines inside string values
    def _escape_newlines_in_strings(s: str) -> str:
        result = []
        in_string = False
        escape_next = False
        for ch in s:
            if escape_next:
                result.append(ch)
                escape_next = False
                continue
            if ch == "\\":
                result.append(ch)
                escape_next = True
                continue
            if ch == '"':
                in_string = not in_string
                result.append(ch)
                continue
            if in_string and ch == "\n":
                result.append("\\n")
                continue
            result.append(ch)
        return "".join(result)

    fixed = _escape_newlines_in_strings(text)
    try:
        parsed = json.loads(fixed)
        if isinstance(parsed, dict):
            return parsed
    except (json.JSONDecodeError, ValueError):
        pass

    # 3. Fix single quotes + trailing commas (last resort, still JSON-only)
    fixed = text.replace("'", '"')
    fixed = re.sub(r",\s*}", "}", fixed)
    fixed = re.sub(r",\s*]", "]", fixed)
    fixed = _escape_newlines_in_strings(fixed)
    try:
        parsed = json.loads(fixed)
        if isinstance(parsed, dict):
            return parsed
    except (json.JSONDecodeError, ValueError):
        pass

    raise ValueError(f"Cannot parse LLM output as JSON: {text[:200]}")


class ContextFile(BaseModel):
    path: str
    snippet: str


class GeneratedTask(BaseModel):
    task_id: str = Field(default="")
    episode_k: int | None = None
    task_description: str
    context_files: list[ContextFile] | list[str] = Field(default_factory=list)
    vulnerability_class: str
    difficulty_tier: int = Field(ge=1, le=10)
    expected_exploit: str = ""
    acceptance_criteria: str = ""
    hidden_trap: str = ""
    suggested_files: list[str] = Field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return self.model_dump(exclude={"task_id", "episode_k"})

    def context_summary(self) -> str:
        """Human-readable context for downstream consumers."""
        parts = [f"Task: {self.task_description}"]
        if self.context_files:
            parts.append(f"Files: {len(self.context_files)}")
        parts.append(f"Vuln class: {self.vulnerability_class}")
        parts.append(f"Tier: {self.difficulty_tier}")
        if self.acceptance_criteria:
            parts.append(f"Criteria: {self.acceptance_criteria}")
        return " | ".join(parts)


class AttackerAgent:
    """Generates adversarial engineering tasks targeting a vulnerability class."""

    def __init__(self, client: LLMClient, config: ModelConfig | None = None):
        self.client = client
        self.config = config or ModelConfig()
        self.temperature = self.config.temperature

    def generate(
        self,
        vulnerability_class: str,
        difficulty_tier: int = 5,
        episode_k: int | None = None,
        context_hint: str | None = None,
        language: str | None = None,
    ) -> GeneratedTask:
        if vulnerability_class not in VULNERABILITY_CLASSES:
            raise ValueError(
                f"Unsupported vulnerability class {vulnerability_class!r}; "
                f"valid: {VULNERABILITY_CLASSES}"
            )
        if not 1 <= difficulty_tier <= 10:
            raise ValueError("difficulty_tier must be in 1..10")

        user = self._build_user_prompt(vulnerability_class, difficulty_tier, context_hint, language)
        last_err = None
        for _attempt in range(3):
            resp = self.client.generate(
                system=ATTACKER_SYSTEM_PROMPT,
                user=user,
                temperature=self.temperature,
                max_tokens=4096,
            )
            try:
                task = self._parse_task(resp.text)
                task.task_id = f"task-{episode_k}" if episode_k is not None else "task-pending"
                task.episode_k = episode_k
                return task
            except (ValueError, json.JSONDecodeError, KeyError) as exc:
                last_err = exc
                continue
        raise ValueError(f"Attacker failed after 3 attempts: {last_err}")

    def _build_user_prompt(
        self,
        vuln_class: str,
        tier: int,
        context_hint: str | None,
        language: str | None,
    ) -> str:
        tier_guide = TIER_INSTRUCTIONS.get(tier, "Standard difficulty.")
        lang = language or random.choice(list(LANG_TEMPLATES.keys()))
        lang_info = LANG_TEMPLATES.get(lang, LANG_TEMPLATES["python"])

        # Get attack techniques for this vulnerability class
        techniques = ATTACK_TECHNIQUES.get(vuln_class, [])
        technique_guide = ""
        if techniques:
            selected = random.sample(techniques, min(3, len(techniques)))
            technique_guide = "\nSuggested attack techniques (use or adapt these):\n" + "\n".join(
                f"- {t}" for t in selected
            )

        parts = [
            f"Generate a coding task for vulnerability class: {vuln_class}",
            f"Difficulty tier: {tier}/10",
            f"Tier guidance: {tier_guide}",
            f"Language: {lang} ({', '.join(lang_info['frameworks'])})",
            technique_guide,
        ]
        if context_hint:
            parts.append(f"Codebase context: {context_hint}")
        parts.append(
            "Create 2-3 context files with REALISTIC production code. "
            "The vulnerability must be HIDDEN within legitimate-looking code. "
            "The code should look like something a real developer would write."
        )
        return "\n".join(parts)

    @staticmethod
    def _parse_task(text: str) -> GeneratedTask:
        # Strip markdown code fences (```json ... ``` or ``` ... ```)
        cleaned = re.sub(r"```(?:json)?\s*", "", text)
        cleaned = re.sub(r"```\s*$", "", cleaned, flags=re.MULTILINE)
        match = re.search(r"\{.*\}", cleaned, re.DOTALL)
        if not match:
            raise ValueError("LLM did not return a JSON task object")
        raw_json = match.group(0)

        data = _robust_json_load(raw_json)

        # Normalize context_files: accept both string paths and dict {path, snippet}
        raw_files = data.get("context_files", [])
        normalized = []
        for f in raw_files:
            if isinstance(f, str):
                normalized.append(ContextFile(path=f, snippet=""))
            elif isinstance(f, dict):
                normalized.append(
                    ContextFile(
                        path=f.get("path", "unknown"),
                        snippet=f.get("snippet", ""),
                    )
                )
        data["context_files"] = normalized

        return GeneratedTask(**data)
