"""Distiller Agent - converts failure traces into defensive rules."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass

from ..llm import LLMClient, ModelConfig

DISTILLER_SYSTEM_PROMPT = """\
You are a security expert translating raw execution failure traces into actionable
defensive rules for autonomous coding agents.

Given a confirmed vulnerability failure trace, produce a concise imperative rule that:
1. GENERALIZES THE PATTERN: no specific variable names, file paths, or line numbers.
   Abstract to the vulnerability class.
2. PROVIDES ACTIONABLE GUIDANCE: tell the developer EXACTLY what to do and what not to do.
3. IS SELF-CONTAINED: understandable without other rules or the trace.
4. IS CONCISE: under 100 words.
5. IS IMPERATIVE: start with ALWAYS or NEVER.

Return ONLY a JSON object with keys:
- rule_text: the imperative rule
- vulnerability_class: the vulnerability class
- source_pattern: brief description of what went wrong
- recommended_fix: general prevention approach
"""


@dataclass
class DistilledRule:
    rule_text: str
    vulnerability_class: str
    source_pattern: str
    recommended_fix: str
    source_trace_id: str = ""

    @property
    def is_valid(self) -> bool:
        text = self.rule_text.strip().lower()
        return (
            len(self.rule_text.strip()) > 10
            and text.startswith(("always", "never"))
        )


class DistillerAgent:
    """Distills failure traces (phi_k) into imperative rules (rho_k)."""

    def __init__(self, client: LLMClient, config: ModelConfig | None = None):
        self.client = client
        self.temperature = (config or ModelConfig()).temperature

    def distill(self, trace: str, trace_id: str = "") -> DistilledRule:
        resp = self.client.generate(
            system=DISTILLER_SYSTEM_PROMPT,
            user=f"FAILURE TRACE:\n{trace}",
            temperature=self.temperature,
        )
        rule = self._parse_rule(resp.text)
        rule.source_trace_id = trace_id
        return rule

    @staticmethod
    def _parse_rule(text: str) -> DistilledRule:
        match = re.search(r"\{.*\}", text, re.DOTALL)
        if not match:
            raise ValueError("Distiller did not return a JSON rule")
        data = json.loads(match.group(0))
        return DistilledRule(
            rule_text=data.get("rule_text", ""),
            vulnerability_class=data.get("vulnerability_class", ""),
            source_pattern=data.get("source_pattern", ""),
            recommended_fix=data.get("recommended_fix", ""),
        )