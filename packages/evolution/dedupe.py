"""Semantic deduplication + rule validation helpers."""

from __future__ import annotations

from typing import Any

try:
    import numpy as np  # type: ignore[import-not-found]
except ImportError:  # pragma: no cover
    np = None


def is_duplicate(
    new_rule: str,
    existing_rules: list[str],
    threshold: float = 0.85,
) -> bool:
    """Token-overlap Jaccard fallback if embeddings unavailable."""
    from .store import PromptRule

    if not existing_rules:
        return False
    new_tokens = _tokens(new_rule)
    for existing in existing_rules:
        existing_tokens = _tokens(existing)
        if not new_tokens or not existing_tokens:
            continue
        overlap = len(new_tokens & existing_tokens) / len(new_tokens | existing_tokens)
        if overlap >= threshold:
            return True
    return False


def _tokens(text: str) -> set[str]:
    import re

    return set(re.findall(r"[a-z0-9]+", text.lower()))


def validate_rule_mandate(rule: Any) -> bool:
    """Distilled rules must be imperative (start with ALWAYS/NEVER) and concise."""
    text = getattr(rule, "rule_text", "")
    text = (text or "").strip().lower()
    return len(getattr(rule, "rule_text", "")) > 10 and text.startswith(("always", "never"))