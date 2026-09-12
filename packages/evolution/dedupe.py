"""Semantic deduplication + rule validation helpers.

Uses sentence-transformers for cosine similarity when available,
falls back to token-overlap Jaccard similarity otherwise.
"""

from __future__ import annotations

import logging
import re
from typing import Any

logger = logging.getLogger(__name__)

# Lazy-loaded sentence-transformers model
_model: Any = None
_model_loaded: bool = False


def _get_model() -> Any:
    """Lazily load the sentence-transformers model."""
    global _model, _model_loaded
    if _model_loaded:
        return _model
    _model_loaded = True
    try:
        from sentence_transformers import SentenceTransformer

        _model = SentenceTransformer("all-MiniLM-L6-v2")
        logger.info("Loaded sentence-transformers model 'all-MiniLM-L6-v2'")
    except Exception:
        logger.debug("sentence-transformers not available, using Jaccard fallback")
        _model = None
    return _model


def _embed(texts: list[str]) -> Any:
    """Embed a list of texts using sentence-transformers. Returns None if unavailable."""
    model = _get_model()
    if model is None:
        return None
    embeddings = model.encode(texts, convert_to_numpy=True)
    return embeddings


def is_duplicate(
    new_rule: str,
    existing_rules: list[str],
    threshold: float = 0.85,
) -> bool:
    """Check if a new rule is semantically duplicate of existing rules.

    Uses sentence-transformers cosine similarity when available,
    falls back to Jaccard token overlap.
    """
    if not existing_rules:
        return False

    # Try semantic similarity first
    embeddings = _embed([new_rule] + existing_rules)
    if embeddings is not None:
        import numpy as np

        new_emb = embeddings[0]
        existing_embs = embeddings[1:]
        # Cosine similarity (embeddings are L2-normalized by sentence-transformers)
        similarities = np.dot(existing_embs, new_emb)
        return bool(float(np.max(similarities)) >= threshold)

    # Fallback: Jaccard token overlap
    return _jaccard_duplicate(new_rule, existing_rules, threshold)


def _jaccard_duplicate(
    new_rule: str,
    existing_rules: list[str],
    threshold: float = 0.85,
) -> bool:
    """Token-overlap Jaccard similarity fallback."""
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
    return set(re.findall(r"[a-z0-9]+", text.lower()))


def validate_rule_mandate(rule: Any) -> bool:
    """Distilled rules must be imperative (start with ALWAYS/NEVER) and concise."""
    text = getattr(rule, "rule_text", "")
    text = (text or "").strip().lower()
    return len(getattr(rule, "rule_text", "")) > 10 and text.startswith(("always", "never"))


def semantic_similarity(a: str, b: str) -> float:
    """Compute semantic similarity between two texts.

    Returns a value between 0.0 (completely different) and 1.0 (identical).
    Falls back to Jaccard if sentence-transformers unavailable.
    """
    embeddings = _embed([a, b])
    if embeddings is not None:
        import numpy as np

        return float(np.dot(embeddings[0], embeddings[1]))

    # Jaccard fallback
    tokens_a = _tokens(a)
    tokens_b = _tokens(b)
    if not tokens_a or not tokens_b:
        return 0.0
    return len(tokens_a & tokens_b) / len(tokens_a | tokens_b)
