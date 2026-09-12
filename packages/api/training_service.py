"""Shared training helpers — single source of truth for provider resolution and persistence.

Used by packages/api/main.py (sync + SSE endpoints) and packages/api/worker.py
so all entry points behave identically.
"""

from __future__ import annotations

from typing import Optional

from sqlalchemy.orm import Session

from .config import Settings
from .models import EloRecord, EpisodeRecord, PromptRecord, RuleRecord


def resolve_llm_provider(settings: Settings) -> tuple[str, Optional[str], str]:
    """Pick best available LLM provider. Returns (provider, api_key, model)."""
    if settings.groq_api_key:
        return "groq", settings.groq_api_key, settings.llm_model
    if settings.anthropic_api_key:
        return "anthropic", settings.anthropic_api_key, settings.llm_model
    if settings.openai_api_key:
        return "openai", settings.openai_api_key, settings.llm_model
    if settings.huggingface_api_key:
        return "huggingface", settings.huggingface_api_key, settings.llm_model
    if settings.openrouter_api_key:
        return "openrouter", settings.openrouter_api_key, settings.llm_model
    if settings.gemini_api_key:
        return "gemini", settings.gemini_api_key, settings.llm_model
    if settings.modelscope_api_key:
        return "modelscope", settings.modelscope_api_key, settings.llm_model
    return "mock", None, settings.llm_model


def get_current_ratings(db: Session) -> tuple[float, float]:
    """Return (attacker, developer) ratings, defaulting to 1500/1500."""
    elo_record = db.get(EloRecord, "global")
    if elo_record:
        return (elo_record.attacker_rating, elo_record.developer_rating)
    return (1500.0, 1500.0)


def get_prompt_version(db: Session) -> int:
    """Return latest prompt version, defaulting to 0."""
    latest = db.query(PromptRecord).order_by(PromptRecord.version.desc()).first()
    return latest.version if latest else 0


def persist_episode(
    db: Session,
    *,
    trace,  # EpisodeTrace — untyped to avoid circular import
    vulnerability_class: str,
    current_ratings: tuple[float, float],
) -> EpisodeRecord:
    """Persist an EpisodeTrace + Elo + distilled rule. Returns the EpisodeRecord."""
    ep = EpisodeRecord(
        id=trace.episode_id,
        status="completed" if not trace.error else "failed",
        vulnerability_class=vulnerability_class,
        difficulty_tier=trace.difficulty_tier,
        outcome=trace.judge_outcome,
        task_description=trace.task.task_description if trace.task else "",
        patch_text=trace.patch_text,
        judge_verdict=trace.judge_verdict,
        attacker_rating=trace.elo_after.get("attacker", current_ratings[0]),
        developer_rating=trace.elo_after.get("developer", current_ratings[1]),
        prompt_version=trace.prompt_version,
        error=trace.error or None,
    )
    db.add(ep)

    elo_record = db.get(EloRecord, "global")
    if elo_record:
        elo_record.attacker_rating = trace.elo_after.get("attacker", elo_record.attacker_rating)
        elo_record.developer_rating = trace.elo_after.get("developer", elo_record.developer_rating)
        elo_record.episodes_played += 1
    else:
        db.add(
            EloRecord(
                id="global",
                attacker_rating=trace.elo_after.get("attacker", 1500.0),
                developer_rating=trace.elo_after.get("developer", 1500.0),
                episodes_played=1,
            )
        )

    if trace.distilled_rule and trace.regression_passed:
        rule = trace.distilled_rule
        db.add(
            RuleRecord(
                rule_text=rule.rule_text,
                vulnerability_class=rule.vulnerability_class,
                source_pattern=rule.source_pattern,
                recommended_fix=rule.recommended_fix,
                source_trace_id=rule.source_trace_id,
                prompt_version=trace.prompt_version,
                approved=True,
            )
        )

    db.commit()
    return ep
