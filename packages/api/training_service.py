"""Shared training helpers — single source of truth for provider resolution and persistence.

Used by packages/api/main.py (sync + SSE endpoints) and packages/api/worker.py
so all entry points behave identically.
"""

from __future__ import annotations
from typing import Optional


from sqlalchemy.orm import Session

from .config import Settings
from .models import EloRecord, EpisodeRecord, PromptRecord, RuleRecord


def resolve_llm_provider(settings: Settings):
    """Pick best available LLM provider. Returns (provider, api_key, model)."""
    # Respect explicit LLM_PROVIDER setting first
    provider = settings.llm_provider.lower()
    key = _provider_key(settings, provider)
    if key:
        return provider, key, settings.llm_model
    # Fallback: auto-detect from available keys
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


def _provider_key(settings: Settings, provider: str) -> str:
    """Return the configured API key for a provider name ("" if none)."""
    return {
        "groq": settings.groq_api_key,
        "anthropic": settings.anthropic_api_key,
        "openai": settings.openai_api_key,
        "huggingface": settings.huggingface_api_key,
        "openrouter": settings.openrouter_api_key,
        "gemini": settings.gemini_api_key,
        "modelscope": settings.modelscope_api_key,
    }.get(provider, "")


def resolve_small_llm_provider(settings: Settings):
    """Resolve the optional distillation client.

    Returns None when SMALL_LLM_MODEL is unset (caller must fall back to the
    main client) or when the provider has no key configured — never a client
    that would fail at call time.
    """
    if not settings.small_llm_model:
        return None
    provider = (settings.small_llm_provider or "").lower() or "groq"
    if provider == "mock":
        return "mock", None, settings.small_llm_model
    key = _provider_key(settings, provider)
    if not key:
        return None
    return provider, key, settings.small_llm_model


def build_loop(prompt_version: int, use_react: bool = False):
    """Build a TrainingLoop with main + optional small client.

    Single source of truth for client construction across the sync endpoint,
    the SSE stream, and the worker (which has its own env-override path and
    does not use this helper).
    """
    from ..agents.llm import ModelConfig, build_client
    from ..agents.training_loop import TrainingLoop
    from .config import get_settings

    settings = get_settings()
    provider, key, model = resolve_llm_provider(settings)
    llm = build_client(provider, model, api_key=key)
    small = None
    resolved_small = resolve_small_llm_provider(settings)
    if resolved_small is not None:
        small_provider, small_key, small_model = resolved_small
        small = build_client(small_provider, small_model, api_key=small_key)
    # Only forward explicitly configured overrides; otherwise ModelConfig's
    # tuned per-role defaults apply (passing None would clobber them).
    model_config = ModelConfig()
    if settings.attacker_temperature is not None:
        model_config.attacker_temperature = settings.attacker_temperature
    if settings.developer_temperature is not None:
        model_config.developer_temperature = settings.developer_temperature
    if settings.distiller_temperature is not None:
        model_config.distiller_temperature = settings.distiller_temperature
    return TrainingLoop(
        llm=llm,
        prompt_version=prompt_version,
        use_react=use_react,
        small_llm=small,
        model_config=model_config,
    )


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
