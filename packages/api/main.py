"""CoEvolve API — simplified for Render free tier deployment."""

from __future__ import annotations

import asyncio
import concurrent.futures
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, StreamingResponse
from sqlalchemy import func
from sqlalchemy.orm import Session

from .config import get_settings
from .database import Base, get_db, get_engine, get_session_factory
from .models import EloRecord, EpisodeRecord, PromptRecord, RuleRecord
from .schemas import (
    EloHistoryResponse,
    EpisodeRead,
    MetricsSnapshot,
    RuleRead,
    TrainingRunRequest,
    TrainingRunResponse,
)


import logging

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    try:
        engine = get_engine()
        Base.metadata.create_all(engine)
        _seed_elo()
        logger.info("Database connected successfully")
    except Exception as exc:
        logger.error("Database connection failed: %s", exc)
        logger.error("Check your DATABASE_URL environment variable")
    yield


app = FastAPI(
    title="CoEvolve API",
    version="0.1.0",
    description="Adversarial Training as a Service",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def _seed_elo() -> None:
    db = get_session_factory()()
    try:
        if db.query(EloRecord).count() == 0:
            db.add(EloRecord(id="global", attacker_rating=1500.0, developer_rating=1500.0))
            db.commit()
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Health / Metrics
# ---------------------------------------------------------------------------
@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "healthy"}


@app.get("/metrics", response_model=MetricsSnapshot)
def metrics(db: Session = Depends(get_db)) -> MetricsSnapshot:
    total = db.query(func.count(EpisodeRecord.id)).scalar() or 0
    secure = db.query(func.count(EpisodeRecord.id)).filter(EpisodeRecord.outcome == 0).scalar() or 0
    rules_count = db.query(func.count(RuleRecord.id)).scalar() or 0
    elo = db.get(EloRecord, "global")
    return MetricsSnapshot(
        total_episodes=total,
        secure_rate=secure / total if total else 0.0,
        epo={
            "attacker": elo.attacker_rating if elo else 1500.0,
            "developer": elo.developer_rating if elo else 1500.0,
        },
        rules_count=rules_count,
    )


# ---------------------------------------------------------------------------
# Episodes
# ---------------------------------------------------------------------------
@app.get("/episodes", response_model=list[EpisodeRead])
def list_episodes(
    status: str | None = Query(None),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
) -> list[EpisodeRecord]:
    q = db.query(EpisodeRecord)
    if status:
        q = q.filter(EpisodeRecord.status == status)
    return q.order_by(EpisodeRecord.created_at.desc()).offset(offset).limit(limit).all()


@app.get("/episodes/{episode_id}", response_model=EpisodeRead)
def get_episode(episode_id: str, db: Session = Depends(get_db)) -> EpisodeRecord:
    ep = db.get(EpisodeRecord, episode_id)
    if not ep:
        raise HTTPException(404, "Episode not found")
    return ep


# ---------------------------------------------------------------------------
# ELO
# ---------------------------------------------------------------------------
@app.get("/elo")
def elo(db: Session = Depends(get_db)) -> dict[str, float]:
    record = db.get(EloRecord, "global")
    return {
        "attacker": record.attacker_rating if record else 1500.0,
        "developer": record.developer_rating if record else 1500.0,
    }


@app.get("/elo/history", response_model=EloHistoryResponse)
def elo_history(db: Session = Depends(get_db)) -> EloHistoryResponse:
    record = db.get(EloRecord, "global")
    return EloHistoryResponse(
        history=[],
        current={
            "attacker": record.attacker_rating if record else 1500.0,
            "developer": record.developer_rating if record else 1500.0,
        },
    )


# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------
@app.get("/rules", response_model=list[RuleRead])
def list_rules(
    vuln_class: str | None = Query(None),
    approved_only: bool = Query(False),
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
) -> list[RuleRecord]:
    q = db.query(RuleRecord)
    if vuln_class:
        q = q.filter(RuleRecord.vulnerability_class == vuln_class)
    if approved_only:
        q = q.filter(RuleRecord.approved.is_(True))
    return q.order_by(RuleRecord.created_at.desc()).limit(limit).all()


# ---------------------------------------------------------------------------
# Training — Synchronous Run
# ---------------------------------------------------------------------------
@app.post("/training/run", response_model=TrainingRunResponse)
def run_training_episode(
    body: TrainingRunRequest, db: Session = Depends(get_db)
) -> TrainingRunResponse:
    """Execute one co-evolutionary training episode (blocks until done)."""
    from ..agents.llm import build_client
    from ..agents.training_loop import EpisodeConfig, TrainingLoop

    elo_record = db.get(EloRecord, "global")
    current_ratings = (
        (elo_record.attacker_rating, elo_record.developer_rating)
        if elo_record
        else (1500.0, 1500.0)
    )

    latest_prompt = db.query(PromptRecord).order_by(PromptRecord.version.desc()).first()
    prompt_version = latest_prompt.version if latest_prompt else 0

    settings = get_settings()
    # Pick best available provider
    if settings.groq_api_key:
        provider, key = "groq", settings.groq_api_key
    elif settings.anthropic_api_key:
        provider, key = "anthropic", settings.anthropic_api_key
    elif settings.openai_api_key:
        provider, key = "openai", settings.openai_api_key
    elif settings.huggingface_api_key:
        provider, key = "huggingface", settings.huggingface_api_key
    elif settings.openrouter_api_key:
        provider, key = "openrouter", settings.openrouter_api_key
    else:
        provider, key = "mock", None

    llm = build_client(provider, settings.llm_model, api_key=key)

    loop = TrainingLoop(llm=llm, prompt_version=prompt_version, use_react=body.use_react)
    config = EpisodeConfig(
        vulnerability_class=body.vulnerability_class,
        language=body.language,
        context_hint=body.context_hint,
        max_retries=body.max_retries,
    )
    trace = loop.run_episode(config, current_ratings=current_ratings)

    ep = EpisodeRecord(
        id=trace.episode_id,
        status="completed" if not trace.error else "failed",
        vulnerability_class=body.vulnerability_class,
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

    if elo_record:
        elo_record.attacker_rating = trace.elo_after.get("attacker", elo_record.attacker_rating)
        elo_record.developer_rating = trace.elo_after.get("developer", elo_record.developer_rating)
        elo_record.episodes_played += 1
    else:
        db.add(EloRecord(
            id="global",
            attacker_rating=trace.elo_after.get("attacker", 1500.0),
            developer_rating=trace.elo_after.get("developer", 1500.0),
            episodes_played=1,
        ))

    if trace.distilled_rule and trace.regression_passed:
        rule = trace.distilled_rule
        db.add(RuleRecord(
            rule_text=rule.rule_text,
            vulnerability_class=rule.vulnerability_class,
            source_pattern=rule.source_pattern,
            recommended_fix=rule.recommended_fix,
            source_trace_id=rule.source_trace_id,
            prompt_version=trace.prompt_version,
            approved=True,
        ))

    db.commit()

    return TrainingRunResponse(
        episode_id=trace.episode_id,
        status="completed" if not trace.error else "failed",
        difficulty_tier=trace.difficulty_tier,
        judge_outcome=trace.judge_outcome,
        judge_verdict=trace.judge_verdict,
        rule_distilled=trace.distilled_rule is not None and trace.regression_passed,
        rule_text=trace.distilled_rule.rule_text if trace.distilled_rule else None,
        regression_passed=trace.regression_passed,
        elo_before=trace.elo_before,
        elo_after=trace.elo_after,
        duration_s=trace.duration_s,
        error=trace.error or None,
    )


# ---------------------------------------------------------------------------
# Training — SSE Stream (real-time progress)
# ---------------------------------------------------------------------------
@app.get("/training/stream")
async def training_stream(
    vulnerability_class: str = "SQLi",
    language: str = "python",
):
    """Stream training progress via Server-Sent Events."""
    import json

    from ..agents.llm import build_client
    from ..agents.training_loop import EpisodeConfig, TrainingLoop

    async def event_generator():
        from .database import get_session_factory

        factory = get_session_factory()
        db = factory()

        try:
            elo_record = db.get(EloRecord, "global")
            current_ratings = (
                (elo_record.attacker_rating, elo_record.developer_rating)
                if elo_record
                else (1500.0, 1500.0)
            )

            latest_prompt = db.query(PromptRecord).order_by(PromptRecord.version.desc()).first()
            prompt_version = latest_prompt.version if latest_prompt else 0

            settings = get_settings()
            if settings.groq_api_key:
                provider, key = "groq", settings.groq_api_key
            elif settings.anthropic_api_key:
                provider, key = "anthropic", settings.anthropic_api_key
            elif settings.openai_api_key:
                provider, key = "openai", settings.openai_api_key
            else:
                provider, key = "mock", None

            llm = build_client(provider, settings.llm_model, api_key=key)
            config = EpisodeConfig(
                vulnerability_class=vulnerability_class,
                language=language,
                context_hint="",
                max_retries=3,
            )

            yield f"data: {json.dumps({'type': 'start', 'vuln': vulnerability_class, 'lang': language, 'elo': list(current_ratings)})}\n\n"
            await asyncio.sleep(0.1)

            # Run in thread pool
            loop_inst = TrainingLoop(llm=llm, prompt_version=prompt_version, use_react=True)

            with concurrent.futures.ThreadPoolExecutor() as pool:
                future = pool.submit(loop_inst.run_episode, config, current_ratings=current_ratings)
                trace = await asyncio.get_event_loop().run_in_executor(None, future.result)

            outcome_text = "SECURE" if trace.judge_outcome == 0 else "VULNERABLE"

            steps = [
                {"type": "agent", "agent": "attacker", "status": "done", "message": f"Task generated (tier {trace.difficulty_tier}/10)"},
                {"type": "agent", "agent": "developer", "status": "done", "message": f"Patch built ({len(trace.patch_text)} chars)"},
                {"type": "agent", "agent": "judge", "status": "done", "message": f"Outcome: {outcome_text}"},
            ]
            if trace.distilled_rule and trace.regression_passed:
                steps.append({"type": "agent", "agent": "distiller", "status": "done", "message": f"Rule: {trace.distilled_rule.rule_text[:80]}"})
            else:
                steps.append({"type": "agent", "agent": "distiller", "status": "skip", "message": "No rule distilled"})

            for step in steps:
                yield f"data: {json.dumps(step)}\n\n"
                await asyncio.sleep(0.1)

            yield f"data: {json.dumps({'type': 'elo', 'before': trace.elo_before, 'after': trace.elo_after})}\n\n"

            # Persist
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

            if elo_record:
                elo_record.attacker_rating = trace.elo_after.get("attacker", elo_record.attacker_rating)
                elo_record.developer_rating = trace.elo_after.get("developer", elo_record.developer_rating)
                elo_record.episodes_played += 1
            else:
                db.add(EloRecord(
                    id="global",
                    attacker_rating=trace.elo_after.get("attacker", 1500.0),
                    developer_rating=trace.elo_after.get("developer", 1500.0),
                    episodes_played=1,
                ))

            if trace.distilled_rule and trace.regression_passed:
                rule = trace.distilled_rule
                db.add(RuleRecord(
                    rule_text=rule.rule_text,
                    vulnerability_class=rule.vulnerability_class,
                    source_pattern=rule.source_pattern,
                    recommended_fix=rule.recommended_fix,
                    source_trace_id=rule.source_trace_id,
                    prompt_version=trace.prompt_version,
                    approved=True,
                ))

            db.commit()

            yield f"data: {json.dumps({'type': 'complete', 'episode_id': trace.episode_id, 'outcome': trace.judge_outcome, 'rule_distilled': trace.distilled_rule is not None and trace.regression_passed, 'duration_s': trace.duration_s})}\n\n"

        except Exception as e:
            yield f"data: {json.dumps({'type': 'error', 'message': str(e)})}\n\n"
        finally:
            db.close()

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "Connection": "keep-alive", "X-Accel-Buffering": "no"},
    )
