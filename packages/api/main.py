"""CoEvolve API — simplified for Render free tier deployment."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from sqlalchemy import func
from sqlalchemy.orm import Session

from .auth import APIKey, require_api_key_if_enabled
from .config import get_settings
from .database import Base, get_db, get_engine, get_session_factory
from .models import EloRecord, EpisodeRecord, PromptRecord, RuleRecord
from .schemas import (
    EloHistoryResponse,
    EpisodeRead,
    EpisodeStopResponse,
    MetricsSnapshot,
    PromptDiffResponse,
    PromptRead,
    RuleDetailRead,
    RuleRead,
    TrainingJobEnqueueRequest,
    TrainingJobRead,
    TrainingRunRequest,
    TrainingRunResponse,
    VulnerabilityCoverage,
)
from .task_queue import TrainingJob, get_task_queue
from .training_service import (
    get_current_ratings,
    get_prompt_version,
    persist_episode,
    resolve_llm_provider,
)

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    try:
        engine = get_engine()
        Base.metadata.create_all(engine)
        _seed_elo()
        # Warm the key store so ADMIN_API_KEY bootstrap registers at startup
        # (works for both memory and db backends).
        from .auth import get_key_store

        get_key_store()
        logger.info("Database connected successfully")
    except Exception as exc:
        # Log and continue so /health stays available; training endpoints
        # will surface DB errors per-request. Fail-fast is handled by
        # docker-compose.prod.yml required-var validation instead.
        logger.error("Database connection failed: %s", exc)
        logger.error("Check your DATABASE_URL environment variable")
    yield


app = FastAPI(
    title="CoEvolve API",
    version="0.1.0",
    description="Adversarial Training as a Service",
    lifespan=lifespan,
)


def _configure_cors() -> None:
    settings = get_settings()
    origins = settings.cors_origin_list
    if "*" in origins:
        # Browsers reject allow_credentials with "*"; disable credentials
        # in wildcard mode (dev default). Set CORS_ORIGINS to explicit
        # origins in production to re-enable credentials.
        app.add_middleware(
            CORSMiddleware,
            allow_origins=["*"],
            allow_credentials=False,
            allow_methods=["*"],
            allow_headers=["*"],
        )
    else:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=origins,
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )


_configure_cors()


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
    ratings = {
        "attacker": elo.attacker_rating if elo else 1500.0,
        "developer": elo.developer_rating if elo else 1500.0,
    }
    return MetricsSnapshot(
        total_episodes=total,
        secure_rate=secure / total if total else 0.0,
        epo=ratings,
        elo=ratings,
        rules_count=rules_count,
    )


# ---------------------------------------------------------------------------
# Episodes
# ---------------------------------------------------------------------------
@app.get("/episodes", response_model=list[EpisodeRead])
def list_episodes(
    status: Optional[str] = Query(None),
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
    vuln_class: Optional[str] = Query(None),
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
# Prompts
# ---------------------------------------------------------------------------
@app.get("/prompts/current", response_model=PromptRead)
def get_current_prompt(db: Session = Depends(get_db)) -> PromptRecord:
    prompt = db.query(PromptRecord).order_by(PromptRecord.version.desc()).first()
    if not prompt:
        raise HTTPException(404, "No prompt versions found")
    return prompt


@app.get("/prompts/history", response_model=list[PromptRead])
def get_prompt_history(
    limit: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
) -> list[PromptRecord]:
    return db.query(PromptRecord).order_by(PromptRecord.version.desc()).limit(limit).all()


@app.get("/prompts/diff/{v1}/{v2}", response_model=PromptDiffResponse)
def get_prompt_diff(v1: int, v2: int, db: Session = Depends(get_db)) -> PromptDiffResponse:
    from ..evolution.store import PromptStore

    store = PromptStore()
    try:
        diff = store.diff(v1, v2)
    except KeyError as exc:
        raise HTTPException(404, f"Version {v1} or {v2} not found") from exc
    return PromptDiffResponse(
        from_version=diff["from"],
        to_version=diff["to"],
        added=diff["added"],
        removed=diff["removed"],
    )


# ---------------------------------------------------------------------------
# Rules — single rule
# ---------------------------------------------------------------------------
@app.get("/rules/{rule_id}", response_model=RuleDetailRead)
def get_rule(rule_id: str, db: Session = Depends(get_db)) -> RuleRecord:
    rule = db.get(RuleRecord, rule_id)
    if not rule:
        raise HTTPException(404, "Rule not found")
    return rule


# ---------------------------------------------------------------------------
# Vulnerabilities — coverage report
# ---------------------------------------------------------------------------
@app.get("/vulnerabilities/coverage", response_model=list[VulnerabilityCoverage])
def get_vulnerability_coverage(db: Session = Depends(get_db)) -> list[VulnerabilityCoverage]:
    from sqlalchemy import case

    rows = (
        db.query(
            EpisodeRecord.vulnerability_class,
            func.count(EpisodeRecord.id).label("total"),
            func.sum(case((EpisodeRecord.outcome == 1, 1), else_=0)).label("detected"),
            func.sum(case((EpisodeRecord.outcome == 0, 1), else_=0)).label("secure"),
        )
        .filter(EpisodeRecord.vulnerability_class.isnot(None))
        .group_by(EpisodeRecord.vulnerability_class)
        .all()
    )
    result = []
    for row in rows:
        total = row.total or 0
        detected = row.detected or 0
        result.append(
            VulnerabilityCoverage(
                vulnerability_class=row.vulnerability_class,
                total_episodes=total,
                detected_count=detected,
                secure_count=row.secure or 0,
                coverage_rate=(total - detected) / total if total else 0.0,
            )
        )
    return result


# ---------------------------------------------------------------------------
# Episodes — stop (auth enforced when REQUIRE_AUTH=true)
# ---------------------------------------------------------------------------
@app.post("/episodes/{episode_id}/stop", response_model=EpisodeStopResponse)
def stop_episode(
    episode_id: str,
    db: Session = Depends(get_db),
    _auth: Optional[APIKey] = Depends(require_api_key_if_enabled),
) -> EpisodeStopResponse:
    ep = db.get(EpisodeRecord, episode_id)
    if not ep:
        raise HTTPException(404, "Episode not found")
    if ep.status in ("completed", "failed"):
        return EpisodeStopResponse(
            episode_id=episode_id,
            status=ep.status,
            message=f"Episode already {ep.status}",
        )
    ep.status = "failed"
    ep.error = "Stopped by user"
    db.commit()
    return EpisodeStopResponse(
        episode_id=episode_id,
        status="failed",
        message="Episode stopped",
    )


# ---------------------------------------------------------------------------
# Training — Synchronous Run
# ---------------------------------------------------------------------------
# NOTE: this is a sync `def` endpoint, so FastAPI runs it in a threadpool —
# it does not block the async event loop. For long-running jobs prefer the
# TaskQueue/worker path (packages/api/task_queue.py + worker.py).
@app.post("/training/run", response_model=TrainingRunResponse)
def run_training_episode(
    body: TrainingRunRequest,
    db: Session = Depends(get_db),
    _auth: Optional[APIKey] = Depends(require_api_key_if_enabled),
) -> TrainingRunResponse:
    """Execute one co-evolutionary training episode (blocks until done)."""
    from ..agents.llm import build_client
    from ..agents.training_loop import EpisodeConfig, TrainingLoop

    current_ratings = get_current_ratings(db)
    prompt_version = get_prompt_version(db)

    settings = get_settings()
    provider, key, model = resolve_llm_provider(settings)

    llm = build_client(provider, model, api_key=key)

    loop = TrainingLoop(llm=llm, prompt_version=prompt_version, use_react=body.use_react)
    config = EpisodeConfig(
        vulnerability_class=body.vulnerability_class,
        language=body.language,
        context_hint=body.context_hint,
        max_retries=body.max_retries,
    )
    trace = loop.run_episode(config, current_ratings=current_ratings)

    persist_episode(
        db,
        trace=trace,
        vulnerability_class=body.vulnerability_class,
        current_ratings=current_ratings,
    )

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


def _job_to_read(job: TrainingJob, queue_position: Optional[int] = None) -> TrainingJobRead:
    return TrainingJobRead(
        job_id=job.job_id,
        status=job.status.value,
        vulnerability_class=job.vulnerability_class,
        language=job.language,
        context_hint=job.context_hint,
        max_retries=job.max_retries,
        use_react=job.use_react,
        queue_position=queue_position,
        created_at=job.created_at,
        started_at=job.started_at,
        completed_at=job.completed_at,
        result=job.result,
        error=job.error,
    )


# ---------------------------------------------------------------------------
# Training — Async Jobs (non-blocking; processed by worker.py)
# ---------------------------------------------------------------------------
# NOTE: with the in-memory queue backend this only works single-process.
# Multi-process deployments (uvicorn --workers + separate worker) require
# REDIS_URL so the API and worker share queue state.
@app.post("/training/jobs", response_model=TrainingJobRead, status_code=202)
def enqueue_training_job(
    body: TrainingJobEnqueueRequest,
    _auth: Optional[APIKey] = Depends(require_api_key_if_enabled),
) -> TrainingJobRead:
    """Enqueue a training episode and return immediately (202 Accepted)."""
    queue = get_task_queue()
    job = queue.enqueue(
        TrainingJob(
            vulnerability_class=body.vulnerability_class,
            language=body.language,
            context_hint=body.context_hint,
            max_retries=body.max_retries,
            use_react=body.use_react,
        )
    )
    return _job_to_read(job, queue_position=queue.queue_length())


@app.get("/training/jobs", response_model=list[TrainingJobRead])
def list_training_jobs(
    limit: int = Query(50, ge=1, le=200),
) -> list[TrainingJobRead]:
    """List recent training jobs (newest first)."""
    return [_job_to_read(j) for j in get_task_queue().list_jobs(limit=limit)]


@app.get("/training/jobs/{job_id}", response_model=TrainingJobRead)
def get_training_job(job_id: str) -> TrainingJobRead:
    """Poll a training job's status and result."""
    job = get_task_queue().get_job(job_id)
    if job is None:
        raise HTTPException(404, "Job not found")
    return _job_to_read(job)


# ---------------------------------------------------------------------------
# Training — SSE Stream (real-time progress)
# ---------------------------------------------------------------------------
@app.get("/training/stream")
async def training_stream(
    vulnerability_class: str = "SQLi",
    language: str = "python",
    _auth: Optional[APIKey] = Depends(require_api_key_if_enabled),
):
    """Stream training progress via Server-Sent Events.

    Auth enforced when REQUIRE_AUTH=true. Browsers/EventSource cannot set
    headers, so pass ``?api_key=<key>`` (supported by the API key query
    scheme) for this endpoint.
    """
    import json

    from ..agents.llm import build_client
    from ..agents.training_loop import EpisodeConfig, TrainingLoop

    async def event_generator():
        db = get_session_factory()()

        try:
            current_ratings = get_current_ratings(db)
            prompt_version = get_prompt_version(db)

            settings = get_settings()
            provider, key, model = resolve_llm_provider(settings)

            llm = build_client(provider, model, api_key=key)
            config = EpisodeConfig(
                vulnerability_class=vulnerability_class,
                language=language,
                context_hint="",
                max_retries=3,
            )

            yield f"data: {json.dumps({'type': 'start', 'vuln': vulnerability_class, 'lang': language, 'elo': list(current_ratings)})}\n\n"
            await asyncio.sleep(0.1)

            # Run blocking training loop in a threadpool; do not hold the
            # DB connection open longer than needed — persist after completion.
            loop_inst = TrainingLoop(llm=llm, prompt_version=prompt_version, use_react=True)

            trace = await asyncio.to_thread(
                loop_inst.run_episode, config, current_ratings=current_ratings
            )

            outcome_text = "SECURE" if trace.judge_outcome == 0 else "VULNERABLE"

            steps = [
                {
                    "type": "agent",
                    "agent": "attacker",
                    "status": "done",
                    "message": f"Task generated (tier {trace.difficulty_tier}/10)",
                },
                {
                    "type": "agent",
                    "agent": "developer",
                    "status": "done",
                    "message": f"Patch built ({len(trace.patch_text)} chars)",
                },
                {
                    "type": "agent",
                    "agent": "judge",
                    "status": "done",
                    "message": f"Outcome: {outcome_text}",
                },
            ]
            if trace.distilled_rule and trace.regression_passed:
                steps.append(
                    {
                        "type": "agent",
                        "agent": "distiller",
                        "status": "done",
                        "message": f"Rule: {trace.distilled_rule.rule_text[:80]}",
                    }
                )
            else:
                steps.append(
                    {
                        "type": "agent",
                        "agent": "distiller",
                        "status": "skip",
                        "message": "No rule distilled",
                    }
                )

            for step in steps:
                yield f"data: {json.dumps(step)}\n\n"
                await asyncio.sleep(0.1)

            yield f"data: {json.dumps({'type': 'elo', 'before': trace.elo_before, 'after': trace.elo_after})}\n\n"

            # Persist via shared helper (single source of truth)
            persist_episode(
                db,
                trace=trace,
                vulnerability_class=vulnerability_class,
                current_ratings=current_ratings,
            )

            yield f"data: {json.dumps({'type': 'complete', 'episode_id': trace.episode_id, 'outcome': trace.judge_outcome, 'rule_distilled': trace.distilled_rule is not None and trace.regression_passed, 'duration_s': trace.duration_s})}\n\n"

        except Exception as e:
            yield f"data: {json.dumps({'type': 'error', 'message': str(e)})}\n\n"
        finally:
            db.close()

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )
