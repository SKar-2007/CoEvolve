"""Main FastAPI application with full CRUD endpoints."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException, Query
from sqlalchemy import func
from sqlalchemy.orm import Session

from .config import get_settings
from .database import Base, get_db, get_engine, get_session_factory
from .models import EloRecord, EpisodeRecord, PromptRecord, RuleRecord
from .schemas import (
    EloHistoryResponse,
    EpisodeCreate,
    EpisodeRead,
    MetricsSnapshot,
    PromptDiffResponse,
    PromptVersionRead,
    RuleRead,
    TrainingJobListResponse,
    TrainingJobRead,
    TrainingRunRequest,
    TrainingRunResponse,
)
from .task_queue import TaskQueue, TrainingJob

settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    Base.metadata.create_all(get_engine())
    _seed_elo()
    yield


app = FastAPI(
    title="CoEvolve Sandbox API",
    version="0.1.0",
    description="Automated Adversarial-Training-as-a-Service framework for autonomous coding agents",
    lifespan=lifespan,
)

# Global task queue instance
_task_queue: TaskQueue | None = None


def get_task_queue() -> TaskQueue:
    global _task_queue
    if _task_queue is None:
        _task_queue = TaskQueue(redis_url=settings.redis_url)
    return _task_queue


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
@app.post("/episodes", response_model=EpisodeRead, status_code=201)
def create_episode(body: EpisodeCreate, db: Session = Depends(get_db)) -> EpisodeRecord:
    ep = EpisodeRecord(
        status="pending",
        vulnerability_class=body.vulnerability_classes[0] if body.vulnerability_classes else "SQLi",
    )
    db.add(ep)
    db.commit()
    db.refresh(ep)
    return ep


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


# ---------------------------------------------------------------------------
# Prompts
# ---------------------------------------------------------------------------
@app.get("/prompts/current", response_model=PromptVersionRead)
def current_prompt(db: Session = Depends(get_db)) -> PromptVersionRead:
    record = db.query(PromptRecord).order_by(PromptRecord.version.desc()).first()
    if not record:
        raise HTTPException(404, "No prompts found")
    return PromptVersionRead(
        version=record.version,
        rules_count=len(record.rules or []),
        created_at=record.created_at,
    )


@app.get("/prompts/history", response_model=list[PromptVersionRead])
def prompt_history(
    limit: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
) -> list[PromptVersionRead]:
    records = db.query(PromptRecord).order_by(PromptRecord.version.desc()).limit(limit).all()
    return [
        PromptVersionRead(
            version=r.version,
            rules_count=len(r.rules or []),
            created_at=r.created_at,
        )
        for r in records
    ]


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


@app.get("/rules/{rule_id}", response_model=RuleRead)
def get_rule(rule_id: str, db: Session = Depends(get_db)) -> RuleRecord:
    rule = db.get(RuleRecord, rule_id)
    if not rule:
        raise HTTPException(404, "Rule not found")
    return rule


# ---------------------------------------------------------------------------
# Prompt Diffs
# ---------------------------------------------------------------------------
@app.get("/prompts/diff/{v1}/{v2}", response_model=PromptDiffResponse)
def prompt_diff(v1: int, v2: int, db: Session = Depends(get_db)) -> PromptDiffResponse:
    from ..evolution.store import PromptStore

    store = PromptStore()
    diff = store.diff(v1, v2)
    return PromptDiffResponse(
        version_a=v1,
        version_b=v2,
        added_rules=diff.get("added", []),
        removed_rules=diff.get("removed", []),
    )


# ---------------------------------------------------------------------------
# Elo History
# ---------------------------------------------------------------------------
@app.get("/elo/history", response_model=EloHistoryResponse)
def elo_history(db: Session = Depends(get_db)) -> EloHistoryResponse:
    record = db.get(EloRecord, "global")
    return EloHistoryResponse(
        history=[],  # TODO: store history in DB
        current={
            "attacker": record.attacker_rating if record else 1500.0,
            "developer": record.developer_rating if record else 1500.0,
        },
    )


# ---------------------------------------------------------------------------
# Episode Stop
# ---------------------------------------------------------------------------
@app.post("/episodes/{episode_id}/stop", response_model=EpisodeRead)
def stop_episode(episode_id: str, db: Session = Depends(get_db)) -> EpisodeRecord:
    ep = db.get(EpisodeRecord, episode_id)
    if not ep:
        raise HTTPException(404, "Episode not found")
    if ep.status in ("completed", "failed"):
        raise HTTPException(400, "Episode already finished")
    ep.status = "failed"
    ep.error = "Stopped by user"
    db.commit()
    db.refresh(ep)
    return ep


# ---------------------------------------------------------------------------
# Training Loop
# ---------------------------------------------------------------------------
@app.post("/training/run", response_model=TrainingRunResponse)
def run_training_episode(
    body: TrainingRunRequest, db: Session = Depends(get_db)
) -> TrainingRunResponse:
    """Execute one co-evolutionary training episode."""
    from ..agents.llm import build_client
    from ..agents.training_loop import EpisodeConfig, TrainingLoop

    # Get current Elo
    elo_record = db.get(EloRecord, "global")
    current_ratings = (
        (elo_record.attacker_rating, elo_record.developer_rating)
        if elo_record
        else (1500.0, 1500.0)
    )

    # Get current prompt version
    latest_prompt = db.query(PromptRecord).order_by(PromptRecord.version.desc()).first()
    prompt_version = latest_prompt.version if latest_prompt else 0

    # Build LLM client
    settings = get_settings()
    provider = "anthropic" if settings.anthropic_api_key else "openai"
    llm = build_client(provider)

    # Build and run training loop
    loop = TrainingLoop(llm=llm, prompt_version=prompt_version)
    config = EpisodeConfig(
        vulnerability_class=body.vulnerability_class,
        language=body.language,
        context_hint=body.context_hint,
        max_retries=body.max_retries,
    )
    trace = loop.run_episode(config, current_ratings=current_ratings)

    # Persist episode to DB
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

    # Update global Elo
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

    # Record distilled rule if any
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
# Async Training Jobs (Redis queue)
# ---------------------------------------------------------------------------
@app.post("/training/async", response_model=TrainingJobRead, status_code=202)
def enqueue_training_job(body: TrainingRunRequest) -> TrainingJobRead:
    """Enqueue a training episode for background execution."""
    queue = get_task_queue()
    job = TrainingJob(
        vulnerability_class=body.vulnerability_class,
        language=body.language,
        context_hint=body.context_hint,
        max_retries=body.max_retries,
    )
    queue.enqueue(job)
    return TrainingJobRead(
        job_id=job.job_id,
        status=job.status.value,
        vulnerability_class=job.vulnerability_class,
        created_at=job.created_at,
    )


@app.get("/training/jobs", response_model=TrainingJobListResponse)
def list_training_jobs(limit: int = Query(50, ge=1, le=200)) -> TrainingJobListResponse:
    """List recent training jobs."""
    queue = get_task_queue()
    jobs = queue.list_jobs(limit=limit)
    return TrainingJobListResponse(
        jobs=[
            TrainingJobRead(
                job_id=j.job_id,
                status=j.status.value,
                vulnerability_class=j.vulnerability_class,
                created_at=j.created_at,
                started_at=j.started_at,
                completed_at=j.completed_at,
                error=j.error or None,
            )
            for j in jobs
        ],
        queue_length=queue.queue_length(),
    )


@app.get("/training/jobs/{job_id}", response_model=TrainingJobRead)
def get_training_job(job_id: str) -> TrainingJobRead:
    """Get status of a specific training job."""
    queue = get_task_queue()
    job = queue.get_job(job_id)
    if not job:
        raise HTTPException(404, "Job not found")
    return TrainingJobRead(
        job_id=job.job_id,
        status=job.status.value,
        vulnerability_class=job.vulnerability_class,
        created_at=job.created_at,
        started_at=job.started_at,
        completed_at=job.completed_at,
        result=job.result if job.result else None,
        error=job.error or None,
    )
