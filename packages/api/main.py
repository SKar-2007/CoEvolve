"""Main FastAPI application with full CRUD endpoints."""

from __future__ import annotations

from fastapi import Depends, FastAPI, HTTPException, Query
from sqlalchemy import func
from sqlalchemy.orm import Session

from .config import get_settings
from .database import Base, get_db, get_engine, get_session_factory
from .models import EloRecord, EpisodeRecord, PromptRecord, RuleRecord
from .schemas import (
    EpisodeCreate,
    EpisodeRead,
    MetricsSnapshot,
    PromptVersionRead,
    RuleRead,
)

settings = get_settings()

app = FastAPI(
    title="CoEvolve Sandbox API",
    version="0.1.0",
    description="Automated Adversarial-Training-as-a-Service framework for autonomous coding agents",
)


@app.on_event("startup")
def startup() -> None:
    Base.metadata.create_all(get_engine())
    _seed_elo()


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
    secure = (
        db.query(func.count(EpisodeRecord.id))
        .filter(EpisodeRecord.outcome == 0)
        .scalar()
        or 0
    )
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
    record = (
        db.query(PromptRecord)
        .order_by(PromptRecord.version.desc())
        .first()
    )
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
    records = (
        db.query(PromptRecord)
        .order_by(PromptRecord.version.desc())
        .limit(limit)
        .all()
    )
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
