"""SQLAlchemy ORM models for the CoEvolve Sandbox API."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    Column,
    DateTime,
    Enum,
    Float,
    Integer,
    JSON,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column

from .database import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _uuid() -> str:
    return str(uuid.uuid4())


class EpisodeRecord(Base):
    __tablename__ = "episodes"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)

    @property
    def episode_id(self) -> str:
        return self.id

    status: Mapped[str] = mapped_column(
        Enum("pending", "creating", "executing", "evaluating", "completed", "failed",
             name="episode_status"),
        default="pending",
    )
    vulnerability_class: Mapped[str | None] = mapped_column(String(64), nullable=True)
    difficulty_tier: Mapped[int | None] = mapped_column(Integer, nullable=True)
    outcome: Mapped[int | None] = mapped_column(Integer, nullable=True)  # 0=secure, 1=vuln
    task_description: Mapped[str | None] = mapped_column(Text, nullable=True)
    patch_text: Mapped[str | None] = mapped_column(Text, nullable=True)
    exploit_payload: Mapped[str | None] = mapped_column(Text, nullable=True)
    container_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    judge_verdict: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    metadata_: Mapped[dict | None] = mapped_column("metadata", JSON, nullable=True)
    attacker_rating: Mapped[float] = mapped_column(Float, default=1500.0)
    developer_rating: Mapped[float] = mapped_column(Float, default=1500.0)
    prompt_version: Mapped[int] = mapped_column(Integer, default=1)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class PromptRecord(Base):
    __tablename__ = "prompts"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    version: Mapped[int] = mapped_column(Integer, unique=True, nullable=False)
    base_prompt: Mapped[str] = mapped_column(Text, default="")
    rules: Mapped[list] = mapped_column(JSON, default=list)
    commit_message: Mapped[str] = mapped_column(Text, default="")
    parent_version: Mapped[int | None] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)


class RuleRecord(Base):
    __tablename__ = "rules"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    rule_text: Mapped[str] = mapped_column(Text, nullable=False)
    vulnerability_class: Mapped[str] = mapped_column(String(64), nullable=False)
    source_pattern: Mapped[str] = mapped_column(Text, default="")
    recommended_fix: Mapped[str] = mapped_column(Text, default="")
    source_trace_id: Mapped[str] = mapped_column(String(64), default="")
    prompt_version: Mapped[int] = mapped_column(Integer, default=1)
    approved: Mapped[bool] = mapped_column(default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)


class EloRecord(Base):
    __tablename__ = "elo_ratings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    attacker_rating: Mapped[float] = mapped_column(Float, default=1500.0)
    developer_rating: Mapped[float] = mapped_column(Float, default=1500.0)
    episodes_played: Mapped[int] = mapped_column(Integer, default=0)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
