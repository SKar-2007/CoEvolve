"""Pydantic schemas for request/response payloads."""

from __future__ import annotations

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field


class EpisodeStatus(str, Enum):
    PENDING = "pending"
    CREATING = "creating"
    EXECUTING = "executing"
    EVALUATING = "evaluating"
    COMPLETED = "completed"
    FAILED = "failed"


class EpisodeCreate(BaseModel):
    vulnerability_classes: list[str] = Field(default=["SQLi"])
    max_duration_minutes: int = Field(default=30, ge=1, le=120)


class EpisodeRead(BaseModel):
    episode_id: str
    status: EpisodeStatus
    vulnerability_class: str | None = None
    difficulty_tier: int | None = None
    outcome: int | None = None
    task_description: str | None = None
    patch_text: str | None = None
    container_id: str | None = None
    error: str | None = None
    attacker_rating: float = 1500.0
    developer_rating: float = 1500.0
    prompt_version: int = 1
    created_at: datetime

    class Config:
        from_attributes = True


class PromptVersionRead(BaseModel):
    version: int
    rules_count: int
    created_at: datetime
    diff: dict[str, list[str]] | None = None


class RuleRead(BaseModel):
    rule_id: str
    rule_text: str
    vulnerability_class: str
    version: int

    class Config:
        from_attributes = True


class MetricsSnapshot(BaseModel):
    total_episodes: int = 0
    secure_rate: float = 0.0
    epo: dict[str, float] = Field(default_factory=dict)
    rules_count: int = 0
