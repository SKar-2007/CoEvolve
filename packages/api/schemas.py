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


class TrainingRunRequest(BaseModel):
    """Request to run a training episode via the training loop."""

    vulnerability_class: str = "SQLi"
    language: str = "python"
    context_hint: str = ""
    max_retries: int = 3


class TrainingRunResponse(BaseModel):
    """Response from a training episode run."""

    episode_id: str
    status: str
    difficulty_tier: int
    judge_outcome: int
    judge_verdict: dict = Field(default_factory=dict)
    rule_distilled: bool = False
    rule_text: str | None = None
    regression_passed: bool = True
    elo_before: dict[str, float] = Field(default_factory=dict)
    elo_after: dict[str, float] = Field(default_factory=dict)
    duration_s: float = 0.0
    error: str | None = None


class PromptDiffResponse(BaseModel):
    """Diff between two prompt versions."""

    version_a: int
    version_b: int
    added_rules: list[str] = Field(default_factory=list)
    removed_rules: list[str] = Field(default_factory=list)


class EloHistoryResponse(BaseModel):
    """Historical Elo ratings."""

    history: list[dict] = Field(default_factory=list)
    current: dict[str, float] = Field(default_factory=dict)


class TrainingJobRead(BaseModel):
    """Training job status."""

    job_id: str
    status: str
    vulnerability_class: str = "SQLi"
    created_at: float = 0.0
    started_at: float | None = None
    completed_at: float | None = None
    result: dict | None = None
    error: str | None = None


class TrainingJobListResponse(BaseModel):
    """List of training jobs with queue info."""

    jobs: list[TrainingJobRead] = Field(default_factory=list)
    queue_length: int = 0
