"""Pydantic schemas for request/response payloads."""

from datetime import datetime
from typing import Optional

from enum import Enum

from pydantic import BaseModel, ConfigDict, Field


class EpisodeStatus(str, Enum):
    PENDING = "pending"
    COMPLETED = "completed"
    FAILED = "failed"


class EpisodeRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    episode_id: str
    status: EpisodeStatus
    vulnerability_class: Optional[str] = None
    difficulty_tier: Optional[int] = None
    outcome: Optional[int] = None
    task_description: Optional[str] = None
    patch_text: Optional[str] = None
    judge_verdict: Optional[dict] = None
    error: Optional[str] = None
    attacker_rating: float = 1500.0
    developer_rating: float = 1500.0
    prompt_version: int = 1
    created_at: datetime


class MetricsSnapshot(BaseModel):
    total_episodes: int = 0
    secure_rate: float = 0.0
    # Deprecated typo alias — kept for backward compatibility. Use `elo`.
    epo: dict[str, float] = Field(default_factory=dict)
    elo: dict[str, float] = Field(default_factory=dict)
    rules_count: int = 0


class TrainingRunRequest(BaseModel):
    vulnerability_class: str = "SQLi"
    language: str = "python"
    context_hint: str = ""
    max_retries: int = 3
    use_react: bool = False


class TrainingRunResponse(BaseModel):
    episode_id: str
    status: str
    difficulty_tier: int
    judge_outcome: int
    judge_verdict: dict = Field(default_factory=dict)
    rule_distilled: bool = False
    rule_text: Optional[str] = None
    regression_passed: bool = True
    elo_before: dict[str, float] = Field(default_factory=dict)
    elo_after: dict[str, float] = Field(default_factory=dict)
    duration_s: float = 0.0
    error: Optional[str] = None


class RuleRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    rule_text: str
    vulnerability_class: str
    source_pattern: str
    recommended_fix: str
    approved: bool
    created_at: datetime


class EloHistoryResponse(BaseModel):
    history: list[dict] = Field(default_factory=list)
    current: dict[str, float] = Field(default_factory=dict)


class PromptRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    version: int
    base_prompt: str
    rules: list = Field(default_factory=list)
    commit_message: str = ""
    parent_version: Optional[int] = None
    created_at: datetime


class PromptDiffResponse(BaseModel):
    from_version: int
    to_version: int
    added: list[str] = Field(default_factory=list)
    removed: list[str] = Field(default_factory=list)


class RuleDetailRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    rule_text: str
    vulnerability_class: str
    source_pattern: str
    recommended_fix: str
    source_trace_id: str
    prompt_version: int
    approved: bool
    created_at: datetime


class VulnerabilityCoverage(BaseModel):
    vulnerability_class: str
    total_episodes: int = 0
    detected_count: int = 0
    secure_count: int = 0
    coverage_rate: float = 0.0


class EpisodeStopResponse(BaseModel):
    episode_id: str
    status: str
    message: str


class TrainingJobEnqueueRequest(BaseModel):
    vulnerability_class: str = "SQLi"
    language: str = "python"
    context_hint: str = ""
    max_retries: int = 3
    use_react: bool = False


class TrainingJobRead(BaseModel):
    job_id: str
    status: str
    vulnerability_class: str = "SQLi"
    language: str = "python"
    context_hint: str = ""
    max_retries: int = 3
    use_react: bool = False
    queue_position: Optional[int] = None
    created_at: float = 0.0
    started_at: Optional[float] = None
    completed_at: Optional[float] = None
    result: dict = Field(default_factory=dict)
    error: str = ""
