"""Application configuration via pydantic-settings."""

from __future__ import annotations

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

    api_host: str = "0.0.0.0"
    api_port: int = 8000

    database_url: str = "postgresql://postgres:password@localhost:5432/coevolve"
    redis_url: str = "redis://localhost:6379"

    llm_provider: str = "anthropic"
    llm_model: str = "claude-sonnet-4-5"
    llm_small_model: str = "claude-haiku-4-5"

    anthropic_api_key: str = ""
    openai_api_key: str = ""
    openrouter_api_key: str = ""
    gemini_api_key: str = ""
    huggingface_api_key: str = ""
    groq_api_key: str = ""

    jwt_secret: str = "change-me"
    log_level: str = "INFO"


@lru_cache
def get_settings() -> Settings:
    return Settings()
