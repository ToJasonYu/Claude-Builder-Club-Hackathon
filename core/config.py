from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    anthropic_api_key: str = Field(..., description="ANTHROPIC_API_KEY")
    claude_model: str = Field(default="claude-opus-4-6")
    findings_dir: Path = Field(default=Path("findings"))
    drafts_dir: Path = Field(default=Path("outreach/drafts"))
    dashboard_output: Path = Field(default=Path("dashboard_data.json"))
    web_fetch_timeout: int = Field(default=10)
    max_mission_chars: int = Field(default=2000)


@lru_cache
def get_settings() -> Settings:
    return Settings()
