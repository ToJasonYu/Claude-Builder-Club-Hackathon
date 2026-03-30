"""File I/O for findings, dashboard, and disclosure drafts."""

import json
import logging
from datetime import datetime, timezone
from pathlib import Path

from pydantic import ValidationError

from core.config import Settings
from core.models import DashboardOutput, FindingFile

log = logging.getLogger(__name__)


class IOService:
    def __init__(self, settings: Settings) -> None:
        self._findings_dir = settings.findings_dir
        self._drafts_dir = settings.drafts_dir
        self._dashboard_path = settings.dashboard_output

    def list_finding_files(self) -> list[Path]:
        if not self._findings_dir.exists():
            log.warning("findings/ directory not found at %s", self._findings_dir)
            return []
        return sorted(self._findings_dir.glob("*.json"))

    def load_finding(self, path: Path) -> FindingFile:
        """Load and validate a finding file. Raises on failure."""
        raw = path.read_text(encoding="utf-8")
        data = json.loads(raw)
        return FindingFile.model_validate(data)

    def write_dashboard(self, dashboard: DashboardOutput) -> None:
        """Overwrite dashboard_data.json (idempotent)."""
        self._dashboard_path.write_text(
            dashboard.model_dump_json(indent=2), encoding="utf-8"
        )
        log.info("Wrote %s", self._dashboard_path)

    def load_dashboard(self) -> DashboardOutput:
        """Load existing dashboard_data.json. Raises FileNotFoundError if missing."""
        raw = self._dashboard_path.read_text(encoding="utf-8")
        return DashboardOutput.model_validate_json(raw)

    def write_draft(self, slug: str, markdown_content: str) -> Path:
        """Write a disclosure draft markdown file. Returns the path."""
        self._drafts_dir.mkdir(parents=True, exist_ok=True)
        path = self._drafts_dir / f"{slug}_disclosure.md"
        path.write_text(markdown_content, encoding="utf-8")
        log.info("Wrote draft: %s", path)
        return path
