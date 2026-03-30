"""Anthropic SDK wrapper with structured output parsing and retry logic."""

import json
import logging
import time

import anthropic

from core.config import Settings
from core.models import (
    NGOProfile,
    SISEnrichment,
    SISResult,
    VulnerabilityFinding,
)
from core.prompts import (
    DISCLOSURE_SYSTEM,
    SIS_ENRICHMENT_SYSTEM,
    build_disclosure_prompt,
    build_sis_enrichment_prompt,
)

log = logging.getLogger(__name__)

_STUB_ENRICHMENT = SISEnrichment(
    mission_alignment_narrative="Mission alignment analysis unavailable.",
    urgency_note="Security remediation is recommended.",
)


class ClaudeService:
    def __init__(self, settings: Settings) -> None:
        self._client = anthropic.Anthropic(api_key=settings.anthropic_api_key)
        self._model = settings.claude_model

    def _create(self, system: str, user: str, max_tokens: int = 512) -> str:
        """Single API call with one retry on rate limit."""
        for attempt in range(2):
            try:
                response = self._client.messages.create(
                    model=self._model,
                    max_tokens=max_tokens,
                    system=system,
                    messages=[{"role": "user", "content": user}],
                )
                return response.content[0].text
            except anthropic.RateLimitError:
                if attempt == 0:
                    log.warning("Rate limited — waiting 60s before retry")
                    time.sleep(60)
                else:
                    raise
        return ""  # unreachable

    def score_enrichment(
        self,
        ngo: NGOProfile,
        mission_text: str,
        findings: list[VulnerabilityFinding],
        sis_results: list[SISResult],
    ) -> SISEnrichment:
        """One Claude call per NGO for qualitative mission-alignment context."""
        prompt = build_sis_enrichment_prompt(ngo, mission_text, findings, sis_results)
        try:
            raw = self._create(SIS_ENRICHMENT_SYSTEM, prompt, max_tokens=512)
            # Strip markdown fences if present
            raw = raw.strip()
            if raw.startswith("```"):
                raw = raw.split("```")[1]
                if raw.startswith("json"):
                    raw = raw[4:]
            return SISEnrichment.model_validate_json(raw)
        except (json.JSONDecodeError, ValueError, anthropic.APIError) as exc:
            log.warning("[%s] Enrichment failed (%s) — using stub", ngo.slug, exc)
            return _STUB_ENRICHMENT

    def draft_disclosure(
        self,
        ngo: NGOProfile,
        mission_text: str,
        findings: list[VulnerabilityFinding],
        sis_results: list[SISResult],
        enrichment: SISEnrichment,
    ) -> str:
        """One Claude call per NGO for the full Markdown disclosure email."""
        prompt = build_disclosure_prompt(
            ngo, mission_text, findings, sis_results, enrichment
        )
        return self._create(DISCLOSURE_SYSTEM, prompt, max_tokens=3000)
