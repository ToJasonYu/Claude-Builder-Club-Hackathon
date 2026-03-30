"""Groq LLM wrapper with structured output parsing and retry logic."""

import json
import logging
import time

import groq as groq_sdk

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
        self._client = groq_sdk.Groq(api_key=settings.groq_api_key)
        self._model = settings.groq_model

    def _create(self, system: str, user: str, max_tokens: int = 512) -> str:
        """Single API call with one retry on rate limit."""
        for attempt in range(2):
            try:
                response = self._client.chat.completions.create(
                    model=self._model,
                    max_tokens=max_tokens,
                    messages=[
                        {"role": "system", "content": system},
                        {"role": "user", "content": user},
                    ],
                )
                return response.choices[0].message.content
            except groq_sdk.RateLimitError:
                if attempt == 0:
                    log.warning("Rate limited — waiting 60s before retry")
                    time.sleep(60)
                else:
                    raise
        return ""

    def score_enrichment(
        self,
        ngo: NGOProfile,
        mission_text: str,
        findings: list[VulnerabilityFinding],
        sis_results: list[SISResult],
    ) -> SISEnrichment:
        """One LLM call per NGO for qualitative mission-alignment context."""
        prompt = build_sis_enrichment_prompt(ngo, mission_text, findings, sis_results)
        try:
            raw = self._create(SIS_ENRICHMENT_SYSTEM, prompt, max_tokens=1024)
            raw = raw.strip()
            if raw.startswith("```"):
                raw = raw.split("```")[1]
                if raw.startswith("json"):
                    raw = raw[4:]
            return SISEnrichment.model_validate_json(raw)
        except (json.JSONDecodeError, ValueError, groq_sdk.APIError) as exc:
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
        """One LLM call per NGO for the full Markdown disclosure email."""
        prompt = build_disclosure_prompt(
            ngo, mission_text, findings, sis_results, enrichment
        )
        return self._create(DISCLOSURE_SYSTEM, prompt, max_tokens=3000)
