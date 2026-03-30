"""All Claude prompt templates in one place for easy iteration."""

import json
from typing import Any

from core.models import FindingFile, NGOProfile, SISEnrichment, SISResult, VulnerabilityFinding
from core.scoring import (
    DATA_SENSITIVITY_LABELS,
    EASE_LABELS,
    POPULATION_LABELS,
)

# ---------------------------------------------------------------------------
# SIS Enrichment prompts
# ---------------------------------------------------------------------------

SIS_ENRICHMENT_SYSTEM = """\
You are a security researcher helping NGOs understand their vulnerability exposure \
in plain language. You write clearly for non-technical program directors, not IT staff. \
Always respond with valid JSON matching the schema provided. Do not add commentary \
outside the JSON."""


def build_sis_enrichment_prompt(
    ngo: NGOProfile,
    mission_text: str,
    findings: list[VulnerabilityFinding],
    sis_results: list[SISResult],
) -> str:
    sis_by_id = {r.finding_id: r for r in sis_results}
    findings_summary = [
        {
            "id": f.id,
            "title": f.title,
            "severity": f.severity,
            "sis_total": sis_by_id[f.id].total_sis if f.id in sis_by_id else "N/A",
            "data_sensitivity": f.data_sensitivity,
            "ease_of_remediation": f.ease_of_remediation,
        }
        for f in findings
    ]
    return f"""\
I have computed a Social Impact Score (SIS, 1–100) for vulnerabilities found at the \
following NGO. Please provide a brief mission-alignment analysis.

NGO: {ngo.name}
Population served: {POPULATION_LABELS[ngo.population_served]}
Mission: {mission_text}

Vulnerabilities and pre-computed SIS scores:
{json.dumps(findings_summary, indent=2)}

Respond ONLY with this JSON structure (no markdown fences, no preamble):
{{
  "mission_alignment_narrative": "<1–2 sentences: how does the worst vulnerability \
directly threaten this NGO's ability to serve its population?>",
  "urgency_note": "<1 sentence: plain-language urgency for a non-technical program \
director, referencing the population at risk>"
}}"""


# ---------------------------------------------------------------------------
# Disclosure draft prompts
# ---------------------------------------------------------------------------

DISCLOSURE_SYSTEM = """\
You are a compassionate security researcher writing a responsible disclosure email \
to a nonprofit organization. Your tone is: empathetic, collaborative, \
non-threatening, and accessible to non-technical readers. You never use accusatory \
language. You treat the organization as a partner, not a target. Frame everything \
around their mission and the people they serve.

Structure the output as a complete Markdown document with these exact sections, \
in order:
1. ## Subject: (email subject line)
2. Greeting paragraph — acknowledge their mission and the importance of the work
3. ## Security Nutrition Label (ASCII box as specified)
4. ## Overview — 1–2 paragraphs in plain language about the overall situation
5. ## Vulnerability Details — one ### subsection per finding with plain-language \
   description and mission impact
6. ## Remediation Steps — include the provided code/config artifact in a fenced \
   code block
7. ## Next Steps — offer to assist, provide timeline expectations (90-day window)
8. ## Closing — warm, collaborative sign-off from "Volunteer Security Research Team"

Output ONLY the Markdown document. Do not add any preamble or postamble."""


def build_disclosure_prompt(
    ngo: NGOProfile,
    mission_text: str,
    findings: list[VulnerabilityFinding],
    sis_results: list[SISResult],
    enrichment: SISEnrichment,
) -> str:
    sis_by_id = {r.finding_id: r for r in sis_results}
    headline_sis = max((r.total_sis for r in sis_results), default=0)
    worst = max(sis_results, key=lambda r: r.total_sis, default=None)

    data_label = DATA_SENSITIVITY_LABELS.get(
        worst.breakdown.data_sensitivity, "Sensitive Data"
    ) if worst else "Sensitive Data"
    pop_label = POPULATION_LABELS.get(ngo.population_served, str(ngo.population_served))
    ease_label = EASE_LABELS.get(
        worst.breakdown.ease_of_remediation, "Unknown"
    ) if worst else "Unknown"

    nutrition_label = f"""\
┌─────────────────────────────────────┐
│  SECURITY NUTRITION LABEL           │
│  {ngo.name:<35} │
├─────────────────────────────────────┤
│  Overall Impact Score: {headline_sis:>3}/100       │
│  Data at Risk:  {data_label:<21} │
│  People at Risk: {pop_label:<20} │
│  Fix Complexity: {ease_label:<20} │
│  Findings: {len(findings):<27} │
└─────────────────────────────────────┘"""

    findings_detail = []
    for f in findings:
        r = sis_by_id.get(f.id)
        findings_detail.append({
            "id": f.id,
            "title": f.title,
            "severity": f.severity,
            "description": f.description,
            "evidence_summary": f.evidence_summary,
            "sis_total": r.total_sis if r else "N/A",
            "data_sensitivity": DATA_SENSITIVITY_LABELS.get(f.data_sensitivity, f.data_sensitivity),
            "ease_of_remediation": EASE_LABELS.get(f.ease_of_remediation, f.ease_of_remediation),
            "remediation_code": f.remediation_code,
            "remediation_type": f.remediation_type,
            "references": [str(ref) for ref in f.references],
        })

    return f"""\
Draft a responsible disclosure email for the following NGO.

NGO: {ngo.name}
Mission: {mission_text}
Contact: {ngo.contact_email}

Mission impact summary (use this framing):
{enrichment.mission_alignment_narrative}
{enrichment.urgency_note}

Security Nutrition Label to embed verbatim in section 3:
{nutrition_label}

Findings to disclose:
{json.dumps(findings_detail, indent=2, default=str)}"""
