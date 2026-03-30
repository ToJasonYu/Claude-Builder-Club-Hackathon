"""Agent 1: Social Impact Scoring — reads findings/, calculates SIS, writes dashboard_data.json."""

import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path

from pydantic import ValidationError

from core.config import get_settings
from core.models import (
    DashboardOutput,
    DashboardSummary,
    FailureRecord,
    FindingDashboardEntry,
    NGODashboardEntry,
)
from core.scoring import calculate_all_sis
from services.claude_service import ClaudeService
from services.io_service import IOService
from services.web_service import WebService

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger(__name__)


def main() -> None:
    settings = get_settings()
    io = IOService(settings)
    web = WebService(settings)
    claude = ClaudeService(settings)

    finding_files = io.list_finding_files()
    if not finding_files:
        log.warning("No finding files found in %s — nothing to process.", settings.findings_dir)
        return

    log.info("Found %d finding file(s) to process.", len(finding_files))

    ngo_entries: list[NGODashboardEntry] = []
    failures: list[FailureRecord] = []

    for path in finding_files:
        log.info("[%s] Loading...", path.name)
        try:
            finding_file = io.load_finding(path)
        except (json.JSONDecodeError, ValidationError) as exc:
            log.error("[%s] Validation failed: %s", path.name, exc)
            failures.append(FailureRecord(
                file=str(path),
                error=str(exc)[:500],
                timestamp=datetime.now(timezone.utc),
            ))
            continue

        ngo = finding_file.ngo
        slug = ngo.slug
        log.info("[%s] Loaded %d finding(s) for %s", slug, len(finding_file.findings), ngo.name)

        # Resolve mission text
        if ngo.mission_statement:
            mission_text = ngo.mission_statement
            mission_source = "finding_file"
            log.info("[%s] Using mission statement from finding file.", slug)
        else:
            log.info("[%s] Fetching mission from %s...", slug, ngo.website_url)
            mission_text, mission_source = web.fetch_mission(ngo.website_url)
            log.info("[%s] Mission source: %s", slug, mission_source)

        # Calculate SIS (pure Python — deterministic)
        sis_results = calculate_all_sis(finding_file)
        headline_sis = max(r.total_sis for r in sis_results)
        log.info("[%s] SIS scores: %s (headline: %d)", slug,
                 [r.total_sis for r in sis_results], headline_sis)

        # Claude enrichment call (one per NGO)
        log.info("[%s] Calling Claude for mission-alignment enrichment...", slug)
        enrichment = claude.score_enrichment(ngo, mission_text, finding_file.findings, sis_results)
        log.info("[%s] Enrichment complete.", slug)

        # Build finding dashboard entries
        sis_by_id = {r.finding_id: r for r in sis_results}
        finding_entries = [
            FindingDashboardEntry(
                id=f.id,
                title=f.title,
                severity=f.severity,
                cvss_score=f.cvss_score,
                vulnerability_type=f.vulnerability_type,
                affected_component=f.affected_component,
                sis=sis_by_id[f.id],
            )
            for f in finding_file.findings
            if f.id in sis_by_id
        ]

        ngo_entries.append(NGODashboardEntry(
            slug=slug,
            name=ngo.name,
            website_url=str(ngo.website_url),
            population_served=ngo.population_served,
            contact_email=str(ngo.contact_email),
            headline_sis=headline_sis,
            mission_alignment_narrative=enrichment.mission_alignment_narrative,
            urgency_note=enrichment.urgency_note,
            mission_source=mission_source,
            processed_at=datetime.now(timezone.utc),
            findings=finding_entries,
        ))

    # Build summary
    all_findings = [f for entry in ngo_entries for f in entry.findings]
    total_sis_values = [f.sis.total_sis for f in all_findings]
    avg_sis = round(sum(total_sis_values) / len(total_sis_values), 1) if total_sis_values else 0.0

    summary = DashboardSummary(
        total_ngos=len(ngo_entries),
        total_findings=len(all_findings),
        critical_count=sum(1 for f in all_findings if f.severity == "critical"),
        high_count=sum(1 for f in all_findings if f.severity == "high"),
        avg_sis=avg_sis,
        ngos_with_drafts=sum(1 for e in ngo_entries if e.disclosure_draft_path is not None),
    )

    dashboard = DashboardOutput(
        generated_at=datetime.now(timezone.utc),
        summary=summary,
        ngos=ngo_entries,
        failures=failures,
    )

    io.write_dashboard(dashboard)
    log.info(
        "Done. %d NGO(s) processed, %d failure(s). Dashboard: %s",
        len(ngo_entries),
        len(failures),
        settings.dashboard_output,
    )


if __name__ == "__main__":
    main()
