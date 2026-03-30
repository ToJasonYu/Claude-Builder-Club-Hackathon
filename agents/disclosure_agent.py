"""Agent 2: Disclosure draft generation — reads dashboard, drafts emails, updates dashboard."""

import logging
import sys
from datetime import datetime, timezone

from pydantic import ValidationError

from core.config import get_settings
from core.models import SISEnrichment
from services.claude_service import ClaudeService
from services.io_service import IOService

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger(__name__)


def main() -> None:
    settings = get_settings()
    io = IOService(settings)
    claude = ClaudeService(settings)

    # Load existing dashboard (must run sis_agent first)
    try:
        dashboard = io.load_dashboard()
    except FileNotFoundError:
        log.error(
            "dashboard_data.json not found at %s. Run sis_agent first.",
            settings.dashboard_output,
        )
        sys.exit(1)

    log.info(
        "Loaded dashboard: %d NGO(s), %d total findings.",
        len(dashboard.ngos),
        dashboard.summary.total_findings,
    )

    drafts_written = 0
    failures = 0

    for ngo_entry in dashboard.ngos:
        slug = ngo_entry.slug
        log.info("[%s] Drafting disclosure email for %s...", slug, ngo_entry.name)

        # Reload the original finding file to get remediation_code blocks
        finding_path = settings.findings_dir / f"{slug}.json"
        try:
            finding_file = io.load_finding(finding_path)
        except (FileNotFoundError, ValidationError) as exc:
            log.error("[%s] Could not reload finding file: %s — skipping draft", slug, exc)
            failures += 1
            continue

        # Reconstruct SIS results from dashboard data (already computed)
        from core.models import SISResult, SISBreakdown
        sis_results = [
            SISResult(
                finding_id=fe.sis.finding_id,
                population_score=fe.sis.population_score,
                data_sensitivity_score=fe.sis.data_sensitivity_score,
                ease_of_remediation_score=fe.sis.ease_of_remediation_score,
                total_sis=fe.sis.total_sis,
                breakdown=fe.sis.breakdown,
            )
            for fe in ngo_entry.findings
        ]

        # Reconstruct enrichment from dashboard data
        enrichment = SISEnrichment(
            mission_alignment_narrative=ngo_entry.mission_alignment_narrative,
            urgency_note=ngo_entry.urgency_note,
        )

        # Use stored mission text (from dashboard) or fallback
        mission_text = (
            finding_file.ngo.mission_statement
            or ngo_entry.mission_alignment_narrative  # fallback
        )

        # Call Claude for the full disclosure draft
        try:
            markdown = claude.draft_disclosure(
                ngo=finding_file.ngo,
                mission_text=mission_text,
                findings=finding_file.findings,
                sis_results=sis_results,
                enrichment=enrichment,
            )
        except Exception as exc:
            log.error("[%s] Claude draft call failed: %s — skipping", slug, exc)
            failures += 1
            continue

        # Save draft
        draft_path = io.write_draft(slug, markdown)
        ngo_entry.disclosure_draft_path = str(draft_path)
        drafts_written += 1
        log.info("[%s] Draft saved: %s", slug, draft_path)

    # Update dashboard with draft paths and ngos_with_drafts count
    dashboard.summary.ngos_with_drafts = drafts_written
    dashboard.generated_at = datetime.now(timezone.utc)
    io.write_dashboard(dashboard)

    log.info(
        "Done. %d draft(s) written, %d failure(s). Dashboard updated: %s",
        drafts_written,
        failures,
        settings.dashboard_output,
    )


if __name__ == "__main__":
    main()
