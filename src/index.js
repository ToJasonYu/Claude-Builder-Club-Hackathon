// ============================================================================
// NGO-Guardian — Main Pipeline Orchestrator
// Discovery → Fingerprint → Scan → Score → Report
// ============================================================================

import { writeFileSync, mkdirSync, existsSync } from "fs";
import { join, dirname } from "path";
import { fileURLToPath } from "url";

import { discoverNGOs } from "./search/discovery.js";
import { fingerprintAll } from "./search/fingerprint.js";
import { scanAll } from "./scan/detector.js";
import { scoreAll } from "./scan/severity.js";
import { generateVibeCheckReport, generateFixArtifact, writeReports } from "./report/generator.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const PROJECT_ROOT = join(__dirname, "..");

// ─── Banner ──────────────────────────────────────────────────────────────────

function printBanner() {
  console.log(`
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║   🛡️  NGO-GUARDIAN — Autonomous Safety Net for Non-Profits   ║
║                                                              ║
║   "We are Guardians, not Hunters."                           ║
║                                                              ║
║   Pipeline: Discovery → Fingerprint → Scan → Score → Report ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
  `);
}

// ─── Pipeline ────────────────────────────────────────────────────────────────

async function runPipeline() {
  const startTime = Date.now();
  printBanner();

  // Stage 1: Discovery
  console.log("━".repeat(60));
  console.log("  STAGE 1/5 — AGENTIC SEARCH & DISCOVERY");
  console.log("━".repeat(60));
  const targets = discoverNGOs({ sector: "all" });

  // Stage 2: Fingerprint
  console.log("━".repeat(60));
  console.log("  STAGE 2/5 — TECH STACK FINGERPRINTING");
  console.log("━".repeat(60));
  const fingerprinted = fingerprintAll(targets);

  // Stage 3: Vulnerability Detection
  console.log("━".repeat(60));
  console.log("  STAGE 3/5 — VULNERABILITY DETECTION");
  console.log("━".repeat(60));
  const scanned = scanAll(fingerprinted);

  // Stage 4: Severity Scoring
  console.log("━".repeat(60));
  console.log("  STAGE 4/5 — VIBE RISK SCORING");
  console.log("━".repeat(60));
  const scored = scoreAll(scanned);

  // Stage 5: Report Generation
  console.log("━".repeat(60));
  console.log("  STAGE 5/5 — REPORT & FIX ARTIFACT GENERATION");
  console.log("━".repeat(60));

  // Write data/targets.json
  const dataDir = join(PROJECT_ROOT, "data");
  if (!existsSync(dataDir)) {
    mkdirSync(dataDir, { recursive: true });
  }

  const targetsJson = scored.map(t => ({
    name: t.name,
    domain: t.domain,
    sector: t.sector,
    mission: t.mission,
    subdomains: t.subdomains,
    endpoints: t.endpoints,
    techStack: {
      platform: t.fingerprint?.vibeStack?.platform || null,
      framework: t.fingerprint?.vibeStack?.framework || null,
      isVibeCoded: t.fingerprint?.isVibeCoded || false
    },
    securityHeaders: {
      score: t.fingerprint?.headerScore || null,
      missing: t.fingerprint?.securityHeaders?.missing?.map(h => h.name) || [],
      present: t.fingerprint?.securityHeaders?.present || []
    },
    vulnerabilities: t.scan.vulnerabilities.map(v => ({
      id: v.id,
      title: v.title,
      severity: v.severity,
      category: v.category,
      location: v.location,
      cwe: v.cwe
    })),
    scoring: {
      vibeRiskScore: t.scoring.vibeRiskScore,
      riskLevel: t.scoring.riskLevel,
      criticalDataExposure: t.scoring.criticalDataExposure
    }
  }));

  const targetsPath = join(dataDir, "targets.json");
  writeFileSync(targetsPath, JSON.stringify(targetsJson, null, 2), "utf-8");
  console.log(`\n💾 [DATA] Written: ${targetsPath}`);

  // Write reports
  const { reportPath, patchPath } = writeReports(scored);

  // Summary
  const elapsed = ((Date.now() - startTime) / 1000).toFixed(2);

  console.log(`
${"━".repeat(60)}
  ✅ PIPELINE COMPLETE
${"━".repeat(60)}

  ⏱️  Elapsed: ${elapsed}s
  🎯 Targets scanned: ${scored.length}
  🐛 Vulnerabilities found: ${scored.reduce((s, t) => s + t.scan.counts.total, 0)}
  🔴 Critical findings: ${scored.reduce((s, t) => s + t.scan.counts.critical, 0)}
  📊 Average Vibe Risk Score: ${Math.round(scored.reduce((s, t) => s + t.scoring.vibeRiskScore, 0) / scored.length)}/100

  📁 Output Files:
     └─ ${targetsPath}
     └─ ${reportPath}
     └─ ${patchPath}

  🤝 Next: Person B picks up vibe-check-report.md & fix-artifact.patch
     for empathy-first disclosure and social impact scoring.
`);
}

// ─── Run ─────────────────────────────────────────────────────────────────────

runPipeline().catch(err => {
  console.error("❌ Pipeline failed:", err);
  process.exit(1);
});
