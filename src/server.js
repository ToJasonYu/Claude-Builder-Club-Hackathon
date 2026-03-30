// ============================================================================
// NGO-Guardian — Dashboard Server
// Serves the interactive web dashboard and API endpoints
// ============================================================================

import express from "express";
import { readFileSync, existsSync } from "fs";
import { join, dirname } from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const PROJECT_ROOT = join(__dirname, "..");

const app = express();
const PORT = 3000;

// Serve static dashboard files
app.use(express.static(join(__dirname, "dashboard", "public")));

// ─── API Endpoints ───────────────────────────────────────────────────────────

app.get("/api/targets", (req, res) => {
  const targetsPath = join(PROJECT_ROOT, "data", "targets.json");
  if (!existsSync(targetsPath)) {
    return res.status(404).json({ error: "No scan data found. Run the pipeline first." });
  }
  const data = JSON.parse(readFileSync(targetsPath, "utf-8"));
  res.json(data);
});

app.get("/api/report", (req, res) => {
  const reportPath = join(PROJECT_ROOT, "output", "vibe-check-report.md");
  if (!existsSync(reportPath)) {
    return res.status(404).json({ error: "Report not found." });
  }
  res.type("text/markdown").send(readFileSync(reportPath, "utf-8"));
});

app.get("/api/fix-artifact", (req, res) => {
  const patchPath = join(PROJECT_ROOT, "output", "fix-artifact.patch");
  if (!existsSync(patchPath)) {
    return res.status(404).json({ error: "Fix artifact not found." });
  }
  res.type("text/plain").send(readFileSync(patchPath, "utf-8"));
});

app.get("/api/findings/:slug", (req, res) => {
  const findingsDir = join(PROJECT_ROOT, "findings");
  const filename = `vibe-check-report-${req.params.slug}.md`;
  const filePath = join(findingsDir, filename);
  if (!existsSync(filePath)) {
    return res.status(404).json({ error: "Finding not found." });
  }
  res.type("text/markdown").send(readFileSync(filePath, "utf-8"));
});

app.get("/api/stats", (req, res) => {
  const targetsPath = join(PROJECT_ROOT, "data", "targets.json");
  if (!existsSync(targetsPath)) {
    return res.status(404).json({ error: "No data." });
  }
  const targets = JSON.parse(readFileSync(targetsPath, "utf-8"));
  const totalVulns = targets.reduce((s, t) => s + t.vulnerabilities.length, 0);
  const totalCritical = targets.reduce((s, t) => s + t.vulnerabilities.filter(v => v.severity === "CRITICAL").length, 0);
  const totalHigh = targets.reduce((s, t) => s + t.vulnerabilities.filter(v => v.severity === "HIGH").length, 0);
  const avgScore = Math.round(targets.reduce((s, t) => s + t.scoring.vibeRiskScore, 0) / targets.length);
  const criticalDataTargets = targets.filter(t => t.scoring.criticalDataExposure).length;

  res.json({
    totalTargets: targets.length,
    totalVulnerabilities: totalVulns,
    criticalFindings: totalCritical,
    highFindings: totalHigh,
    averageVibeRiskScore: avgScore,
    criticalDataTargets,
    scanTimestamp: new Date().toISOString(),
    pipelineVersion: "1.0.0"
  });
});

// SPA fallback
app.use((req, res) => {
  res.sendFile(join(__dirname, "dashboard", "public", "index.html"));
});

app.listen(PORT, () => {
  console.log(`
  🛡️  NGO-Guardian Dashboard
  ──────────────────────────
  Running at: http://localhost:${PORT}
  API:        http://localhost:${PORT}/api/targets
  `);
});
