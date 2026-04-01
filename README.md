# 🛡️ NGO-Guardian

**Autonomous Safety Net for Non-Profits** — Agentic vulnerability detection for vibe-coded NGO infrastructure.

> "We are Guardians, not Hunters."
> 

## Architecture

```
Discovery → Fingerprint → Scan → Score → Report
   │            │           │       │        │
   ▼            ▼           ▼       ▼        ▼
 Find .org   Detect tech  Find    Vibe     vibe-check-report.md
 targets     stacks &     vulns   Risk     fix-artifact.patch
             headers              Score    targets.json
```

## Quick Start

```bash
npm start
```

This runs the full pipeline and outputs:
- `data/targets.json` — All discovered targets with findings
- `output/vibe-check-report.md` — Full vulnerability report (→ Person B)
- `output/fix-artifact.patch` — Remediation code snippets (→ Person B)

## Project Structure

```
src/
├── index.js              # Pipeline orchestrator
├── search/
│   ├── discovery.js      # Agentic NGO discovery
│   └── fingerprint.js    # Tech stack & header fingerprinting
├── scan/
│   ├── detector.js       # Vulnerability detection engine
│   └── severity.js       # Vibe Risk Score calculator
└── report/
    └── generator.js      # Report & fix artifact generator
```

## Ethical Guardrails

- **Zero-Exploitation**: Detect only, never touch
- **Privacy First**: All findings stored locally
- **Helper Persona**: Supportive, never threatening

## Team

- **Person A** (Security Architect): Engine, scanning, fix artifacts
- **Person B** (Impact & Disclosure): Human risk, impact scores, outreach

---

*Built for the Claude Builder Club Hackathon*
