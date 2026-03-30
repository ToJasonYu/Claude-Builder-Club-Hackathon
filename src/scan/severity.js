// ============================================================================
// NGO-Guardian — Scan: Severity Scoring
// Calculates "Vibe Risk Score" and human-readable risk assessments
// ============================================================================

const SEVERITY_WEIGHTS = {
  CRITICAL: 25,
  HIGH: 15,
  MEDIUM: 8,
  LOW: 3
};

const RISK_LEVELS = [
  { min: 80, label: "🔴 SEVERE",   description: "Immediate risk — sensitive data likely exposed. Urgent remediation required." },
  { min: 60, label: "🟠 HIGH",     description: "Significant vulnerabilities — exploitation is straightforward. Prioritize fixes." },
  { min: 40, label: "🟡 MODERATE", description: "Notable security gaps — could be exploited with some effort. Plan remediation." },
  { min: 20, label: "🔵 LOW",      description: "Minor issues — limited impact but should be addressed in next sprint." },
  { min: 0,  label: "🟢 MINIMAL",  description: "Good security posture — only minor improvements recommended." }
];

/**
 * Additional context factors that amplify risk for NGOs specifically
 */
const NGO_RISK_AMPLIFIERS = {
  humanitarian: {
    label: "Humanitarian Data",
    multiplier: 1.3,
    reason: "Stores PII of vulnerable populations (refugees, children, disaster victims)"
  },
  environmental: {
    label: "Environmental Data",
    multiplier: 1.1,
    reason: "Contains sensitive field data, volunteer PII, and donor information"
  }
};

/**
 * Data sensitivity classifications found in typical NGO apps
 */
const DATA_SENSITIVITY = {
  "donors": { level: "HIGH", type: "Financial PII", examples: "Names, emails, payment info, donation history" },
  "beneficiaries": { level: "CRITICAL", type: "Protected PII", examples: "Location data, health records, family info of vulnerable populations" },
  "children": { level: "CRITICAL", type: "Protected Minor PII", examples: "Child profiles, photos, welfare records" },
  "cases": { level: "CRITICAL", type: "Case Records", examples: "Refugee status, legal cases, sensitive personal histories" },
  "personnel": { level: "HIGH", type: "Staff PII", examples: "Field worker locations, contact info, assignments" },
  "volunteers": { level: "MEDIUM", type: "Volunteer PII", examples: "Names, emails, availability, skills" },
  "payments": { level: "HIGH", type: "Financial Records", examples: "Transaction records, payment methods, amounts" },
  "locations": { level: "HIGH", type: "Geospatial Data", examples: "Aid distribution points, refugee camp locations" },
  "sensors": { level: "LOW", type: "Environmental Data", examples: "Pollution readings, GPS coordinates of sensors" }
};

/**
 * Calculate the Vibe Risk Score for a scanned target
 * @returns {Object} Scoring result with numeric score, risk level, and human-readable assessment
 */
export function calculateVibeRiskScore(scannedTarget) {
  const { scan, fingerprint, sector, endpoints } = scannedTarget;

  // Base score from vulnerability severity
  let rawScore = 0;
  for (const vuln of scan.vulnerabilities) {
    rawScore += SEVERITY_WEIGHTS[vuln.severity] || 0;
  }

  // Cap raw score at 100
  rawScore = Math.min(rawScore, 100);

  // Apply NGO sector amplifier
  const amplifier = NGO_RISK_AMPLIFIERS[sector] || { multiplier: 1.0 };
  let amplifiedScore = Math.min(Math.round(rawScore * amplifier.multiplier), 100);

  // Determine risk level
  const riskLevel = RISK_LEVELS.find(r => amplifiedScore >= r.min) || RISK_LEVELS[RISK_LEVELS.length - 1];

  // Identify exposed data types
  const exposedData = (endpoints || [])
    .map(ep => {
      const resource = ep.replace(/^\/api\/(v\d+\/)?/, "").split("/")[0];
      return DATA_SENSITIVITY[resource] || null;
    })
    .filter(Boolean);

  const criticalData = exposedData.filter(d => d.level === "CRITICAL");

  // Header security score
  const headerScore = fingerprint?.headerScore ?? 100;

  return {
    vibeRiskScore: amplifiedScore,
    rawScore,
    riskLevel: riskLevel.label,
    riskDescription: riskLevel.description,
    sectorAmplifier: amplifier,
    headerScore,
    exposedDataTypes: exposedData,
    criticalDataExposure: criticalData.length > 0,
    humanSummary: buildHumanSummary(scannedTarget, amplifiedScore, riskLevel, criticalData, headerScore)
  };
}

/**
 * Build a human-readable summary for Person B's disclosure pipeline
 */
function buildHumanSummary(target, score, riskLevel, criticalData, headerScore) {
  let summary = `${target.name} has a Vibe Risk Score of ${score}/100 (${riskLevel.label}).\n`;
  summary += `Tech Stack: ${target.fingerprint?.vibeStack?.platform || "Unknown"} + ${target.fingerprint?.vibeStack?.framework || "Unknown"}.\n`;
  summary += `Security Header Coverage: ${headerScore}%.\n`;
  summary += `Total Vulnerabilities: ${target.scan.counts.total} `;
  summary += `(${target.scan.counts.critical} Critical, ${target.scan.counts.high} High, ${target.scan.counts.medium} Medium, ${target.scan.counts.low} Low).\n`;

  if (criticalData.length > 0) {
    summary += `\n⚠️  CRITICAL DATA AT RISK:\n`;
    for (const d of criticalData) {
      summary += `   - ${d.type}: ${d.examples}\n`;
    }
  }

  return summary;
}

/**
 * Score all scanned targets
 */
export function scoreAll(targets) {
  console.log("📊 [SEVERITY] Calculating Vibe Risk Scores...\n");

  const results = targets.map(target => {
    const scoring = calculateVibeRiskScore(target);

    console.log(`   ${target.name}: ${scoring.vibeRiskScore}/100 ${scoring.riskLevel}`);
    if (scoring.criticalDataExposure) {
      console.log(`      └─ ⚠️  Critical data types at risk!`);
    }

    return { ...target, scoring };
  });

  results.sort((a, b) => b.scoring.vibeRiskScore - a.scoring.vibeRiskScore);

  console.log(`\n📊 [SEVERITY] Complete — targets ranked by risk.\n`);

  return results;
}

export { SEVERITY_WEIGHTS, RISK_LEVELS, DATA_SENSITIVITY, NGO_RISK_AMPLIFIERS };
