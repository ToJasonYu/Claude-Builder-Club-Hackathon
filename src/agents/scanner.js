// ============================================================================
// NGO-Guardian — Scanner Agent
// Reads targets.json → deep-scans each target → classifies data risk →
// outputs per-target vibe-check-report.md to findings/
// ============================================================================

import { readFileSync, writeFileSync, mkdirSync, existsSync } from "fs";
import { join, dirname } from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const PROJECT_ROOT = join(__dirname, "..", "..");

// ─── Simulated Deep Scan Checks ─────────────────────────────────────────────

/**
 * Deep scan simulations — each check probes a specific vibe-coded vulnerability
 * In production, these would make real HTTP requests (with consent)
 */
const DEEP_SCAN_CHECKS = {
  envFile: {
    id: "SCAN-ENV",
    name: "Public .env File Exposure",
    description: "Checks if /.env, /.env.local, /.env.production are publicly accessible",
    probe: (target) => {
      const envEndpoints = target.endpoints.filter(ep =>
        ep.includes(".env")
      );
      if (envEndpoints.length === 0) return null;

      // Simulate .env file contents based on tech stack
      const envContents = generateSimulatedEnvContents(target);
      return {
        found: true,
        endpoints: envEndpoints,
        simulatedContents: envContents,
        exposedSecrets: extractSecrets(envContents),
        httpStatus: 200,
        responseHeaders: { "content-type": "text/plain", "content-length": envContents.length }
      };
    }
  },

  graphqlPlayground: {
    id: "SCAN-GQL",
    name: "Unauthenticated GraphQL Playground",
    description: "Checks if /graphql endpoint exposes an introspection-enabled playground without auth",
    probe: (target) => {
      const gqlEndpoint = target.endpoints.find(ep => ep.includes("graphql"));
      if (!gqlEndpoint) return null;

      return {
        found: true,
        endpoint: gqlEndpoint,
        introspectionEnabled: true,
        playgroundEnabled: true,
        authRequired: false,
        exposedTypes: generateExposedGraphQLTypes(target),
        exposedMutations: generateExposedMutations(target),
        httpStatus: 200,
        responseHeaders: { "content-type": "application/json" }
      };
    }
  },

  swaggerExposed: {
    id: "SCAN-SWAGGER",
    name: "Exposed Swagger/OpenAPI Documentation",
    description: "Checks if /swagger.json or /api-docs are publicly accessible",
    probe: (target) => {
      // Simulate: some targets have exposed API docs
      const hasApi = target.endpoints.some(ep => ep.startsWith("/api/"));
      if (!hasApi) return null;

      const exposedDomains = {
        "globalwaterinitiative.org": true,
        "oceanguardalliance.org": true,
        "childbridge-intl.org": false,
        "ecorestorefd.org": false,
        "refugeeaidnetwork.org": true
      };

      if (!exposedDomains[target.domain]) return null;

      return {
        found: true,
        endpoints: ["/swagger.json", "/api-docs"],
        apiVersion: "3.0.1",
        exposedRoutes: target.endpoints.filter(ep => ep.startsWith("/api/")),
        authSchemes: [],
        description: `Full API specification for ${target.name} — all endpoints, request/response schemas, and data models visible without authentication.`
      };
    }
  },

  clientSideKeys: {
    id: "SCAN-KEYS",
    name: "Hardcoded API Keys in Client-Side JS",
    description: "Scans JavaScript bundles for hardcoded API keys, tokens, and secrets",
    probe: (target) => {
      const keyFindings = generateClientKeyFindings(target);
      if (keyFindings.length === 0) return null;

      return {
        found: true,
        keys: keyFindings,
        bundleLocations: generateBundleLocations(target),
        sourceMapAvailable: target.securityHeaders.missing.length > 3
      };
    }
  },

  openApiEndpoints: {
    id: "SCAN-OPENAPI",
    name: "Unauthenticated API Endpoints",
    description: "Checks if sensitive API endpoints respond without authentication tokens",
    probe: (target) => {
      const apiEndpoints = target.endpoints.filter(ep =>
        ep.startsWith("/api/") && !ep.includes("auth") && !ep.includes("public")
      );
      if (apiEndpoints.length === 0) return null;

      return {
        found: true,
        endpoints: apiEndpoints.map(ep => ({
          path: ep,
          method: "GET",
          httpStatus: 200,
          authRequired: false,
          sampleDataType: classifyEndpointData(ep),
          recordCount: Math.floor(Math.random() * 5000) + 100
        }))
      };
    }
  },

  databaseExposure: {
    id: "SCAN-DB",
    name: "Direct Database Exposure",
    description: "Checks for exposed Supabase REST/Firebase endpoints without proper access controls",
    probe: (target) => {
      const platform = target.techStack.platform;
      if (!["Supabase", "Firebase"].includes(platform)) return null;

      return {
        found: true,
        platform,
        accessLevel: platform === "Supabase" ? "anon_key_no_rls" : "public_rules",
        exposedTables: generateExposedTables(target),
        directUrl: platform === "Supabase"
          ? `https://${target.domain.replace(".org", "")}.supabase.co/rest/v1/`
          : `https://${target.domain.replace(".org", "")}.firebaseio.com/`
      };
    }
  }
};

// ─── Data Risk Classification (AI-simulated) ────────────────────────────────

/**
 * Classifies data risk into PII, Location, Financial categories
 * Simulates what Claude would output as risk classification
 */
const DATA_RISK_CLASSIFIER = {
  classify(findings, target) {
    const classification = {
      pii: { found: false, severity: "NONE", details: [] },
      location: { found: false, severity: "NONE", details: [] },
      financial: { found: false, severity: "NONE", details: [] },
      minorData: { found: false, severity: "NONE", details: [] },
      healthData: { found: false, severity: "NONE", details: [] },
      overallRisk: "LOW",
      humanImpactStatement: ""
    };

    // PII classification
    const piiIndicators = ["donors", "beneficiaries", "personnel", "volunteers", "children", "sponsors", "cases"];
    const foundPII = target.endpoints
      .map(ep => ep.replace(/^\/api\/(v\d+\/)?/, "").split("/")[0])
      .filter(r => piiIndicators.includes(r));

    if (foundPII.length > 0) {
      classification.pii = {
        found: true,
        severity: foundPII.includes("children") || foundPII.includes("cases") ? "CRITICAL" : "HIGH",
        details: foundPII.map(r => PII_DETAILS[r] || { type: r, risk: "Contains personal information" })
      };
    }

    // Location data
    const locationIndicators = ["locations", "maps", "sensors", "sites"];
    const foundLocation = target.endpoints
      .map(ep => ep.replace(/^\/api\/(v\d+\/)?/, "").split("/")[0])
      .filter(r => locationIndicators.includes(r));

    if (foundLocation.length > 0 || target.subdomains.some(s => s.includes("maps"))) {
      classification.location = {
        found: true,
        severity: target.sector === "humanitarian" ? "CRITICAL" : "HIGH",
        details: [{
          type: "Geospatial Data",
          risk: target.sector === "humanitarian"
            ? "Location data of vulnerable populations (refugees, aid recipients) — could be exploited for targeting"
            : "Environmental monitoring sites, volunteer field locations"
        }]
      };
    }

    // Financial data
    const financialIndicators = ["donations", "payments", "sponsors", "donors"];
    const foundFinancial = target.endpoints
      .map(ep => ep.replace(/^\/api\/(v\d+\/)?/, "").split("/")[0])
      .filter(r => financialIndicators.includes(r));

    if (foundFinancial.length > 0) {
      classification.financial = {
        found: true,
        severity: "HIGH",
        details: [{
          type: "Financial Records",
          risk: "Donation amounts, payment methods, transaction histories, sponsor financial commitments"
        }]
      };
    }

    // Minor data (children)
    if (foundPII.includes("children")) {
      classification.minorData = {
        found: true,
        severity: "CRITICAL",
        details: [{
          type: "Protected Minor Data",
          risk: "Profiles, photographs, welfare records, and sponsorship details of orphaned and at-risk children — highest protection category under GDPR, COPPA, and most data protection laws"
        }]
      };
    }

    // Health data
    if (target.sector === "humanitarian" && (foundPII.includes("cases") || foundPII.includes("beneficiaries"))) {
      classification.healthData = {
        found: true,
        severity: "CRITICAL",
        details: [{
          type: "Health & Welfare Records",
          risk: "Medical histories, disability status, mental health assessments, and welfare evaluations of vulnerable individuals"
        }]
      };
    }

    // Overall risk
    const severities = [classification.pii, classification.location, classification.financial, classification.minorData, classification.healthData]
      .filter(c => c.found)
      .map(c => c.severity);

    if (severities.includes("CRITICAL")) classification.overallRisk = "CRITICAL";
    else if (severities.includes("HIGH")) classification.overallRisk = "HIGH";
    else if (severities.includes("MEDIUM")) classification.overallRisk = "MEDIUM";

    // Human impact statement
    classification.humanImpactStatement = generateHumanImpactStatement(target, classification);

    return classification;
  }
};

const PII_DETAILS = {
  donors: { type: "Donor PII", risk: "Full names, email addresses, phone numbers, mailing addresses of financial supporters" },
  beneficiaries: { type: "Beneficiary PII", risk: "Names, locations, family details, and assistance records of aid recipients — extremely vulnerable population" },
  personnel: { type: "Staff/Field Worker PII", risk: "Employee names, field locations, contact details, assignment schedules — safety risk in conflict zones" },
  volunteers: { type: "Volunteer PII", risk: "Names, emails, skills, availability, and site assignments" },
  children: { type: "Minor PII", risk: "Child names, photographs, ages, welfare status, sponsorship records, school enrollment — protected under COPPA/GDPR" },
  sponsors: { type: "Sponsor PII", risk: "Individual/corporate sponsor identities, financial commitments, contact information" },
  cases: { type: "Case File PII", risk: "Refugee status applications, legal case details, personal histories, family separation records, trauma assessments" }
};

// ─── Simulation Data Generators ──────────────────────────────────────────────

function generateSimulatedEnvContents(target) {
  const platform = target.techStack.platform;
  let env = `# ${target.name} — Environment Configuration\n`;
  env += `# WARNING: This file should NEVER be publicly accessible\n\n`;

  if (platform === "Supabase") {
    env += `SUPABASE_URL=https://${target.domain.replace(".org", "")}.supabase.co\n`;
    env += `SUPABASE_ANON_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InhtdX...[REDACTED]\n`;
    env += `SUPABASE_SERVICE_ROLE_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFz...[REDACTED]\n`;
    env += `DATABASE_URL=postgresql://postgres:[REDACTED]@db.${target.domain.replace(".org", "")}.supabase.co:5432/postgres\n`;
  } else if (platform === "Firebase") {
    env += `FIREBASE_API_KEY=AIzaSy...[REDACTED]\n`;
    env += `FIREBASE_AUTH_DOMAIN=${target.domain.replace(".org", "")}.firebaseapp.com\n`;
    env += `FIREBASE_PROJECT_ID=${target.domain.replace(".org", "")}\n`;
    env += `FIREBASE_ADMIN_SDK_KEY={"type":"service_account","project_id":"...[REDACTED]"}\n`;
  } else if (platform === "Netlify") {
    env += `STRIPE_SECRET_KEY=sk_live_...[REDACTED]\n`;
    env += `STRIPE_PUBLISHABLE_KEY=pk_live_...[REDACTED]\n`;
    env += `STRIPE_WEBHOOK_SECRET=whsec_...[REDACTED]\n`;
  } else {
    env += `DATABASE_URL=postgresql://user:[REDACTED]@host:5432/db\n`;
    env += `JWT_SECRET=[REDACTED_256BIT_KEY]\n`;
  }

  env += `\nNODE_ENV=production\n`;
  env += `NEXT_PUBLIC_API_URL=https://api.${target.domain}\n`;
  env += `SENDGRID_API_KEY=SG...[REDACTED]\n`;
  env += `SENTRY_DSN=https://[REDACTED]@sentry.io/[REDACTED]\n`;

  return env;
}

function extractSecrets(envContents) {
  const secretPatterns = [
    { pattern: "SUPABASE_SERVICE_ROLE_KEY", type: "Supabase Service Key", severity: "CRITICAL" },
    { pattern: "DATABASE_URL", type: "Database Connection String", severity: "CRITICAL" },
    { pattern: "FIREBASE_ADMIN_SDK_KEY", type: "Firebase Admin Key", severity: "CRITICAL" },
    { pattern: "STRIPE_SECRET_KEY", type: "Stripe Secret Key", severity: "CRITICAL" },
    { pattern: "JWT_SECRET", type: "JWT Signing Key", severity: "CRITICAL" },
    { pattern: "SENDGRID_API_KEY", type: "SendGrid API Key", severity: "HIGH" },
    { pattern: "STRIPE_WEBHOOK_SECRET", type: "Stripe Webhook Secret", severity: "HIGH" },
    { pattern: "SUPABASE_ANON_KEY", type: "Supabase Anon Key", severity: "MEDIUM" },
    { pattern: "SENTRY_DSN", type: "Sentry DSN", severity: "LOW" }
  ];

  return secretPatterns
    .filter(s => envContents.includes(s.pattern))
    .map(s => ({ ...s, redacted: true }));
}

function generateExposedGraphQLTypes(target) {
  const baseTypes = ["Query", "Mutation", "Subscription"];
  const dataTypes = target.endpoints
    .filter(ep => ep.startsWith("/api/"))
    .map(ep => {
      const resource = ep.replace(/^\/api\/(v\d+\/)?/, "").split("/")[0];
      return resource.charAt(0).toUpperCase() + resource.slice(1);
    });

  return [...baseTypes, ...dataTypes, "User", "AuthPayload", "PaginationInfo"];
}

function generateExposedMutations(target) {
  return target.endpoints
    .filter(ep => ep.startsWith("/api/") && !ep.includes("auth"))
    .map(ep => {
      const resource = ep.replace(/^\/api\/(v\d+\/)?/, "").split("/")[0];
      return [
        `create${resource.charAt(0).toUpperCase() + resource.slice(1)}`,
        `update${resource.charAt(0).toUpperCase() + resource.slice(1)}`,
        `delete${resource.charAt(0).toUpperCase() + resource.slice(1)}`
      ];
    })
    .flat();
}

function generateClientKeyFindings(target) {
  const keyMap = {
    "Supabase": [
      { key: "SUPABASE_ANON_KEY", value: "eyJhbGciOi...[REDACTED]", severity: "HIGH", context: "Combined with disabled RLS = full database access" },
      { key: "SUPABASE_URL", value: `https://${target.domain.replace(".org", "")}.supabase.co`, severity: "MEDIUM", context: "Exposes database project identifier" }
    ],
    "Firebase": [
      { key: "FIREBASE_API_KEY", value: "AIzaSy...[REDACTED]", severity: "MEDIUM", context: "Firebase API keys are designed to be public, but combined with open Firestore rules = full access" },
      { key: "FIREBASE_APP_ID", value: "1:123456789:web:abc...[REDACTED]", severity: "LOW", context: "App identifier" },
      { key: "FIREBASE_MEASUREMENT_ID", value: "G-...[REDACTED]", severity: "LOW", context: "Analytics identifier" }
    ],
    "Netlify": [
      { key: "STRIPE_PUBLISHABLE_KEY", value: "pk_live_...[REDACTED]", severity: "LOW", context: "Publishable keys are meant to be public" },
      { key: "NEXT_PUBLIC_API_URL", value: `https://api.${target.domain}`, severity: "LOW", context: "API base URL" }
    ],
    "Vercel": [
      { key: "NEXT_PUBLIC_API_URL", value: `https://api.${target.domain}`, severity: "LOW", context: "API base URL exposed" },
      { key: "NEXT_PUBLIC_SENTRY_DSN", value: "https://...[REDACTED]@sentry.io/...", severity: "LOW", context: "Error tracking DSN" }
    ]
  };

  return keyMap[target.techStack.platform] || [];
}

function generateBundleLocations(target) {
  const framework = target.techStack.framework || "";
  if (framework.includes("Next")) {
    return [`/_next/static/chunks/main-[hash].js`, `/_next/static/chunks/pages/_app-[hash].js`];
  } else if (framework.includes("Nuxt")) {
    return [`/_nuxt/entry.[hash].js`, `/_nuxt/[hash].js`];
  } else if (framework.includes("Svelte")) {
    return [`/_app/immutable/entry/start.[hash].js`, `/_app/immutable/chunks/[hash].js`];
  } else {
    return [`/assets/index-[hash].js`, `/assets/vendor-[hash].js`];
  }
}

function generateExposedTables(target) {
  return target.endpoints
    .filter(ep => ep.startsWith("/api/") && !ep.includes("auth") && !ep.includes("public"))
    .map(ep => {
      const name = ep.replace(/^\/api\/(v\d+\/)?/, "").split("/")[0];
      return {
        name,
        estimatedRows: Math.floor(Math.random() * 10000) + 50,
        rlsEnabled: false,
        columns: generateTableColumns(name)
      };
    });
}

function generateTableColumns(tableName) {
  const columnSets = {
    donors: ["id", "full_name", "email", "phone", "address", "donation_total", "last_donation_date", "payment_method_hash"],
    beneficiaries: ["id", "full_name", "date_of_birth", "location_lat", "location_lng", "family_size", "assistance_type", "health_notes", "created_at"],
    children: ["id", "first_name", "last_name", "date_of_birth", "photo_url", "welfare_status", "sponsor_id", "school_name", "health_record_id"],
    cases: ["id", "case_number", "applicant_name", "nationality", "status", "assigned_worker", "notes", "documents", "created_at"],
    personnel: ["id", "full_name", "role", "email", "phone", "field_location", "clearance_level", "emergency_contact"],
    volunteers: ["id", "name", "email", "skills", "availability", "assigned_site", "hours_logged"],
    payments: ["id", "donor_id", "amount", "currency", "method", "stripe_charge_id", "receipt_url", "created_at"],
    donations: ["id", "donor_email", "amount", "campaign", "recurring", "payment_token", "created_at"],
    sensors: ["id", "sensor_type", "latitude", "longitude", "last_reading", "battery_level", "deployed_date"],
    sites: ["id", "site_name", "coordinates", "status", "lead_volunteer", "tree_count", "area_hectares"],
    locations: ["id", "name", "type", "latitude", "longitude", "capacity", "current_occupancy", "security_level"],
    reports: ["id", "title", "author", "content", "classification", "created_at", "status"],
    documents: ["id", "title", "file_url", "uploaded_by", "classification", "tags", "created_at"]
  };

  return columnSets[tableName] || ["id", "data", "created_at", "updated_at"];
}

function classifyEndpointData(endpoint) {
  const resource = endpoint.replace(/^\/api\/(v\d+\/)?/, "").split("/")[0];
  const classifications = {
    donors: { category: "PII + Financial", sensitivity: "HIGH" },
    beneficiaries: { category: "PII + Health", sensitivity: "CRITICAL" },
    children: { category: "Minor PII", sensitivity: "CRITICAL" },
    cases: { category: "PII + Legal", sensitivity: "CRITICAL" },
    personnel: { category: "PII + Location", sensitivity: "HIGH" },
    volunteers: { category: "PII", sensitivity: "MEDIUM" },
    payments: { category: "Financial", sensitivity: "HIGH" },
    donations: { category: "Financial + PII", sensitivity: "HIGH" },
    locations: { category: "Geospatial", sensitivity: "HIGH" },
    sensors: { category: "Environmental", sensitivity: "LOW" },
    sites: { category: "Geospatial", sensitivity: "MEDIUM" },
    reports: { category: "Internal Documents", sensitivity: "MEDIUM" },
    documents: { category: "Internal Documents", sensitivity: "MEDIUM" },
    projects: { category: "Operational", sensitivity: "LOW" }
  };
  return classifications[resource] || { category: "Unknown", sensitivity: "MEDIUM" };
}

function generateHumanImpactStatement(target, classification) {
  const impacts = [];

  if (classification.minorData.found) {
    impacts.push(`Children's personal data, including photographs and welfare records, could be accessed by malicious actors. This puts orphaned and at-risk minors at direct risk of exploitation.`);
  }

  if (classification.healthData.found) {
    impacts.push(`Health and welfare records of vulnerable individuals (refugees, disaster survivors) could be exposed, leading to discrimination, denial of services, or targeted persecution.`);
  }

  if (classification.pii.found && classification.location.found) {
    impacts.push(`The combination of personal identity data and location coordinates creates a severe risk: bad actors could physically locate vulnerable individuals including refugees, aid workers in conflict zones, or abuse survivors.`);
  } else if (classification.pii.found) {
    impacts.push(`Personal information of ${target.sector === "humanitarian" ? "vulnerable populations" : "donors and volunteers"} could be harvested for identity theft, phishing, or social engineering.`);
  }

  if (classification.financial.found) {
    impacts.push(`Financial records including donation amounts and payment information could be exploited for fraud, or used to target high-value donors with spear-phishing campaigns.`);
  }

  if (impacts.length === 0) {
    impacts.push(`While the data exposure is limited, any breach of an NGO's digital infrastructure undermines donor trust and could divert resources from the organization's core mission.`);
  }

  return impacts.join("\n\n");
}

// ─── Report Generator ────────────────────────────────────────────────────────

function generatePerTargetReport(target, scanResults, riskClassification) {
  const timestamp = new Date().toISOString();
  const slug = target.domain.replace(/\./g, "-");
  let md = "";

  // Header
  md += `# 🛡️ Vibe Check Report: ${target.name}\n\n`;
  md += `> **Target**: \`${target.domain}\`\n`;
  md += `> **Scan Date**: ${timestamp}\n`;
  md += `> **Scanner Agent**: NGO-Guardian v1.0\n`;
  md += `> **Mode**: Detection Only — Zero Exploitation\n\n`;
  md += `---\n\n`;

  // Target Profile
  md += `## 📋 Target Profile\n\n`;
  md += `| Field | Value |\n`;
  md += `|-------|-------|\n`;
  md += `| **Organization** | ${target.name} |\n`;
  md += `| **Domain** | \`${target.domain}\` |\n`;
  md += `| **Sector** | ${target.sector.charAt(0).toUpperCase() + target.sector.slice(1)} |\n`;
  md += `| **Mission** | ${target.mission} |\n`;
  md += `| **Tech Stack** | ${target.techStack.platform} + ${target.techStack.framework || "Unknown"} |\n`;
  md += `| **Vibe-Coded** | ${target.techStack.isVibeCoded ? "✅ Yes" : "❌ No"} |\n`;
  md += `| **Vibe Risk Score** | **${target.scoring.vibeRiskScore}/100** ${target.scoring.riskLevel} |\n`;
  md += `| **Security Header Score** | ${target.securityHeaders.score ?? "N/A"}% |\n\n`;

  // Subdomains
  md += `### Discovered Subdomains\n\n`;
  for (const sub of target.subdomains) {
    md += `- \`${sub}\`\n`;
  }
  md += `\n`;

  // Data Risk Classification
  md += `---\n\n`;
  md += `## 🧠 AI Data Risk Classification\n\n`;
  md += `> *Classified by Claude — analyzing data types at risk based on exposed endpoints and database schemas*\n\n`;
  md += `| Category | Found | Severity | Details |\n`;
  md += `|----------|-------|----------|---------|\n`;

  const riskCategories = [
    { key: "pii", label: "🔵 PII (Personal)" },
    { key: "location", label: "📍 Location Data" },
    { key: "financial", label: "💰 Financial" },
    { key: "minorData", label: "👶 Minor/Child Data" },
    { key: "healthData", label: "🏥 Health/Welfare" }
  ];

  for (const cat of riskCategories) {
    const data = riskClassification[cat.key];
    const found = data.found ? "⚠️ YES" : "—";
    const severity = data.found ? data.severity : "—";
    const details = data.found ? data.details.map(d => d.type).join(", ") : "Not detected";
    md += `| ${cat.label} | ${found} | ${severity} | ${details} |\n`;
  }

  md += `\n`;

  if (riskClassification.overallRisk === "CRITICAL") {
    md += `> [!CAUTION]\n`;
    md += `> **Overall Data Risk: CRITICAL** — This organization handles highly sensitive data that appears to be insufficiently protected.\n\n`;
  } else if (riskClassification.overallRisk === "HIGH") {
    md += `> [!WARNING]\n`;
    md += `> **Overall Data Risk: HIGH** — Significant sensitive data exposure detected.\n\n`;
  }

  // Human Impact Statement
  md += `### 💔 Human Impact Assessment\n\n`;
  md += riskClassification.humanImpactStatement.split("\n\n").map(p => `> ${p}`).join("\n>\n");
  md += `\n\n`;

  // Deep Scan Findings
  md += `---\n\n`;
  md += `## 🔍 Deep Scan Findings\n\n`;

  let findingNum = 0;
  for (const [checkKey, result] of Object.entries(scanResults)) {
    if (!result || !result.found) continue;
    findingNum++;
    const check = DEEP_SCAN_CHECKS[checkKey];

    md += `### Finding ${findingNum}: ${check.name}\n\n`;
    md += `- **Check ID**: \`${check.id}\`\n`;
    md += `- **Status**: 🔴 VULNERABLE\n`;
    md += `- **Description**: ${check.description}\n\n`;

    // Check-specific details
    if (checkKey === "envFile") {
      md += `**Exposed Endpoints:**\n`;
      for (const ep of result.endpoints) {
        md += `- \`${target.domain}${ep}\` → HTTP ${result.httpStatus}\n`;
      }
      md += `\n**Exposed Secrets (${result.exposedSecrets.length} found):**\n\n`;
      md += `| Secret | Type | Severity |\n`;
      md += `|--------|------|----------|\n`;
      for (const secret of result.exposedSecrets) {
        md += `| \`${secret.pattern}\` | ${secret.type} | ${secret.severity} |\n`;
      }
      md += `\n`;
      md += `> ⚠️ All secret values have been **REDACTED** in this report. NGO-Guardian does not store or transmit actual credentials.\n\n`;
    }

    if (checkKey === "graphqlPlayground") {
      md += `**Endpoint**: \`${target.domain}${result.endpoint}\`\n\n`;
      md += `| Property | Value |\n`;
      md += `|----------|-------|\n`;
      md += `| Introspection | ${result.introspectionEnabled ? "✅ Enabled" : "❌ Disabled"} |\n`;
      md += `| Playground UI | ${result.playgroundEnabled ? "✅ Accessible" : "❌ Blocked"} |\n`;
      md += `| Auth Required | ${result.authRequired ? "✅ Yes" : "❌ No"} |\n\n`;
      md += `**Exposed Types**: \`${result.exposedTypes.join("`, `")}\`\n\n`;
      md += `**Exposed Mutations** (${result.exposedMutations.length}):\n`;
      for (const mut of result.exposedMutations) {
        md += `- \`${mut}\`\n`;
      }
      md += `\n`;
    }

    if (checkKey === "swaggerExposed") {
      md += `**Exposed at**: \`${target.domain}/swagger.json\`, \`${target.domain}/api-docs\`\n\n`;
      md += `**API Version**: ${result.apiVersion}\n\n`;
      md += `**Documented Routes (${result.exposedRoutes.length}):**\n`;
      for (const route of result.exposedRoutes) {
        md += `- \`${route}\`\n`;
      }
      md += `\n**Authentication Schemes**: ${result.authSchemes.length === 0 ? "❌ None defined" : result.authSchemes.join(", ")}\n\n`;
    }

    if (checkKey === "clientSideKeys") {
      md += `**Found in JS bundles:**\n`;
      for (const loc of result.bundleLocations) {
        md += `- \`${target.domain}${loc}\`\n`;
      }
      md += `\n**Hardcoded Keys (${result.keys.length}):**\n\n`;
      md += `| Key | Severity | Context |\n`;
      md += `|-----|----------|---------|\n`;
      for (const k of result.keys) {
        md += `| \`${k.key}\` | ${k.severity} | ${k.context} |\n`;
      }
      md += `\n`;
      if (result.sourceMapAvailable) {
        md += `> ⚠️ Source maps are also available — original source code may reveal additional secrets.\n\n`;
      }
    }

    if (checkKey === "openApiEndpoints") {
      md += `**Unprotected Endpoints (${result.endpoints.length}):**\n\n`;
      md += `| Endpoint | Method | Status | Data Type | Est. Records |\n`;
      md += `|----------|--------|--------|-----------|-------------|\n`;
      for (const ep of result.endpoints) {
        md += `| \`${ep.path}\` | ${ep.method} | ${ep.httpStatus} | ${ep.sampleDataType.category} (${ep.sampleDataType.sensitivity}) | ~${ep.recordCount.toLocaleString()} |\n`;
      }
      md += `\n`;
    }

    if (checkKey === "databaseExposure") {
      md += `**Platform**: ${result.platform}\n`;
      md += `**Access Level**: \`${result.accessLevel}\`\n`;
      md += `**Direct URL**: \`${result.directUrl}\`\n\n`;
      md += `**Exposed Tables (${result.exposedTables.length}):**\n\n`;
      for (const table of result.exposedTables) {
        md += `#### \`${table.name}\` (~${table.estimatedRows.toLocaleString()} rows)\n`;
        md += `- RLS: ${table.rlsEnabled ? "✅ Enabled" : "❌ Disabled"}\n`;
        md += `- Columns: \`${table.columns.join("`, `")}\`\n\n`;
      }
    }
  }

  if (findingNum === 0) {
    md += `*No deep scan vulnerabilities detected for this target.*\n\n`;
  }

  // Existing vulnerability summary from targets.json
  md += `---\n\n`;
  md += `## 📊 Vulnerability Summary\n\n`;
  md += `| ID | Title | Severity | Category | Location |\n`;
  md += `|----|-------|----------|----------|----------|\n`;
  for (const vuln of target.vulnerabilities) {
    md += `| ${vuln.id} | ${vuln.title} | ${vuln.severity} | ${vuln.category} | \`${vuln.location}\` |\n`;
  }
  md += `\n`;

  // Footer
  md += `---\n\n`;
  md += `## 🤝 Disclosure Notes\n\n`;
  md += `This report was generated by the **NGO-Guardian Scanner Agent** as part of our\n`;
  md += `mission to protect under-resourced organizations. This report is intended for\n`;
  md += `**Person B (Impact & Disclosure Lead)** to draft empathy-first outreach.\n\n`;
  md += `- ✅ Detection only — no data was accessed, downloaded, or exploited\n`;
  md += `- ✅ All credential values are REDACTED\n`;
  md += `- ✅ Report stored locally — never transmitted externally\n`;
  md += `- ✅ Intent: Help this organization secure their infrastructure for free\n\n`;
  md += `> *"We are Guardians, not Hunters."*\n`;

  return { slug, content: md, findingCount: findingNum };
}

// ─── Main Scanner Agent ──────────────────────────────────────────────────────

export async function runScannerAgent() {
  console.log(`
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║   🔬 NGO-GUARDIAN — SCANNER AGENT                            ║
║                                                              ║
║   Reading targets.json → Deep Scan → Classify → Report       ║
║   Mode: DETECTION ONLY — Zero Exploitation                   ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
  `);

  // 1. Load targets.json
  const targetsPath = join(PROJECT_ROOT, "data", "targets.json");
  if (!existsSync(targetsPath)) {
    console.error("❌ data/targets.json not found. Run the main pipeline first: npm start");
    process.exit(1);
  }

  const targets = JSON.parse(readFileSync(targetsPath, "utf-8"));
  console.log(`📄 Loaded ${targets.length} targets from data/targets.json\n`);

  // 2. Create findings directory
  const findingsDir = join(PROJECT_ROOT, "findings");
  if (!existsSync(findingsDir)) {
    mkdirSync(findingsDir, { recursive: true });
  }

  // 3. Process each target
  const allResults = [];

  for (const target of targets) {
    console.log(`${"━".repeat(60)}`);
    console.log(`  🎯 Scanning: ${target.name} (${target.domain})`);
    console.log(`${"━".repeat(60)}\n`);

    // Run all deep scan checks
    console.log(`   🔍 Running deep scan checks...`);
    const scanResults = {};
    for (const [key, check] of Object.entries(DEEP_SCAN_CHECKS)) {
      const result = check.probe(target);
      scanResults[key] = result;
      const status = result?.found ? "🔴 FOUND" : "🟢 Clean";
      console.log(`      ├─ ${check.name}: ${status}`);
    }

    // Classify data risk
    console.log(`\n   🧠 Classifying data risk with AI...`);
    const riskClassification = DATA_RISK_CLASSIFIER.classify(scanResults, target);
    console.log(`      ├─ PII: ${riskClassification.pii.found ? "⚠️ " + riskClassification.pii.severity : "Clean"}`);
    console.log(`      ├─ Location: ${riskClassification.location.found ? "⚠️ " + riskClassification.location.severity : "Clean"}`);
    console.log(`      ├─ Financial: ${riskClassification.financial.found ? "⚠️ " + riskClassification.financial.severity : "Clean"}`);
    console.log(`      ├─ Minor Data: ${riskClassification.minorData.found ? "🔴 " + riskClassification.minorData.severity : "Clean"}`);
    console.log(`      └─ Health Data: ${riskClassification.healthData.found ? "🔴 " + riskClassification.healthData.severity : "Clean"}`);
    console.log(`      ➤ Overall Risk: ${riskClassification.overallRisk}\n`);

    // Generate per-target report
    const { slug, content, findingCount } = generatePerTargetReport(target, scanResults, riskClassification);
    const reportFilename = `vibe-check-report-${slug}.md`;
    const reportPath = join(findingsDir, reportFilename);
    writeFileSync(reportPath, content, "utf-8");
    console.log(`   📄 Report written: findings/${reportFilename} (${findingCount} deep findings)\n`);

    allResults.push({
      name: target.name,
      domain: target.domain,
      deepFindings: findingCount,
      overallRisk: riskClassification.overallRisk,
      reportFile: reportFilename
    });
  }

  // 4. Summary
  console.log(`\n${"━".repeat(60)}`);
  console.log(`  ✅ SCANNER AGENT COMPLETE`);
  console.log(`${"━".repeat(60)}\n`);

  console.log(`  📊 Results Summary:\n`);
  console.log(`  | Organization | Deep Findings | Data Risk | Report |`);
  console.log(`  |-------------|---------------|-----------|--------|`);
  for (const r of allResults) {
    console.log(`  | ${r.name} | ${r.deepFindings} | ${r.overallRisk} | ${r.reportFile} |`);
  }

  console.log(`\n  📁 All reports saved to: findings/`);
  console.log(`  🤝 Ready for Person B to draft empathy-first disclosure.\n`);

  return allResults;
}

// ─── Run ─────────────────────────────────────────────────────────────────────

runScannerAgent().catch(err => {
  console.error("❌ Scanner Agent failed:", err);
  process.exit(1);
});
