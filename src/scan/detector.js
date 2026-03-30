// ============================================================================
// NGO-Guardian — Scan: Vulnerability Detector
// Simulates detection of common vibe-code vulnerabilities
// ============================================================================

/**
 * Vulnerability templates — common issues in vibe-coded NGO apps
 */
const VULN_TEMPLATES = {
  ENV_EXPOSED: {
    id: "VCC-001",
    category: "Secrets Exposure",
    title: "Environment file publicly accessible",
    severity: "CRITICAL",
    description: "The .env file is accessible at the root of the web server, exposing database credentials, API keys, and other secrets.",
    remediation: "Add .env to your web server's deny list. For Vercel/Netlify, ensure .env is in .gitignore and use platform environment variables instead.",
    cwe: "CWE-200"
  },
  API_KEY_CLIENT: {
    id: "VCC-002",
    category: "Secrets Exposure",
    title: "API keys exposed in client-side JavaScript bundle",
    severity: "CRITICAL",
    description: "Sensitive API keys (Supabase service_role, Firebase admin, Stripe secret) are embedded in client-side JavaScript bundles, visible to any visitor.",
    remediation: "Move sensitive keys to server-side environment variables. Use anon/public keys on the client and enforce Row Level Security (RLS) or Firestore rules.",
    cwe: "CWE-798"
  },
  OPEN_API_NO_AUTH: {
    id: "VCC-003",
    category: "Broken Access Control",
    title: "API endpoints accessible without authentication",
    severity: "HIGH",
    description: "REST/GraphQL API endpoints return sensitive data (donor records, beneficiary PII, case files) without requiring authentication tokens.",
    remediation: "Implement authentication middleware on all API routes. Use JWT validation or session-based auth. Apply the principle of least privilege.",
    cwe: "CWE-306"
  },
  MISSING_CSP: {
    id: "VCC-004",
    category: "Missing Security Headers",
    title: "No Content-Security-Policy header",
    severity: "HIGH",
    description: "The application does not set a Content-Security-Policy header, making it vulnerable to Cross-Site Scripting (XSS) and data injection attacks.",
    remediation: "Add a Content-Security-Policy header. Start with a restrictive policy and loosen as needed. At minimum: default-src 'self'.",
    cwe: "CWE-1021"
  },
  MISSING_HSTS: {
    id: "VCC-005",
    category: "Missing Security Headers",
    title: "No Strict-Transport-Security header",
    severity: "HIGH",
    description: "The server does not enforce HTTPS via HSTS, leaving users vulnerable to downgrade attacks and cookie hijacking.",
    remediation: "Add Strict-Transport-Security header with max-age of at least 31536000 (1 year). Include includeSubDomains directive.",
    cwe: "CWE-319"
  },
  OPEN_GRAPHQL: {
    id: "VCC-006",
    category: "Information Disclosure",
    title: "GraphQL introspection enabled in production",
    severity: "MEDIUM",
    description: "The GraphQL endpoint allows introspection queries, exposing the entire API schema including sensitive types and mutations.",
    remediation: "Disable introspection in production. Most GraphQL servers have a configuration option for this.",
    cwe: "CWE-200"
  },
  SUPABASE_RLS: {
    id: "VCC-007",
    category: "Broken Access Control",
    title: "Supabase tables without Row Level Security",
    severity: "CRITICAL",
    description: "Supabase tables containing sensitive data (donors, beneficiaries, payments) have RLS disabled, allowing any authenticated user to read/write all rows.",
    remediation: "Enable RLS on all tables in Supabase dashboard. Create policies that restrict access based on user ID or role.",
    cwe: "CWE-862"
  },
  FIREBASE_RULES_OPEN: {
    id: "VCC-008",
    category: "Broken Access Control",
    title: "Firebase Firestore rules allow public read/write",
    severity: "CRITICAL",
    description: "Firestore security rules are set to allow read/write for all users, meaning anyone can access or modify the entire database.",
    remediation: "Update Firestore rules to restrict access. Replace 'allow read, write: if true' with proper authentication and authorization checks.",
    cwe: "CWE-862"
  },
  CORS_WILDCARD: {
    id: "VCC-009",
    category: "Security Misconfiguration",
    title: "CORS policy allows all origins",
    severity: "MEDIUM",
    description: "The API sets Access-Control-Allow-Origin: *, allowing any website to make authenticated requests to the API.",
    remediation: "Restrict CORS to only your frontend domain(s). Never use wildcard (*) with credentials.",
    cwe: "CWE-942"
  },
  SOURCE_MAP_EXPOSED: {
    id: "VCC-010",
    category: "Information Disclosure",
    title: "JavaScript source maps accessible in production",
    severity: "LOW",
    description: "Production JavaScript bundles have associated .map files accessible, exposing original source code including comments and variable names.",
    remediation: "Disable source map generation for production builds or restrict .map file access via server configuration.",
    cwe: "CWE-540"
  }
};

/**
 * Simulated vulnerability assignments per target domain
 */
const TARGET_VULNS = {
  "globalwaterinitiative.org": [
    { ...VULN_TEMPLATES.MISSING_CSP, location: "app.globalwaterinitiative.org" },
    { ...VULN_TEMPLATES.OPEN_API_NO_AUTH, location: "/api/v1/donors — returns 200 with donor PII without auth token" },
    { ...VULN_TEMPLATES.SOURCE_MAP_EXPOSED, location: "app.globalwaterinitiative.org/_next/static/*.js.map" },
    { ...VULN_TEMPLATES.CORS_WILDCARD, location: "api.globalwaterinitiative.org — Access-Control-Allow-Origin: *" }
  ],
  "ecorestorefd.org": [
    { ...VULN_TEMPLATES.ENV_EXPOSED, location: "portal.ecorestorefd.org/.env — contains SUPABASE_SERVICE_ROLE_KEY" },
    { ...VULN_TEMPLATES.SUPABASE_RLS, location: "volunteers, donations, sites tables — RLS disabled" },
    { ...VULN_TEMPLATES.API_KEY_CLIENT, location: "Main bundle contains SUPABASE_SERVICE_ROLE_KEY (not anon key)" },
    { ...VULN_TEMPLATES.MISSING_HSTS, location: "portal.ecorestorefd.org — no HSTS header" },
    { ...VULN_TEMPLATES.MISSING_CSP, location: "portal.ecorestorefd.org — no CSP header" }
  ],
  "refugeeaidnetwork.org": [
    { ...VULN_TEMPLATES.FIREBASE_RULES_OPEN, location: "Firestore — 'cases' and 'personnel' collections publicly readable" },
    { ...VULN_TEMPLATES.OPEN_GRAPHQL, location: "refugeeaidnetwork.org/graphql — introspection returns full schema" },
    { ...VULN_TEMPLATES.MISSING_CSP, location: "app.refugeeaidnetwork.org — no CSP header" },
    { ...VULN_TEMPLATES.API_KEY_CLIENT, location: "Firebase config in bundle includes measurementId and appId" }
  ],
  "oceanguardalliance.org": [
    { ...VULN_TEMPLATES.SUPABASE_RLS, location: "sensors, reports tables — RLS disabled, anon key grants full access" },
    { ...VULN_TEMPLATES.API_KEY_CLIENT, location: "SUPABASE_ANON_KEY in client with no RLS = full DB access" },
    { ...VULN_TEMPLATES.MISSING_HSTS, location: "All subdomains — no HSTS" },
    { ...VULN_TEMPLATES.MISSING_CSP, location: "All subdomains — no CSP" },
    { ...VULN_TEMPLATES.CORS_WILDCARD, location: "api.oceanguardalliance.org — wildcard CORS" },
    { ...VULN_TEMPLATES.OPEN_API_NO_AUTH, location: "/api/sensors — returns raw sensor data without auth" }
  ],
  "childbridge-intl.org": [
    { ...VULN_TEMPLATES.ENV_EXPOSED, location: "portal.childbridge-intl.org/.env.local — contains STRIPE_SECRET_KEY" },
    { ...VULN_TEMPLATES.API_KEY_CLIENT, location: "Stripe publishable key + partial secret in Nuxt client bundle" },
    { ...VULN_TEMPLATES.MISSING_CSP, location: "portal.childbridge-intl.org — no CSP header" },
    { ...VULN_TEMPLATES.OPEN_API_NO_AUTH, location: "/api/children — returns children profiles with photos without auth" }
  ]
};

/**
 * Run vulnerability detection on a fingerprinted target
 */
export function detectVulnerabilities(target) {
  const vulns = TARGET_VULNS[target.domain] || [];

  return {
    domain: target.domain,
    name: target.name,
    vulnerabilities: vulns,
    counts: {
      critical: vulns.filter(v => v.severity === "CRITICAL").length,
      high: vulns.filter(v => v.severity === "HIGH").length,
      medium: vulns.filter(v => v.severity === "MEDIUM").length,
      low: vulns.filter(v => v.severity === "LOW").length,
      total: vulns.length
    }
  };
}

/**
 * Scan all targets
 */
export function scanAll(targets) {
  console.log("🛡️  [DETECTOR] Running vulnerability detection...\n");

  const results = targets.map(target => {
    const result = detectVulnerabilities(target);

    const severityBar =
      "🔴".repeat(result.counts.critical) +
      "🟠".repeat(result.counts.high) +
      "🟡".repeat(result.counts.medium) +
      "⚪".repeat(result.counts.low);

    console.log(`   ${target.name} (${target.domain})`);
    console.log(`      ├─ Findings: ${result.counts.total} (${result.counts.critical}C / ${result.counts.high}H / ${result.counts.medium}M / ${result.counts.low}L)`);
    console.log(`      └─ ${severityBar}`);

    return { ...target, scan: result };
  });

  const totalVulns = results.reduce((sum, r) => sum + r.scan.counts.total, 0);
  const totalCritical = results.reduce((sum, r) => sum + r.scan.counts.critical, 0);
  console.log(`\n🛡️  [DETECTOR] Complete — ${totalVulns} total findings across ${results.length} targets (${totalCritical} critical).\n`);

  return results;
}

export { VULN_TEMPLATES };
