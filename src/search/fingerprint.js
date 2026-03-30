// ============================================================================
// NGO-Guardian — Agentic Search: Fingerprint Module
// Simulates HTTP header fingerprinting to detect "vibe-coded" tech stacks
// ============================================================================

/**
 * Known "vibe-code" stack signatures — quick-ship platforms
 * that are commonly deployed without custom security layers
 */
const VIBE_STACK_SIGNATURES = {
  vercel: {
    name: "Vercel",
    headers: { "x-vercel-id": "iad1::xxxxx-1234567890", "server": "Vercel" },
    risk: "Often deployed with default configs, no rate limiting"
  },
  supabase: {
    name: "Supabase",
    headers: { "x-supabase-info": "supabase-js/2.x", "server": "Supabase" },
    risk: "RLS policies often misconfigured, anon keys in client bundles"
  },
  firebase: {
    name: "Firebase",
    headers: { "x-firebase-info": "firebase-js-sdk/9.x", "server": "Google Frontend" },
    risk: "Firestore rules commonly left open during development"
  },
  netlify: {
    name: "Netlify",
    headers: { "x-nf-request-id": "01ABCDEF-1234-5678-9ABC-DEF012345678", "server": "Netlify" },
    risk: "Serverless functions may expose environment variables"
  },
  railway: {
    name: "Railway",
    headers: { "x-railway-request-id": "req_abc123", "server": "Railway" },
    risk: "Quick deploy often skips security hardening"
  }
};

/**
 * Security headers that SHOULD be present on production sites
 */
const REQUIRED_SECURITY_HEADERS = [
  { name: "Strict-Transport-Security", importance: "CRITICAL", description: "Forces HTTPS connections" },
  { name: "X-Content-Type-Options", importance: "HIGH", description: "Prevents MIME sniffing" },
  { name: "X-Frame-Options", importance: "HIGH", description: "Prevents clickjacking" },
  { name: "Content-Security-Policy", importance: "CRITICAL", description: "Prevents XSS and injection attacks" },
  { name: "X-XSS-Protection", importance: "MEDIUM", description: "Legacy XSS filter" },
  { name: "Referrer-Policy", importance: "MEDIUM", description: "Controls referrer information leakage" },
  { name: "Permissions-Policy", importance: "MEDIUM", description: "Controls browser feature access" }
];

/**
 * Simulated fingerprint profiles per NGO domain
 */
const FINGERPRINT_DATA = {
  "globalwaterinitiative.org": {
    stack: "vercel",
    framework: "Next.js 14",
    missingHeaders: ["Content-Security-Policy", "Permissions-Policy", "Referrer-Policy"],
    presentHeaders: ["Strict-Transport-Security", "X-Content-Type-Options", "X-Frame-Options", "X-XSS-Protection"]
  },
  "ecorestorefd.org": {
    stack: "supabase",
    framework: "React + Vite",
    missingHeaders: ["Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options", "Permissions-Policy", "Referrer-Policy"],
    presentHeaders: ["X-Content-Type-Options", "X-XSS-Protection"]
  },
  "refugeeaidnetwork.org": {
    stack: "firebase",
    framework: "Next.js 13",
    missingHeaders: ["Content-Security-Policy", "X-Frame-Options", "Referrer-Policy"],
    presentHeaders: ["Strict-Transport-Security", "X-Content-Type-Options", "X-XSS-Protection", "Permissions-Policy"]
  },
  "oceanguardalliance.org": {
    stack: "supabase",
    framework: "SvelteKit",
    missingHeaders: ["Strict-Transport-Security", "Content-Security-Policy", "X-Content-Type-Options", "X-Frame-Options", "Permissions-Policy", "Referrer-Policy", "X-XSS-Protection"],
    presentHeaders: []
  },
  "childbridge-intl.org": {
    stack: "netlify",
    framework: "Nuxt 3",
    missingHeaders: ["Content-Security-Policy", "Permissions-Policy"],
    presentHeaders: ["Strict-Transport-Security", "X-Content-Type-Options", "X-Frame-Options", "X-XSS-Protection", "Referrer-Policy"]
  }
};

/**
 * Fingerprint a target — detect tech stack and evaluate security headers
 */
export function fingerprintTarget(target) {
  const data = FINGERPRINT_DATA[target.domain];

  if (!data) {
    return {
      domain: target.domain,
      vibeStack: null,
      isVibeCoded: false,
      securityHeaders: { missing: [], present: [] },
      headerScore: 100
    };
  }

  const stackInfo = VIBE_STACK_SIGNATURES[data.stack];
  const totalHeaders = REQUIRED_SECURITY_HEADERS.length;
  const missingCount = data.missingHeaders.length;
  const headerScore = Math.round(((totalHeaders - missingCount) / totalHeaders) * 100);

  const missingDetails = data.missingHeaders.map(name => {
    const info = REQUIRED_SECURITY_HEADERS.find(h => h.name === name);
    return { name, importance: info?.importance || "MEDIUM", description: info?.description || "" };
  });

  return {
    domain: target.domain,
    vibeStack: {
      platform: stackInfo.name,
      framework: data.framework,
      detectedHeaders: stackInfo.headers,
      riskNote: stackInfo.risk
    },
    isVibeCoded: true,
    securityHeaders: {
      missing: missingDetails,
      present: data.presentHeaders
    },
    headerScore
  };
}

/**
 * Fingerprint all targets in a batch
 */
export function fingerprintAll(targets) {
  console.log("🔬 [FINGERPRINT] Analyzing HTTP headers & tech stacks...\n");

  const results = targets.map(target => {
    const result = fingerprintTarget(target);

    const vibeTag = result.isVibeCoded
      ? `⚡ ${result.vibeStack.platform} + ${result.vibeStack.framework}`
      : "🔒 Custom Stack";

    const headerTag = result.headerScore < 50
      ? `🔴 ${result.headerScore}%`
      : result.headerScore < 75
        ? `🟡 ${result.headerScore}%`
        : `🟢 ${result.headerScore}%`;

    console.log(`   ${target.domain}`);
    console.log(`      ├─ Stack: ${vibeTag}`);
    console.log(`      ├─ Security Headers: ${headerTag}`);
    console.log(`      └─ Missing: ${result.securityHeaders.missing.map(h => h.name).join(", ") || "None"}`);

    return { ...target, fingerprint: result };
  });

  const vibeCoded = results.filter(r => r.fingerprint.isVibeCoded).length;
  console.log(`\n🔬 [FINGERPRINT] Complete — ${vibeCoded}/${results.length} targets show vibe-coded signatures.\n`);

  return results;
}

export { REQUIRED_SECURITY_HEADERS, VIBE_STACK_SIGNATURES };
