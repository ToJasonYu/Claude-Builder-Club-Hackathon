# 🛡️ NGO-Guardian — Vibe Check Report

> **Generated**: 2026-03-29T23:59:15.818Z
> **Scanned Targets**: 5
> **Pipeline**: Discovery → Fingerprint → Scan → Score

---

## 📋 Executive Summary

| Metric | Value |
|--------|-------|
| Total Targets Scanned | 5 |
| Total Vulnerabilities | 23 |
| Critical Findings | 9 |
| Average Vibe Risk Score | 90/100 |

## 🏆 Risk Ranking

| Rank | Organization | Score | Risk Level | Critical |
|------|-------------|-------|------------|----------|
| 1 | EcoRestore Foundation | 100/100 | 🔴 SEVERE | 3 |
| 2 | OceanGuard Alliance | 100/100 | 🔴 SEVERE | 2 |
| 3 | ChildBridge International | 100/100 | 🔴 SEVERE | 2 |
| 4 | Refugee Aid Network | 95/100 | 🔴 SEVERE | 2 |
| 5 | Global Water Initiative | 53/100 | 🟡 MODERATE | 0 |

---

## 🔍 EcoRestore Foundation

- **Domain**: `ecorestorefd.org`
- **Sector**: environmental
- **Mission**: Restoring degraded ecosystems through community-led reforestation
- **Tech Stack**: Supabase + React + Vite
- **Vibe Risk Score**: **100/100** 🔴 SEVERE
- **Security Header Coverage**: 29%

### Subdomains

- `portal.ecorestorefd.org`
- `api.ecorestorefd.org`
- `volunteer.ecorestorefd.org`

### Findings

#### 🔴 [CRITICAL] Environment file publicly accessible (VCC-001)

- **Category**: Secrets Exposure
- **CWE**: CWE-200
- **Location**: `portal.ecorestorefd.org/.env — contains SUPABASE_SERVICE_ROLE_KEY`
- **Description**: The .env file is accessible at the root of the web server, exposing database credentials, API keys, and other secrets.
- **Remediation**: Add .env to your web server's deny list. For Vercel/Netlify, ensure .env is in .gitignore and use platform environment variables instead.

#### 🔴 [CRITICAL] Supabase tables without Row Level Security (VCC-007)

- **Category**: Broken Access Control
- **CWE**: CWE-862
- **Location**: `volunteers, donations, sites tables — RLS disabled`
- **Description**: Supabase tables containing sensitive data (donors, beneficiaries, payments) have RLS disabled, allowing any authenticated user to read/write all rows.
- **Remediation**: Enable RLS on all tables in Supabase dashboard. Create policies that restrict access based on user ID or role.

#### 🔴 [CRITICAL] API keys exposed in client-side JavaScript bundle (VCC-002)

- **Category**: Secrets Exposure
- **CWE**: CWE-798
- **Location**: `Main bundle contains SUPABASE_SERVICE_ROLE_KEY (not anon key)`
- **Description**: Sensitive API keys (Supabase service_role, Firebase admin, Stripe secret) are embedded in client-side JavaScript bundles, visible to any visitor.
- **Remediation**: Move sensitive keys to server-side environment variables. Use anon/public keys on the client and enforce Row Level Security (RLS) or Firestore rules.

#### 🟠 [HIGH] No Strict-Transport-Security header (VCC-005)

- **Category**: Missing Security Headers
- **CWE**: CWE-319
- **Location**: `portal.ecorestorefd.org — no HSTS header`
- **Description**: The server does not enforce HTTPS via HSTS, leaving users vulnerable to downgrade attacks and cookie hijacking.
- **Remediation**: Add Strict-Transport-Security header with max-age of at least 31536000 (1 year). Include includeSubDomains directive.

#### 🟠 [HIGH] No Content-Security-Policy header (VCC-004)

- **Category**: Missing Security Headers
- **CWE**: CWE-1021
- **Location**: `portal.ecorestorefd.org — no CSP header`
- **Description**: The application does not set a Content-Security-Policy header, making it vulnerable to Cross-Site Scripting (XSS) and data injection attacks.
- **Remediation**: Add a Content-Security-Policy header. Start with a restrictive policy and loosen as needed. At minimum: default-src 'self'.

### Missing Security Headers

| Header | Importance | Description |
|--------|-----------|-------------|
| `Strict-Transport-Security` | CRITICAL | Forces HTTPS connections |
| `Content-Security-Policy` | CRITICAL | Prevents XSS and injection attacks |
| `X-Frame-Options` | HIGH | Prevents clickjacking |
| `Permissions-Policy` | MEDIUM | Controls browser feature access |
| `Referrer-Policy` | MEDIUM | Controls referrer information leakage |

---

## 🔍 OceanGuard Alliance

- **Domain**: `oceanguardalliance.org`
- **Sector**: environmental
- **Mission**: Marine conservation and ocean pollution monitoring
- **Tech Stack**: Supabase + SvelteKit
- **Vibe Risk Score**: **100/100** 🔴 SEVERE
- **Security Header Coverage**: N/A%

### Subdomains

- `data.oceanguardalliance.org`
- `api.oceanguardalliance.org`
- `map.oceanguardalliance.org`

### Findings

#### 🔴 [CRITICAL] Supabase tables without Row Level Security (VCC-007)

- **Category**: Broken Access Control
- **CWE**: CWE-862
- **Location**: `sensors, reports tables — RLS disabled, anon key grants full access`
- **Description**: Supabase tables containing sensitive data (donors, beneficiaries, payments) have RLS disabled, allowing any authenticated user to read/write all rows.
- **Remediation**: Enable RLS on all tables in Supabase dashboard. Create policies that restrict access based on user ID or role.

#### 🔴 [CRITICAL] API keys exposed in client-side JavaScript bundle (VCC-002)

- **Category**: Secrets Exposure
- **CWE**: CWE-798
- **Location**: `SUPABASE_ANON_KEY in client with no RLS = full DB access`
- **Description**: Sensitive API keys (Supabase service_role, Firebase admin, Stripe secret) are embedded in client-side JavaScript bundles, visible to any visitor.
- **Remediation**: Move sensitive keys to server-side environment variables. Use anon/public keys on the client and enforce Row Level Security (RLS) or Firestore rules.

#### 🟠 [HIGH] No Strict-Transport-Security header (VCC-005)

- **Category**: Missing Security Headers
- **CWE**: CWE-319
- **Location**: `All subdomains — no HSTS`
- **Description**: The server does not enforce HTTPS via HSTS, leaving users vulnerable to downgrade attacks and cookie hijacking.
- **Remediation**: Add Strict-Transport-Security header with max-age of at least 31536000 (1 year). Include includeSubDomains directive.

#### 🟠 [HIGH] No Content-Security-Policy header (VCC-004)

- **Category**: Missing Security Headers
- **CWE**: CWE-1021
- **Location**: `All subdomains — no CSP`
- **Description**: The application does not set a Content-Security-Policy header, making it vulnerable to Cross-Site Scripting (XSS) and data injection attacks.
- **Remediation**: Add a Content-Security-Policy header. Start with a restrictive policy and loosen as needed. At minimum: default-src 'self'.

#### 🟠 [HIGH] API endpoints accessible without authentication (VCC-003)

- **Category**: Broken Access Control
- **CWE**: CWE-306
- **Location**: `/api/sensors — returns raw sensor data without auth`
- **Description**: REST/GraphQL API endpoints return sensitive data (donor records, beneficiary PII, case files) without requiring authentication tokens.
- **Remediation**: Implement authentication middleware on all API routes. Use JWT validation or session-based auth. Apply the principle of least privilege.

#### 🟡 [MEDIUM] CORS policy allows all origins (VCC-009)

- **Category**: Security Misconfiguration
- **CWE**: CWE-942
- **Location**: `api.oceanguardalliance.org — wildcard CORS`
- **Description**: The API sets Access-Control-Allow-Origin: *, allowing any website to make authenticated requests to the API.
- **Remediation**: Restrict CORS to only your frontend domain(s). Never use wildcard (*) with credentials.

### Missing Security Headers

| Header | Importance | Description |
|--------|-----------|-------------|
| `Strict-Transport-Security` | CRITICAL | Forces HTTPS connections |
| `Content-Security-Policy` | CRITICAL | Prevents XSS and injection attacks |
| `X-Content-Type-Options` | HIGH | Prevents MIME sniffing |
| `X-Frame-Options` | HIGH | Prevents clickjacking |
| `Permissions-Policy` | MEDIUM | Controls browser feature access |
| `Referrer-Policy` | MEDIUM | Controls referrer information leakage |
| `X-XSS-Protection` | MEDIUM | Legacy XSS filter |

---

## 🔍 ChildBridge International

- **Domain**: `childbridge-intl.org`
- **Sector**: humanitarian
- **Mission**: Education and welfare programs for orphaned and at-risk children
- **Tech Stack**: Netlify + Nuxt 3
- **Vibe Risk Score**: **100/100** 🔴 SEVERE
- **Security Header Coverage**: 71%

> ⚠️ **CRITICAL DATA AT RISK** — This organization handles sensitive data that may be exposed.

> - **Protected Minor PII**: Child profiles, photos, welfare records

### Subdomains

- `portal.childbridge-intl.org`
- `api.childbridge-intl.org`
- `sponsor.childbridge-intl.org`
- `files.childbridge-intl.org`

### Findings

#### 🔴 [CRITICAL] Environment file publicly accessible (VCC-001)

- **Category**: Secrets Exposure
- **CWE**: CWE-200
- **Location**: `portal.childbridge-intl.org/.env.local — contains STRIPE_SECRET_KEY`
- **Description**: The .env file is accessible at the root of the web server, exposing database credentials, API keys, and other secrets.
- **Remediation**: Add .env to your web server's deny list. For Vercel/Netlify, ensure .env is in .gitignore and use platform environment variables instead.

#### 🔴 [CRITICAL] API keys exposed in client-side JavaScript bundle (VCC-002)

- **Category**: Secrets Exposure
- **CWE**: CWE-798
- **Location**: `Stripe publishable key + partial secret in Nuxt client bundle`
- **Description**: Sensitive API keys (Supabase service_role, Firebase admin, Stripe secret) are embedded in client-side JavaScript bundles, visible to any visitor.
- **Remediation**: Move sensitive keys to server-side environment variables. Use anon/public keys on the client and enforce Row Level Security (RLS) or Firestore rules.

#### 🟠 [HIGH] No Content-Security-Policy header (VCC-004)

- **Category**: Missing Security Headers
- **CWE**: CWE-1021
- **Location**: `portal.childbridge-intl.org — no CSP header`
- **Description**: The application does not set a Content-Security-Policy header, making it vulnerable to Cross-Site Scripting (XSS) and data injection attacks.
- **Remediation**: Add a Content-Security-Policy header. Start with a restrictive policy and loosen as needed. At minimum: default-src 'self'.

#### 🟠 [HIGH] API endpoints accessible without authentication (VCC-003)

- **Category**: Broken Access Control
- **CWE**: CWE-306
- **Location**: `/api/children — returns children profiles with photos without auth`
- **Description**: REST/GraphQL API endpoints return sensitive data (donor records, beneficiary PII, case files) without requiring authentication tokens.
- **Remediation**: Implement authentication middleware on all API routes. Use JWT validation or session-based auth. Apply the principle of least privilege.

### Missing Security Headers

| Header | Importance | Description |
|--------|-----------|-------------|
| `Content-Security-Policy` | CRITICAL | Prevents XSS and injection attacks |
| `Permissions-Policy` | MEDIUM | Controls browser feature access |

---

## 🔍 Refugee Aid Network

- **Domain**: `refugeeaidnetwork.org`
- **Sector**: humanitarian
- **Mission**: Emergency relief and long-term support for displaced populations
- **Tech Stack**: Firebase + Next.js 13
- **Vibe Risk Score**: **95/100** 🔴 SEVERE
- **Security Header Coverage**: 57%

> ⚠️ **CRITICAL DATA AT RISK** — This organization handles sensitive data that may be exposed.

> - **Case Records**: Refugee status, legal cases, sensitive personal histories

### Subdomains

- `app.refugeeaidnetwork.org`
- `api.refugeeaidnetwork.org`
- `intake.refugeeaidnetwork.org`
- `maps.refugeeaidnetwork.org`

### Findings

#### 🔴 [CRITICAL] Firebase Firestore rules allow public read/write (VCC-008)

- **Category**: Broken Access Control
- **CWE**: CWE-862
- **Location**: `Firestore — 'cases' and 'personnel' collections publicly readable`
- **Description**: Firestore security rules are set to allow read/write for all users, meaning anyone can access or modify the entire database.
- **Remediation**: Update Firestore rules to restrict access. Replace 'allow read, write: if true' with proper authentication and authorization checks.

#### 🔴 [CRITICAL] API keys exposed in client-side JavaScript bundle (VCC-002)

- **Category**: Secrets Exposure
- **CWE**: CWE-798
- **Location**: `Firebase config in bundle includes measurementId and appId`
- **Description**: Sensitive API keys (Supabase service_role, Firebase admin, Stripe secret) are embedded in client-side JavaScript bundles, visible to any visitor.
- **Remediation**: Move sensitive keys to server-side environment variables. Use anon/public keys on the client and enforce Row Level Security (RLS) or Firestore rules.

#### 🟠 [HIGH] No Content-Security-Policy header (VCC-004)

- **Category**: Missing Security Headers
- **CWE**: CWE-1021
- **Location**: `app.refugeeaidnetwork.org — no CSP header`
- **Description**: The application does not set a Content-Security-Policy header, making it vulnerable to Cross-Site Scripting (XSS) and data injection attacks.
- **Remediation**: Add a Content-Security-Policy header. Start with a restrictive policy and loosen as needed. At minimum: default-src 'self'.

#### 🟡 [MEDIUM] GraphQL introspection enabled in production (VCC-006)

- **Category**: Information Disclosure
- **CWE**: CWE-200
- **Location**: `refugeeaidnetwork.org/graphql — introspection returns full schema`
- **Description**: The GraphQL endpoint allows introspection queries, exposing the entire API schema including sensitive types and mutations.
- **Remediation**: Disable introspection in production. Most GraphQL servers have a configuration option for this.

### Missing Security Headers

| Header | Importance | Description |
|--------|-----------|-------------|
| `Content-Security-Policy` | CRITICAL | Prevents XSS and injection attacks |
| `X-Frame-Options` | HIGH | Prevents clickjacking |
| `Referrer-Policy` | MEDIUM | Controls referrer information leakage |

---

## 🔍 Global Water Initiative

- **Domain**: `globalwaterinitiative.org`
- **Sector**: humanitarian
- **Mission**: Providing clean water access to underserved communities worldwide
- **Tech Stack**: Vercel + Next.js 14
- **Vibe Risk Score**: **53/100** 🟡 MODERATE
- **Security Header Coverage**: 57%

> ⚠️ **CRITICAL DATA AT RISK** — This organization handles sensitive data that may be exposed.

> - **Protected PII**: Location data, health records, family info of vulnerable populations

### Subdomains

- `app.globalwaterinitiative.org`
- `api.globalwaterinitiative.org`
- `donate.globalwaterinitiative.org`
- `dashboard.globalwaterinitiative.org`

### Findings

#### 🟠 [HIGH] No Content-Security-Policy header (VCC-004)

- **Category**: Missing Security Headers
- **CWE**: CWE-1021
- **Location**: `app.globalwaterinitiative.org`
- **Description**: The application does not set a Content-Security-Policy header, making it vulnerable to Cross-Site Scripting (XSS) and data injection attacks.
- **Remediation**: Add a Content-Security-Policy header. Start with a restrictive policy and loosen as needed. At minimum: default-src 'self'.

#### 🟠 [HIGH] API endpoints accessible without authentication (VCC-003)

- **Category**: Broken Access Control
- **CWE**: CWE-306
- **Location**: `/api/v1/donors — returns 200 with donor PII without auth token`
- **Description**: REST/GraphQL API endpoints return sensitive data (donor records, beneficiary PII, case files) without requiring authentication tokens.
- **Remediation**: Implement authentication middleware on all API routes. Use JWT validation or session-based auth. Apply the principle of least privilege.

#### 🟡 [MEDIUM] CORS policy allows all origins (VCC-009)

- **Category**: Security Misconfiguration
- **CWE**: CWE-942
- **Location**: `api.globalwaterinitiative.org — Access-Control-Allow-Origin: *`
- **Description**: The API sets Access-Control-Allow-Origin: *, allowing any website to make authenticated requests to the API.
- **Remediation**: Restrict CORS to only your frontend domain(s). Never use wildcard (*) with credentials.

#### ⚪ [LOW] JavaScript source maps accessible in production (VCC-010)

- **Category**: Information Disclosure
- **CWE**: CWE-540
- **Location**: `app.globalwaterinitiative.org/_next/static/*.js.map`
- **Description**: Production JavaScript bundles have associated .map files accessible, exposing original source code including comments and variable names.
- **Remediation**: Disable source map generation for production builds or restrict .map file access via server configuration.

### Missing Security Headers

| Header | Importance | Description |
|--------|-----------|-------------|
| `Content-Security-Policy` | CRITICAL | Prevents XSS and injection attacks |
| `Permissions-Policy` | MEDIUM | Controls browser feature access |
| `Referrer-Policy` | MEDIUM | Controls referrer information leakage |

---

## 🤝 About This Report

This report was generated by **NGO-Guardian**, a social-impact security platform.
We are "Guardians," not "Hunters." Our mission is to help under-resourced organizations
protect their digital infrastructure and the vulnerable data they steward.

> **Ethical Commitment**: Zero-exploitation. Privacy-first. Empathy always.

*For questions or support with remediation, please contact the NGO-Guardian team.*
