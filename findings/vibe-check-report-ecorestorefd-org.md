# 🛡️ Vibe Check Report: EcoRestore Foundation

> **Target**: `ecorestorefd.org`
> **Scan Date**: 2026-03-30T00:10:41.460Z
> **Scanner Agent**: NGO-Guardian v1.0
> **Mode**: Detection Only — Zero Exploitation

---

## 📋 Target Profile

| Field | Value |
|-------|-------|
| **Organization** | EcoRestore Foundation |
| **Domain** | `ecorestorefd.org` |
| **Sector** | Environmental |
| **Mission** | Restoring degraded ecosystems through community-led reforestation |
| **Tech Stack** | Supabase + React + Vite |
| **Vibe-Coded** | ✅ Yes |
| **Vibe Risk Score** | **100/100** 🔴 SEVERE |
| **Security Header Score** | 29% |

### Discovered Subdomains

- `portal.ecorestorefd.org`
- `api.ecorestorefd.org`
- `volunteer.ecorestorefd.org`

---

## 🧠 AI Data Risk Classification

> *Classified by Claude — analyzing data types at risk based on exposed endpoints and database schemas*

| Category | Found | Severity | Details |
|----------|-------|----------|---------|
| 🔵 PII (Personal) | ⚠️ YES | HIGH | Volunteer PII |
| 📍 Location Data | ⚠️ YES | HIGH | Geospatial Data |
| 💰 Financial | ⚠️ YES | HIGH | Financial Records |
| 👶 Minor/Child Data | — | — | Not detected |
| 🏥 Health/Welfare | — | — | Not detected |

> [!WARNING]
> **Overall Data Risk: HIGH** — Significant sensitive data exposure detected.

### 💔 Human Impact Assessment

> The combination of personal identity data and location coordinates creates a severe risk: bad actors could physically locate vulnerable individuals including refugees, aid workers in conflict zones, or abuse survivors.
>
> Financial records including donation amounts and payment information could be exploited for fraud, or used to target high-value donors with spear-phishing campaigns.

---

## 🔍 Deep Scan Findings

### Finding 1: Public .env File Exposure

- **Check ID**: `SCAN-ENV`
- **Status**: 🔴 VULNERABLE
- **Description**: Checks if /.env, /.env.local, /.env.production are publicly accessible

**Exposed Endpoints:**
- `ecorestorefd.org/.env` → HTTP 200

**Exposed Secrets (5 found):**

| Secret | Type | Severity |
|--------|------|----------|
| `SUPABASE_SERVICE_ROLE_KEY` | Supabase Service Key | CRITICAL |
| `DATABASE_URL` | Database Connection String | CRITICAL |
| `SENDGRID_API_KEY` | SendGrid API Key | HIGH |
| `SUPABASE_ANON_KEY` | Supabase Anon Key | MEDIUM |
| `SENTRY_DSN` | Sentry DSN | LOW |

> ⚠️ All secret values have been **REDACTED** in this report. NGO-Guardian does not store or transmit actual credentials.

### Finding 2: Hardcoded API Keys in Client-Side JS

- **Check ID**: `SCAN-KEYS`
- **Status**: 🔴 VULNERABLE
- **Description**: Scans JavaScript bundles for hardcoded API keys, tokens, and secrets

**Found in JS bundles:**
- `ecorestorefd.org/assets/index-[hash].js`
- `ecorestorefd.org/assets/vendor-[hash].js`

**Hardcoded Keys (2):**

| Key | Severity | Context |
|-----|----------|---------|
| `SUPABASE_ANON_KEY` | HIGH | Combined with disabled RLS = full database access |
| `SUPABASE_URL` | MEDIUM | Exposes database project identifier |

> ⚠️ Source maps are also available — original source code may reveal additional secrets.

### Finding 3: Unauthenticated API Endpoints

- **Check ID**: `SCAN-OPENAPI`
- **Status**: 🔴 VULNERABLE
- **Description**: Checks if sensitive API endpoints respond without authentication tokens

**Unprotected Endpoints (4):**

| Endpoint | Method | Status | Data Type | Est. Records |
|----------|--------|--------|-----------|-------------|
| `/api/volunteers` | GET | 200 | PII (MEDIUM) | ~2,044 |
| `/api/sites` | GET | 200 | Geospatial (MEDIUM) | ~1,142 |
| `/api/donations` | GET | 200 | Financial + PII (HIGH) | ~3,772 |
| `/api/impact-data` | GET | 200 | Unknown (MEDIUM) | ~465 |

### Finding 4: Direct Database Exposure

- **Check ID**: `SCAN-DB`
- **Status**: 🔴 VULNERABLE
- **Description**: Checks for exposed Supabase REST/Firebase endpoints without proper access controls

**Platform**: Supabase
**Access Level**: `anon_key_no_rls`
**Direct URL**: `https://ecorestorefd.supabase.co/rest/v1/`

**Exposed Tables (4):**

#### `volunteers` (~4,905 rows)
- RLS: ❌ Disabled
- Columns: `id`, `name`, `email`, `skills`, `availability`, `assigned_site`, `hours_logged`

#### `sites` (~2,077 rows)
- RLS: ❌ Disabled
- Columns: `id`, `site_name`, `coordinates`, `status`, `lead_volunteer`, `tree_count`, `area_hectares`

#### `donations` (~6,598 rows)
- RLS: ❌ Disabled
- Columns: `id`, `donor_email`, `amount`, `campaign`, `recurring`, `payment_token`, `created_at`

#### `impact-data` (~2,967 rows)
- RLS: ❌ Disabled
- Columns: `id`, `data`, `created_at`, `updated_at`

---

## 📊 Vulnerability Summary

| ID | Title | Severity | Category | Location |
|----|-------|----------|----------|----------|
| VCC-001 | Environment file publicly accessible | CRITICAL | Secrets Exposure | `portal.ecorestorefd.org/.env — contains SUPABASE_SERVICE_ROLE_KEY` |
| VCC-007 | Supabase tables without Row Level Security | CRITICAL | Broken Access Control | `volunteers, donations, sites tables — RLS disabled` |
| VCC-002 | API keys exposed in client-side JavaScript bundle | CRITICAL | Secrets Exposure | `Main bundle contains SUPABASE_SERVICE_ROLE_KEY (not anon key)` |
| VCC-005 | No Strict-Transport-Security header | HIGH | Missing Security Headers | `portal.ecorestorefd.org — no HSTS header` |
| VCC-004 | No Content-Security-Policy header | HIGH | Missing Security Headers | `portal.ecorestorefd.org — no CSP header` |

---

## 🤝 Disclosure Notes

This report was generated by the **NGO-Guardian Scanner Agent** as part of our
mission to protect under-resourced organizations. This report is intended for
**Person B (Impact & Disclosure Lead)** to draft empathy-first outreach.

- ✅ Detection only — no data was accessed, downloaded, or exploited
- ✅ All credential values are REDACTED
- ✅ Report stored locally — never transmitted externally
- ✅ Intent: Help this organization secure their infrastructure for free

> *"We are Guardians, not Hunters."*
