# 🛡️ Vibe Check Report: Refugee Aid Network

> **Target**: `refugeeaidnetwork.org`
> **Scan Date**: 2026-03-30T00:10:41.505Z
> **Scanner Agent**: NGO-Guardian v1.0
> **Mode**: Detection Only — Zero Exploitation

---

## 📋 Target Profile

| Field | Value |
|-------|-------|
| **Organization** | Refugee Aid Network |
| **Domain** | `refugeeaidnetwork.org` |
| **Sector** | Humanitarian |
| **Mission** | Emergency relief and long-term support for displaced populations |
| **Tech Stack** | Firebase + Next.js 13 |
| **Vibe-Coded** | ✅ Yes |
| **Vibe Risk Score** | **95/100** 🔴 SEVERE |
| **Security Header Score** | 57% |

### Discovered Subdomains

- `app.refugeeaidnetwork.org`
- `api.refugeeaidnetwork.org`
- `intake.refugeeaidnetwork.org`
- `maps.refugeeaidnetwork.org`

---

## 🧠 AI Data Risk Classification

> *Classified by Claude — analyzing data types at risk based on exposed endpoints and database schemas*

| Category | Found | Severity | Details |
|----------|-------|----------|---------|
| 🔵 PII (Personal) | ⚠️ YES | CRITICAL | Case File PII, Staff/Field Worker PII |
| 📍 Location Data | ⚠️ YES | CRITICAL | Geospatial Data |
| 💰 Financial | — | — | Not detected |
| 👶 Minor/Child Data | — | — | Not detected |
| 🏥 Health/Welfare | ⚠️ YES | CRITICAL | Health & Welfare Records |

> [!CAUTION]
> **Overall Data Risk: CRITICAL** — This organization handles highly sensitive data that appears to be insufficiently protected.

### 💔 Human Impact Assessment

> Health and welfare records of vulnerable individuals (refugees, disaster survivors) could be exposed, leading to discrimination, denial of services, or targeted persecution.
>
> The combination of personal identity data and location coordinates creates a severe risk: bad actors could physically locate vulnerable individuals including refugees, aid workers in conflict zones, or abuse survivors.

---

## 🔍 Deep Scan Findings

### Finding 1: Unauthenticated GraphQL Playground

- **Check ID**: `SCAN-GQL`
- **Status**: 🔴 VULNERABLE
- **Description**: Checks if /graphql endpoint exposes an introspection-enabled playground without auth

**Endpoint**: `refugeeaidnetwork.org/graphql`

| Property | Value |
|----------|-------|
| Introspection | ✅ Enabled |
| Playground UI | ✅ Accessible |
| Auth Required | ❌ No |

**Exposed Types**: `Query`, `Mutation`, `Subscription`, `Cases`, `Locations`, `Personnel`, `Auth`, `User`, `AuthPayload`, `PaginationInfo`

**Exposed Mutations** (9):
- `createCases`
- `updateCases`
- `deleteCases`
- `createLocations`
- `updateLocations`
- `deleteLocations`
- `createPersonnel`
- `updatePersonnel`
- `deletePersonnel`

### Finding 2: Exposed Swagger/OpenAPI Documentation

- **Check ID**: `SCAN-SWAGGER`
- **Status**: 🔴 VULNERABLE
- **Description**: Checks if /swagger.json or /api-docs are publicly accessible

**Exposed at**: `refugeeaidnetwork.org/swagger.json`, `refugeeaidnetwork.org/api-docs`

**API Version**: 3.0.1

**Documented Routes (4):**
- `/api/cases`
- `/api/locations`
- `/api/personnel`
- `/api/auth/login`

**Authentication Schemes**: ❌ None defined

### Finding 3: Hardcoded API Keys in Client-Side JS

- **Check ID**: `SCAN-KEYS`
- **Status**: 🔴 VULNERABLE
- **Description**: Scans JavaScript bundles for hardcoded API keys, tokens, and secrets

**Found in JS bundles:**
- `refugeeaidnetwork.org/_next/static/chunks/main-[hash].js`
- `refugeeaidnetwork.org/_next/static/chunks/pages/_app-[hash].js`

**Hardcoded Keys (3):**

| Key | Severity | Context |
|-----|----------|---------|
| `FIREBASE_API_KEY` | MEDIUM | Firebase API keys are designed to be public, but combined with open Firestore rules = full access |
| `FIREBASE_APP_ID` | LOW | App identifier |
| `FIREBASE_MEASUREMENT_ID` | LOW | Analytics identifier |

### Finding 4: Unauthenticated API Endpoints

- **Check ID**: `SCAN-OPENAPI`
- **Status**: 🔴 VULNERABLE
- **Description**: Checks if sensitive API endpoints respond without authentication tokens

**Unprotected Endpoints (3):**

| Endpoint | Method | Status | Data Type | Est. Records |
|----------|--------|--------|-----------|-------------|
| `/api/cases` | GET | 200 | PII + Legal (CRITICAL) | ~2,251 |
| `/api/locations` | GET | 200 | Geospatial (HIGH) | ~475 |
| `/api/personnel` | GET | 200 | PII + Location (HIGH) | ~701 |

### Finding 5: Direct Database Exposure

- **Check ID**: `SCAN-DB`
- **Status**: 🔴 VULNERABLE
- **Description**: Checks for exposed Supabase REST/Firebase endpoints without proper access controls

**Platform**: Firebase
**Access Level**: `public_rules`
**Direct URL**: `https://refugeeaidnetwork.firebaseio.com/`

**Exposed Tables (3):**

#### `cases` (~5,168 rows)
- RLS: ❌ Disabled
- Columns: `id`, `case_number`, `applicant_name`, `nationality`, `status`, `assigned_worker`, `notes`, `documents`, `created_at`

#### `locations` (~9,558 rows)
- RLS: ❌ Disabled
- Columns: `id`, `name`, `type`, `latitude`, `longitude`, `capacity`, `current_occupancy`, `security_level`

#### `personnel` (~3,748 rows)
- RLS: ❌ Disabled
- Columns: `id`, `full_name`, `role`, `email`, `phone`, `field_location`, `clearance_level`, `emergency_contact`

---

## 📊 Vulnerability Summary

| ID | Title | Severity | Category | Location |
|----|-------|----------|----------|----------|
| VCC-008 | Firebase Firestore rules allow public read/write | CRITICAL | Broken Access Control | `Firestore — 'cases' and 'personnel' collections publicly readable` |
| VCC-006 | GraphQL introspection enabled in production | MEDIUM | Information Disclosure | `refugeeaidnetwork.org/graphql — introspection returns full schema` |
| VCC-004 | No Content-Security-Policy header | HIGH | Missing Security Headers | `app.refugeeaidnetwork.org — no CSP header` |
| VCC-002 | API keys exposed in client-side JavaScript bundle | CRITICAL | Secrets Exposure | `Firebase config in bundle includes measurementId and appId` |

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
