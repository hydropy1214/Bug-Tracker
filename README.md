# SentinelX

> **Full-stack web security reconnaissance and vulnerability scanning platform.**  
> Point it at any domain, IP, or API and it runs a 28-phase automated scan covering DNS, ports, TLS, WAF detection, injection testing (SQLi · XSS · SSTI · XXE · SSRF · NoSQLi · CMDi), JWT attacks, CVE matching, path traversal, HTTP smuggling, CORS misconfigs, and more — all with live terminal output and a polished React dashboard.

---

## Table of Contents

1. [Architecture](#architecture)
2. [Quick Start](#quick-start)
3. [Environment Variables](#environment-variables)
4. [Scan Profiles & Policies](#scan-profiles--policies)
5. [28-Phase Scan Engine](#28-phase-scan-engine)
6. [REST API Reference](#rest-api-reference)
7. [Database Schema](#database-schema)
8. [Project Structure](#project-structure)
9. [Development Commands](#development-commands)

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Replit Preview                           │
│                                                                 │
│  ┌───────────────────────────────┐   ┌─────────────────────┐   │
│  │   React 19 + Vite 7           │   │  Express 5 API      │   │
│  │   Tailwind 4 + Framer Motion  │──▶│  + Scan Worker      │   │
│  │   TanStack Query + Wouter     │   │  Port 8080          │   │
│  │   Port 18462                  │   └────────┬────────────┘   │
│  └───────────────────────────────┘            │                │
│           /api/* proxy ──────────────────────▶│                │
└─────────────────────────────────────────────────────────────────┘
                                                 │
                              ┌──────────────────┼──────────────────┐
                              │                  │                  │
                         PostgreSQL         nmap · dig         crt.sh
                         Drizzle ORM        whois · openssl    ipinfo.io
                         6 tables           curl · openssl     Wayback API
                                                                NVD CVE API
```

**Monorepo packages:**

| Package | Purpose |
|---------|---------|
| `apps/api` | Express 5 REST API + background scan worker |
| `apps/web` | React 19 dashboard (Vite 7, Tailwind 4) |
| `packages/db` | Drizzle ORM schema + PostgreSQL client |
| `packages/api-client` | Orval-generated React Query hooks |
| `packages/api-types` | Zod schemas + TypeScript types (from OpenAPI) |
| `packages/api-spec` | OpenAPI 3.1 specification (`openapi.yaml`) |

---

## Quick Start

### Prerequisites

| Tool | Version |
|------|---------|
| Node.js | 20 + |
| pnpm | 10 + |
| PostgreSQL | Provisioned automatically on Replit |

### 1. Install dependencies

```bash
pnpm install
```

### 2. Push database schema

```bash
pnpm --filter @workspace/db push
```

Creates 6 tables: `projects`, `assets`, `endpoints`, `findings`, `scans`, `activity`.

### 3. Start services

```bash
# Terminal 1 — API (port 8080)
pnpm --filter @workspace/api run dev

# Terminal 2 — Web (port 18462)
pnpm --filter @workspace/web run dev
```

On **Replit** both workflows start automatically. The Vite dev server proxies all `/api/*` requests to the API.

---

## Environment Variables

| Variable | Type | Required | Notes |
|----------|------|----------|-------|
| `DATABASE_URL` | Runtime-managed | ✓ | Provisioned automatically by Replit. Do **not** set manually. |
| `SESSION_SECRET` | Secret | ✓ | At least 32 random chars. Used as AES-256-GCM key to encrypt auth headers stored in DB. |
| `API_PORT` | Shared env | ✓ | Port the API binds to. Must match Vite proxy target. Default fallback: `8080`. |
| `NODE_ENV` | Shared env | — | `development` or `production`. |
| `ALLOWED_ORIGINS` | Shared env | — | Comma-separated extra CORS origins (all origins allowed by default). |

**CORS is fully open by default** — all origins, all methods, credentials allowed. No rate limiting. No CSP.

---

## Scan Profiles & Policies

| Profile | Request Budget | Verification Budget | Timeout | Concurrency | Deep Checks | Verification |
|---------|---------------|--------------------:|---------|-------------|-------------|--------------|
| `passive` | 300 | 0 | 12 s | 6 | ✗ | ✗ |
| `safe_active` | 1 500 | 0 | 15 s | 10 | ✓ | ✗ |
| `deep_authorized` | 20 000 | 500 | 30 s | 20 | ✓ | ✓ |
| `authenticated` | 20 000 | 500 | 30 s | 20 | ✓ | ✓ |
| `lab` | 50 000 | 2 000 | 60 s | 32 | ✓ | ✓ |

- **`passive`** — read-only reconnaissance; no active probes sent to the target.
- **`safe_active`** — active checks using harmless canary payloads; no exploit attempts.
- **`deep_authorized`** — full-depth scan; default for Quick Scan and all project scans.
- **`authenticated`** — same as `deep_authorized` but forwards decrypted session headers.
- **`lab`** — unrestricted; for isolated lab/CTF environments only.

---

## 28-Phase Scan Engine

Every scan runs the full phase chain. Phases that require active probes are gated by the scan policy and skipped if a WAF challenge is detected.

| Phase | Name | What it does |
|-------|------|-------------|
| **1** | WAF / CDN Detection | Identifies Cloudflare, AWS WAF, Akamai, Imperva, Sucuri, Fastly. Suspends active probes when a challenge page is detected. |
| **2** | DNS Enumeration | `dig` A · MX · TXT · NS · CNAME · PTR · SOA records. Detects misconfigs and dangling pointers. |
| **3** | IP Geolocation & ASN | ipinfo.io lookup — country, ASN, hosting provider. |
| **4** | WHOIS Intelligence | Domain registration data, expiry, registrar, nameservers. |
| **5** | Subdomain Discovery | crt.sh certificate transparency + DNS brute-force (1 000+ wordlist) + zone transfer attempt. |
| **5b** | Subdomain Takeover | Tests each discovered subdomain for dangling CNAME → unclaimed cloud service (S3, GitHub Pages, Heroku, etc.). |
| **6** | Port Scanning | nmap full-range scan (65 535 ports). Flags dangerous exposed services (telnet, FTP, RDP, SMB, Redis, MongoDB, etc.). |
| **7** | TLS / SSL Analysis | openssl: protocol versions, cipher suites, cert expiry, HSTS preload, CT log, chain issues. |
| **8** | HTTP Security Headers | Full audit: HSTS · CSP · X-Frame-Options · X-Content-Type-Options · Referrer-Policy · Permissions-Policy · CORS. |
| **9** | Technology Fingerprinting | Detects stack (WordPress, Nginx, Apache, Next.js, Laravel, Django, Rails, …). Extracts version numbers. |
| **10** | Sensitive Path Discovery | 50 + paths: `.env` · `.git/HEAD` · `backup.sql` · `credentials.json` · SSH keys · Kubernetes configs · source maps · CI/CD files · `phpinfo.php` · debug endpoints. |
| **11** | Wayback Machine | Historical URL analysis via Wayback CDX API. Finds old endpoints, leaked secrets, removed admin paths. |
| **11b** | Attack Surface Crawl | Same-origin crawl of discovered links, forms, and JS-defined routes. Builds the parameter inventory for injection testing. |
| **12** | Web App Probes | CORS active test · cookie flag audit (Secure, HttpOnly, SameSite) · HTTP TRACE · HTTPS enforcement · clickjacking · mixed content. |
| **13** | API Surface Discovery | GraphQL introspection · Swagger/OpenAPI exposure · Spring Actuator · Laravel Telescope · Django admin · generic API endpoint enumeration. |
| **13b** | API Credential Leaks | Detects API keys, tokens, and secrets exposed in JS bundles, response bodies, and error messages. |
| **13c** | Config / Debug Exposure | Source map leaks · phpinfo · debug pages · stack traces · directory listings. |
| **13d** | XSS Verification | Reflected XSS testing across crawled parameters using context-aware canary payloads. |
| **13e** | Deep Input Testing | Full discovered-parameter injection suite: SQLi (30 + patterns · boolean · time-based · JSON/cookie/header injection) · XSS · open redirect · path traversal across real crawled endpoints. |
| **14** | Host Header Injection | Password-reset link poisoning · cache poisoning · routing bypass. |
| **15** | CRLF Injection | HTTP response splitting · header injection · log injection. |
| **16** | Path Traversal | Directory traversal across 15 + encoding variants (`../` · `%2e%2e/` · `..%5c` · etc.). |
| **17** | JWT Weaknesses | `alg:none` bypass · weak HS256 secret cracking (25-secret wordlist) · missing `exp` · JKU/JWK URL injection · RS256→HS256 confusion · empty signature. |
| **18** | IDOR / BOLA | Broken Object-Level Access Control — sequential ID enumeration on discovered object endpoints. |
| **19** | HTTP Request Smuggling | CL.TE and TE.CL desync probes with timing-based detection. |
| **20** | Log4Shell / Spring4Shell | JNDI injection surface detection (Log4Shell) · class-loader probe (Spring4Shell). |
| **21** | Rate Limiting Absence | Tests login, register, and password-reset endpoints for missing brute-force protection. |
| **22** | Advanced Probes | **SSTI** (arithmetic canary + dual-math, RCE escalation) · **XXE** (file read) · **SSRF** (cloud metadata: AWS/GCP/Azure) · **Deserialization** (Java, PHP, Python surface) · **CMDi** (time-based + canary) · **NoSQLi** (MongoDB operator injection). |
| **23** | CVE Database Lookup | Cross-references detected technology versions against NVD API. Returns matching CVEs with CVSS scores. |
| **24** | Open Registration Verification | Tests whether account self-registration is possible and captures session cookies for later phases. |
| **25** | Default Credential Brute-Force | Tests common username/password pairs against discovered login forms. |
| **26** | SQLi Auth Bypass | Bounded UNION canary + classic bypass payloads against login endpoints. |
| **28** | IDOR with Captured Session | Re-runs IDOR checks using a session cookie captured in Phase 24. |

**Post-scan:**
- WAF-challenged findings are downgraded to informational.
- SSTI/NoSQL findings are suppressed when WAF is active (high false-positive risk).
- OWASP Top 10 · PCI-DSS v4.0 · NIST 800-53 compliance tags applied to every finding.
- Executive summary with risk grade (A–F) and top findings by CVSS.

---

## REST API Reference

Base URL: `/api`

### Health

```
GET  /api/healthz          → { status: "ok" }
```

### Quick Scan

Start a scan without creating a project first. Creates a temporary project, asset, and scan automatically.

```
POST /api/quick-scan
```

**Body:**
```json
{
  "url":         "https://example.com",
  "scanType":    "full",
  "profile":     "deep_authorized",
  "authHeaders": { "Authorization": "Bearer <token>" }
}
```

`scanType`: `recon` | `enumeration` | `vulnerability` | `full`  
`profile`: `passive` | `safe_active` | `deep_authorized` | `authenticated` | `lab`

**Response:**
```json
{
  "projectId": 1,
  "assetId":   1,
  "scanId":    1,
  "target":    "https://example.com",
  "hostname":  "example.com",
  "scanType":  "full",
  "profile":   "deep_authorized",
  "policy":    { ... }
}
```

---

### Projects

```
GET    /api/projects               → Project[]     list all projects
POST   /api/projects               → Project       create project
GET    /api/projects/:id           → Project       get single project
PATCH  /api/projects/:id           → Project       update project
DELETE /api/projects/:id           → 204           delete project
```

**Create / update body fields:** `name` (required) · `description` · `scope` · `status` (`active` | `paused` | `archived`)

Each project response includes: `assetCount` · `findingCount` · `criticalCount` · `highCount`

---

### Assets

```
GET    /api/projects/:projectId/assets    → Asset[]   list assets
POST   /api/projects/:projectId/assets    → Asset     add asset
PATCH  /api/assets/:id                    → Asset     update asset
DELETE /api/assets/:id                    → 204       delete asset
POST   /api/assets/:id/import             → ImportResult   import OpenAPI spec
GET    /api/projects/:projectId/endpoints → Endpoint[]     list imported endpoints
```

**Asset body fields:** `value` (URL, domain, or IP) · `type` (`domain` | `ip` | `api`) · `notes` · `technologies`

**Import body:** `{ spec: <OpenAPI JSON object or string>, source?: string, baseUrl?: string }`  
Accepts OpenAPI 3.x and Swagger 2.x (JSON only — YAML not supported).

---

### Scans

```
GET    /api/scans                              → Scan[]     global scan history (all projects)
GET    /api/projects/:projectId/scans          → Scan[]     scans for a project
POST   /api/projects/:projectId/scans          → Scan       create & queue scan
GET    /api/scans/:id                          → Scan       get scan record
POST   /api/scans/:id/stop                     → Scan       cancel scan
GET    /api/scans/:id/status                   → ScanStatus  poll status + live findings
GET    /api/scans/:id/report                   → Report     download report
GET    /api/scans/:id/report?format=sarif      → SARIF      SARIF 2.1.0 report
GET    /api/scans/:id/diff/:baselineId         → ScanDiff   diff two scans
```

**Create scan body:** `name` · `type` (`recon` | `enumeration` | `vulnerability` | `full`) · `profile` · `authHeaders`

**Poll response** (`GET /api/scans/:id/status`):
```json
{
  "scan":       { "id": 1, "status": "running", "progress": 42, "logs": "...", ... },
  "findings":   [ { "id": 1, "title": "...", "severity": "high", ... } ],
  "wafBlocked": false
}
```

Status values: `pending` → `running` → `completed` | `failed` | `canceled`

---

### Findings

```
GET    /api/projects/:projectId/findings   → Finding[]   list findings
POST   /api/projects/:projectId/findings   → Finding     create manual finding
GET    /api/findings/:id                   → Finding     get finding
PATCH  /api/findings/:id                   → Finding     update finding
DELETE /api/findings/:id                   → 204         delete finding
```

**Finding fields:**
| Field | Values |
|-------|--------|
| `severity` | `critical` · `high` · `medium` · `low` · `info` |
| `status` | `open` · `in_progress` · `resolved` · `wont_fix` |
| `verification` | `verified` · `version_match` · `suspected` · `informational` |
| `evidenceQuality` | `weak` · `standard` · `strong` |
| `reproducibility` | `reproducible` · `intermittent` · `not_reproducible` · `not_tested` |

---

### Dashboard

```
GET /api/dashboard/stats              → DashboardStats
GET /api/dashboard/activity?limit=N  → Activity[]
GET /api/dashboard/severity-breakdown → { critical, high, medium, low, info }
```

**Stats response:**
```json
{
  "totalProjects":    5,
  "activeProjects":   3,
  "totalAssets":      12,
  "totalFindings":    47,
  "openFindings":     31,
  "criticalFindings": 2,
  "highFindings":     8,
  "runningScans":     1,
  "completedScans":   24
}
```

---

## Database Schema

### `projects`
| Column | Type | Notes |
|--------|------|-------|
| id | serial PK | |
| name | text | Required |
| description | text | |
| scope | text | IP ranges, domain globs |
| status | text | `active` · `paused` · `archived` |
| createdAt / updatedAt | timestamptz | |

### `assets`
| Column | Type | Notes |
|--------|------|-------|
| id | serial PK | |
| projectId | int FK → projects | Cascade delete |
| value | text | URL / domain / IP |
| type | text | `domain` · `ip` · `api` |
| status | text | `active` · `inactive` |
| notes | text | |
| technologies | text[] | Detected tech stack |
| apiSpec | text | Raw OpenAPI JSON |
| apiSpecVersion | text | |
| apiSpecImportedAt | timestamptz | |

### `endpoints`
Imported from OpenAPI specs. Columns: `method` · `path` · `operationId` · `summary` · `parameters` (JSON) · `requestBody` (JSON) · `security` (JSON) · `source` · `baseUrl`

### `scans`
| Column | Type | Notes |
|--------|------|-------|
| id | serial PK | |
| projectId | int FK → projects | Cascade delete |
| name | text | |
| type | text | `recon` · `enumeration` · `vulnerability` · `full` |
| profile | text | Scan policy name |
| policy | text | Serialised policy JSON |
| toolCapabilities | text | Available tools JSON |
| authContext | text | AES-256-GCM encrypted auth headers |
| status | text | `pending` · `running` · `completed` · `failed` · `canceled` |
| progress | int | 0–100 |
| findingsCount | int | |
| wafBlocked | boolean | |
| cancelRequested | boolean | |
| logs | text | Full scan log stream |
| startedAt / completedAt | timestamptz | |

### `findings`
| Column | Type | Notes |
|--------|------|-------|
| id | serial PK | |
| projectId / scanId / assetId | int FKs | |
| title | text | |
| description | text | |
| severity | text | `critical` · `high` · `medium` · `low` · `info` |
| status | text | `open` · `in_progress` · `resolved` · `wont_fix` |
| verification | text | `verified` · `version_match` · `suspected` · `informational` |
| verified | boolean | Canary-confirmed finding |
| confidence | int | 0–100 % |
| evidenceQuality | text | `weak` · `standard` · `strong` |
| reproducibility | text | |
| cvss | float | CVSS base score |
| cve | text | CVE-YYYY-NNNNN |
| evidence | text | Proof / request-response |
| remediation | text | Fix guidance |
| affectedEndpoint / affectedParameter | text | |
| negativeTests / limitations / toolInfo | text | |
| verificationMethod | text | |
| createdAt / updatedAt | timestamptz | |

### `activity`
Event log for dashboard feed. Columns: `type` · `title` · `description` · `severity` · `projectId` · `projectName`

---

## Project Structure

```
sentinelx/
├── apps/
│   ├── api/
│   │   ├── src/
│   │   │   ├── app.ts                   Express app — middleware setup
│   │   │   ├── index.ts                 Server entry point
│   │   │   ├── lib/
│   │   │   │   ├── auth-context.ts      AES-256-GCM auth header encryption
│   │   │   │   ├── encryption.ts        Re-export shim
│   │   │   │   ├── logger.ts            Pino structured logger
│   │   │   │   ├── scan-worker.ts       Background scan queue (2s tick)
│   │   │   │   ├── api-schema.ts        OpenAPI/Swagger JSON parser
│   │   │   │   └── scanner/
│   │   │   │       ├── index.ts         Public scanner facade
│   │   │   │       ├── context.ts       AsyncLocalStorage + budgets + policies
│   │   │   │       ├── orchestrator.ts  28-phase pipeline
│   │   │   │       ├── types.ts
│   │   │   │       ├── phases/          One file per scan phase
│   │   │   │       │   ├── waf-detection.ts
│   │   │   │       │   ├── dns.ts
│   │   │   │       │   ├── ip-info.ts
│   │   │   │       │   ├── whois.ts
│   │   │   │       │   ├── subdomains.ts
│   │   │   │       │   ├── ports.ts
│   │   │   │       │   ├── tls.ts
│   │   │   │       │   ├── headers.ts
│   │   │   │       │   ├── tech-fingerprint.ts
│   │   │   │       │   ├── sensitive-paths.ts
│   │   │   │       │   ├── wayback.ts
│   │   │   │       │   ├── surface-discovery.ts
│   │   │   │       │   ├── webapp-probes.ts
│   │   │   │       │   ├── api-surface.ts
│   │   │   │       │   ├── api-leaks.ts
│   │   │   │       │   ├── config-exposure.ts
│   │   │   │       │   ├── xss.ts
│   │   │   │       │   ├── deep-input-testing.ts
│   │   │   │       │   ├── host-header.ts
│   │   │   │       │   ├── crlf.ts
│   │   │   │       │   ├── path-traversal.ts
│   │   │   │       │   ├── jwt.ts
│   │   │   │       │   ├── idor.ts
│   │   │   │       │   ├── request-smuggling.ts
│   │   │   │       │   ├── log4shell.ts
│   │   │   │       │   ├── rate-limiting.ts
│   │   │   │       │   ├── advanced-probes.ts
│   │   │   │       │   ├── compliance.ts
│   │   │   │       │   ├── advanced/
│   │   │   │       │   │   ├── ssti.ts
│   │   │   │       │   │   ├── xxe.ts
│   │   │   │       │   │   ├── ssrf.ts
│   │   │   │       │   │   ├── deserialization.ts
│   │   │   │       │   │   ├── command-injection.ts
│   │   │   │       │   │   ├── nosql-injection.ts
│   │   │   │       │   │   └── cve-lookup.ts
│   │   │   │       │   └── verification/
│   │   │   │       │       ├── active.ts          Phases 24–26, 28
│   │   │   │       │       ├── sql-injection.ts
│   │   │   │       │       ├── ssti.ts
│   │   │   │       │       ├── graphql.ts
│   │   │   │       │       ├── restricted.ts
│   │   │   │       │       └── common.ts
│   │   │   │       └── utils/
│   │   │   │           ├── http.ts
│   │   │   │           ├── findings.ts
│   │   │   │           └── waf.ts
│   │   │   └── routes/
│   │   │       ├── index.ts
│   │   │       ├── health.ts
│   │   │       ├── quick-scan.ts
│   │   │       ├── projects.ts
│   │   │       ├── assets.ts
│   │   │       ├── findings.ts
│   │   │       ├── scans.ts
│   │   │       └── dashboard.ts
│   │   └── build.mjs                    esbuild bundler script
│   └── web/
│       ├── src/
│       │   ├── App.tsx                  Root — QueryClient + Wouter router
│       │   ├── main.tsx
│       │   ├── index.css
│       │   ├── pages/
│       │   │   ├── Dashboard.tsx        Quick scan UI + live terminal
│       │   │   ├── Projects.tsx         Project management
│       │   │   ├── ProjectDetail.tsx    Assets · Findings · Scans tabs
│       │   │   ├── Scans.tsx            Global scan history
│       │   │   ├── Settings.tsx         System config + telemetry
│       │   │   └── not-found.tsx
│       │   ├── components/
│       │   │   ├── layout/Shell.tsx     Sidebar nav + health indicator
│       │   │   ├── dashboard/
│       │   │   │   ├── FindingCard.tsx
│       │   │   │   └── scan-types.ts
│       │   │   └── ui/                  shadcn/ui component library
│       │   ├── hooks/
│       │   │   └── useScanPolling.ts    1.2s polling loop for live scan status
│       │   └── lib/utils.ts
│       └── vite.config.ts              Vite — /api proxy → localhost:8080
├── packages/
│   ├── db/
│   │   ├── src/
│   │   │   ├── index.ts                Drizzle client + pool
│   │   │   └── schema/                 One file per table
│   │   └── drizzle.config.ts
│   ├── api-client/src/                 Orval-generated React Query hooks
│   ├── api-types/src/                  Orval-generated Zod schemas + types
│   └── api-spec/openapi.yaml           OpenAPI 3.1 contract
├── scripts/
│   └── post-merge.sh                   Post-merge setup script
├── .env.example                        All required env vars documented
├── replit.md                           Replit-specific setup guide
├── pnpm-workspace.yaml
└── tsconfig.base.json
```

---

## Development Commands

```bash
# Install all workspace dependencies
pnpm install

# Push database schema (after any schema file change)
pnpm --filter @workspace/db push

# Type-check all packages
pnpm typecheck

# Format scanner + dashboard code
pnpm format:check

# Start API only
pnpm --filter @workspace/api run dev

# Start web only
pnpm --filter @workspace/web run dev

# Build everything (type-check + compile)
pnpm build
```

### Regenerate API client after changing `openapi.yaml`

```bash
cd packages/api-types  && npx orval
cd packages/api-client && npx orval
```

### Add a new scan phase

1. Create `apps/api/src/lib/scanner/phases/<phase-name>.ts` — export a single async function.
2. Import it in `apps/api/src/lib/scanner/index.ts`.
3. Add the phase call in `apps/api/src/lib/scanner/orchestrator.ts`.
4. Add the phase ID to `SCANNER_PHASE_IDS` in `apps/api/src/lib/scan-worker.ts`.

---

*SentinelX — built for security professionals. Use responsibly and only against systems you own or have written permission to test.*
