# SentinelX — Professional Vulnerability Scanner

> A full-stack, self-hosted web application security scanner built on a pnpm monorepo.
> Runs real system tools (nmap, dig, whois, openssl) and performs 21 scanning phases
> covering WAF bypass, subdomain takeover, blind SQLi, JWT cracking, Log4Shell, path
> traversal, CRLF injection, and more — with zero-false-positive guarantees backed by
> baseline comparison and canary tokens.

---

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Complete File Tree](#complete-file-tree)
3. [Every File Explained](#every-file-explained)
4. [What Is Implemented](#what-is-implemented)
5. [What Is Not Yet Implemented](#what-is-not-yet-implemented)
6. [Setup & Installation](#setup--installation)
7. [Running the Project](#running-the-project)
8. [Environment Variables & Secrets](#environment-variables--secrets)
9. [Database Schema](#database-schema)
10. [API Reference](#api-reference)
11. [Scanner Phases (All 21)](#scanner-phases-all-21)
12. [Vulnerability Coverage Matrix](#vulnerability-coverage-matrix)
13. [Technology Stack](#technology-stack)
14. [System Tool Requirements](#system-tool-requirements)

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                     Browser / Client                        │
│                    apps/web (React + Vite)                  │
│      React 19 · TanStack Query · Framer Motion · Wouter     │
└───────────────────────┬─────────────────────────────────────┘
                        │ HTTP (REST)  /api/*
                        ▼
┌─────────────────────────────────────────────────────────────┐
│                    apps/api (Express 5)                      │
│  Routes: projects · assets · scans · findings · quick-scan  │
│  Middleware: Pino logging · CORS · JSON · base-path proxy   │
└───────┬───────────────┬────────────────────────────────────-┘
        │               │
        ▼               ▼
┌──────────────┐  ┌─────────────────────────────────────────┐
│  packages/db │  │         Scan Worker (background)         │
│  Drizzle ORM │  │  Polls DB for pending scans every 2s    │
│  PostgreSQL  │  │  Calls scanTarget() → updates logs/DB   │
└──────────────┘  └──────────────┬──────────────────────────┘
                                 │
                    ┌────────────┴────────────┐
                    │     scanner.ts          │
                    │     21 phases           │
                    │   + vuln-probes.ts      │
                    │  System tools invoked:  │
                    │  nmap dig whois openssl │
                    └─────────────────────────┘
```

---

## Complete File Tree

```
sentinelx/                              ← monorepo root
├── README.md                           ← this file
├── replit.md                           ← Replit-specific setup notes
├── package.json                        ← root scripts + workspace config
├── pnpm-workspace.yaml                 ← workspace glob definitions
├── pnpm-lock.yaml                      ← lockfile (auto-managed)
│
├── artifacts/
│   ├── api-server/                     ← Express 5 backend
│   │   ├── package.json
│   │   ├── tsconfig.json
│   │   ├── esbuild.config.js           ← build bundler config
│   │   └── src/
│   │       ├── index.ts                ← server entry point
│   │       ├── app.ts                  ← Express app + route wiring
│   │       ├── lib/
│   │       │   ├── scanner.ts          ← 2632-line core scan engine
│   │       │   ├── vuln-probes.ts      ← 670-line advanced probes
│   │       │   ├── scan-worker.ts      ← background polling worker
│   │       │   └── auth-context.ts     ← auth header encryption helpers
│   │       └── routes/
│   │           ├── quick-scan.ts       ← POST /api/quick-scan
│   │           ├── scans.ts            ← /api/scans CRUD + status/report
│   │           ├── projects.ts         ← /api/projects CRUD
│   │           ├── assets.ts           ← /api/assets CRUD + spec import
│   │           ├── findings.ts         ← /api/findings CRUD + activity
│   │           ├── dashboard.ts        ← /api/dashboard stats aggregate
│   │           └── health.ts           ← GET /api/healthz
│   │
│   ├── sentinelx/                      ← React 19 frontend
│   │   ├── package.json
│   │   ├── tsconfig.json
│   │   ├── vite.config.ts
│   │   ├── tailwind.config.ts          ← Tailwind v4 config
│   │   ├── index.html
│   │   └── src/
│   │       ├── main.tsx                ← React root, QueryClient setup
│   │       ├── index.css               ← global styles + CSS variables
│   │       ├── App.tsx                 ← router (wouter) + Shell wrapper
│   │       ├── lib/
│   │       │   └── utils.ts            ← cn() class merge helper
│   │       ├── pages/
│   │       │   ├── Dashboard.tsx       ← scan engine UI (main page)
│   │       │   ├── Projects.tsx        ← project list view
│   │       │   ├── ProjectDetail.tsx   ← tabbed project detail
│   │       │   ├── Settings.tsx        ← platform settings
│   │       │   └── tabs/
│   │       │       ├── AssetsTab.tsx   ← asset management tab
│   │       │       ├── ScansTab.tsx    ← scan history tab
│   │       │       └── FindingsTab.tsx ← findings table tab
│   │       └── components/
│   │           ├── layout/
│   │           │   └── Shell.tsx       ← sidebar + header wrapper
│   │           └── ui/                 ← shadcn/ui component library
│   │               ├── button.tsx
│   │               ├── card.tsx
│   │               ├── dialog.tsx
│   │               ├── table.tsx
│   │               ├── badge.tsx
│   │               ├── input.tsx
│   │               ├── label.tsx
│   │               ├── select.tsx
│   │               ├── tabs.tsx
│   │               ├── textarea.tsx
│   │               ├── tooltip.tsx
│   │               ├── progress.tsx
│   │               ├── separator.tsx
│   │               ├── sheet.tsx
│   │               ├── dropdown-menu.tsx
│   │               └── scroll-area.tsx
│   │
│   └── mockup-sandbox/                 ← Vite dev server for UI previews
│       ├── package.json
│       ├── vite.config.ts
│       └── src/
│           └── ...                     ← canvas component previews
│
└── lib/
    ├── db/                             ← shared database package
    │   ├── package.json
    │   ├── tsconfig.json
    │   ├── drizzle.config.ts           ← Drizzle Kit config
    │   └── src/
    │       ├── index.ts                ← exports db, schema tables
    │       └── schema/
    │           ├── projects.ts         ← projects table
    │           ├── assets.ts           ← assets table
    │           ├── scans.ts            ← scans table
    │           ├── findings.ts         ← findings table (rich fields)
    │           ├── endpoints.ts        ← endpoints table (API spec import)
    │           └── activity.ts         ← activity feed table
    │
    ├── api-spec/                       ← OpenAPI 3.1 spec
    │   ├── package.json
    │   └── src/
    │       └── openapi.yaml            ← hand-authored API spec
    │
    ├── api-zod/                        ← generated Zod schemas
    │   ├── package.json
    │   └── src/
    │       └── index.ts                ← (generated from api-spec)
    │
    └── api-client-react/               ← generated React Query hooks
        ├── package.json
        └── src/
            └── index.ts                ← (generated from api-spec)
```

---

## Every File Explained

### `apps/api/src/index.ts`
Server entry point. Reads `PORT` from environment, binds the Express `app`, then calls
`startScanWorker()` to begin the background polling loop. Nothing else lives here.

### `apps/api/src/app.ts`
Express 5 application factory. Registers:
- **Pino HTTP logger** (structured JSON logs)
- **CORS** (open during development; lock down in production)
- **JSON body parser** (10 MB limit)
- **Route mounts** under `/api`:
  - `/api/healthz` → `health.ts`
  - `/api/quick-scan` → `quick-scan.ts`
  - `/api/scans` → `scans.ts`
  - `/api/projects` → `projects.ts`
  - `/api/assets` → `assets.ts`
  - `/api/findings` → `findings.ts`
  - `/api/dashboard` → `dashboard.ts`

### `apps/api/src/lib/scanner.ts` ← **Core engine (2632 lines)**

Exports:
| Export | Description |
|--------|-------------|
| `interface Target` | Parsed URL info: `url`, `hostname`, `port`, `isHttps`, `assetType`, `rawHeaders` |
| `interface RealFinding` | Finding shape: `title`, `severity`, `cvss`, `cve`, `verification`, `confidence`, `evidence`, `remediation`, + 8 more audit fields |
| `interface ScanPolicy` | Budget, concurrency, timeout, feature flags per profile |
| `SCAN_POLICIES` | Map of `safe_passive` / `safe_active` / `deep_authorized` profiles |
| `normalizeTarget()` | Parses a raw URL string into a `Target` object |
| `resolveScanPolicy()` | Returns the right `ScanPolicy` for a given profile string |
| `discoverToolCapabilities()` | Detects which system binaries are available (nmap, dig, whois, openssl) |
| `scanTarget()` | **Main orchestrator** — runs all 21 phases, writes logs, returns `RealFinding[]` |

Internal functions (not exported):
`checkWafAndBypass`, `checkSubdomainTakeover`, `checkHostHeaderInjection`, `checkCrlfInjection`,
`checkJwtWeaknesses`, `checkPathTraversal`, `checkLog4ShellSurface`, `checkRateLimiting`,
`checkDns`, `checkPorts`, `checkTls`, `checkWhois`, `discoverSubdomains`, `getIpInfo`,
`checkWayback`, `checkHeaders`, `fingerprint`, `checkSensitivePaths`, `checkWebApp`,
`checkApiSurface`, `probe` (HTTP fetch wrapper), `nmapScan`, `digQuery`.

### `apps/api/src/lib/vuln-probes.ts` ← **Advanced probes (670 lines)**

Exports:
| Export | Description |
|--------|-------------|
| `checkSSTI()` | Server-Side Template Injection — arithmetic canary `{{7*7}}` across 15+ engines |
| `checkXXE()` | XML External Entity — injects `file:///etc/passwd` entity, checks response |
| `checkSSRF()` | Server-Side Request Forgery — targets AWS/GCP/Azure metadata endpoints |
| `checkDeserialization()` | Java deserialization — injects ysoserial-style payloads, checks error patterns |
| `checkCommandInjection()` | OS command injection — canary token via `;printf`, `|echo`, `$(…)`, `\`…\`` |
| `checkNoSqlInjection()` | MongoDB operator injection — `{$gt:""}`, `{$ne:null}`, `[$ne]=`, form + JSON |
| `lookupCvesForTechs()` | NVD API CVE lookup for detected tech/version combinations |

### `apps/api/src/lib/scan-worker.ts`
Background loop that runs every 2 seconds. Queries the database for scans in `pending` state,
picks up one at a time, sets it to `running`, calls `scanTarget()`, streams log lines back to
the database, and marks the scan `completed` when done. Findings are bulk-inserted into the
`findings` table with full audit metadata.

### `apps/api/src/lib/auth-context.ts`
Helpers to encrypt/decrypt authentication headers (Bearer tokens, cookies) that are stored
alongside scans. Uses `SESSION_SECRET` via AES-256-GCM. Auth context is passed to the scanner
so it can include credentials in probes.

### `apps/api/src/routes/quick-scan.ts`
`POST /api/quick-scan` — one-shot endpoint. Accepts `{ url, scanType?, profile? }`.
Creates a `Project`, an `Asset`, and a `Scan` record in a single transaction, then returns
`{ scanId }`. The scan worker picks it up immediately. Defaults: `scanType = "full"`,
`profile = "deep_authorized"`.

### `apps/api/src/routes/scans.ts`
Full CRUD for scans:
- `GET /api/scans` — paginated list with project/asset joins
- `GET /api/scans/:id/status` — live polling endpoint (returns scan + findings array)
- `GET /api/scans/:id/report` — download full report as JSON or SARIF 2.1
- `POST /api/scans` — create scan manually (for managed projects)
- `PATCH /api/scans/:id` — update status/progress
- `DELETE /api/scans/:id` — soft delete

### `apps/api/src/routes/projects.ts`
Full CRUD for projects with aggregated counts (asset count, scan count, open finding count).

### `apps/api/src/routes/assets.ts`
Asset management. Includes `POST /api/assets/:id/import-spec` which accepts an OpenAPI YAML/JSON
spec and parses it into `endpoints` table rows for structured API surface scanning.

### `apps/api/src/routes/findings.ts`
Full CRUD for findings. Includes `PATCH /api/findings/:id/status` for triaging findings
(open → confirmed → mitigated → false_positive) and writes to the `activity` table.

### `apps/api/src/routes/dashboard.ts`
Returns aggregate stats: total projects, open findings by severity, recent activity feed,
scan counts, and trend data for the dashboard overview cards.

### `apps/api/src/routes/health.ts`
`GET /api/healthz` → `200 { status: "ok", ts: <ISO timestamp> }`. Used by Replit workflow
health checks and uptime monitors.

---

### `apps/web/src/App.tsx`
Root component. Wraps everything in `QueryClientProvider` (TanStack Query). Uses `wouter`
for client-side routing. Routes:
- `/` → `Dashboard`
- `/projects` → `Projects`
- `/projects/:id` → `ProjectDetail`
- `/settings` → `Settings`

All routes are wrapped in `Shell` (sidebar + header layout).

### `apps/web/src/pages/Dashboard.tsx`
Main scan UI. The only user-facing entry point for running a scan:
- URL input field
- Single **SCAN** button (always runs `scanType: "full"`, `profile: "deep_authorized"`)
- Live terminal (streams log lines from the API while scan runs)
- Live finding cards (appear in real time as phases complete)
- Completed: full threat-level report with collapsible finding cards
- Idle: capability grid showing all 12 detection categories

### `apps/web/src/pages/Projects.tsx`
Lists all managed projects (created via the projects API). Shows name, description, status,
asset count, and open finding count. Links to `ProjectDetail`.

### `apps/web/src/pages/ProjectDetail.tsx`
Tabbed view for a specific project. Three tabs: Assets, Scans, Findings.

### `apps/web/src/pages/AssetsTab.tsx`
Lists assets for a project. Supports adding new assets and importing OpenAPI specs.

### `apps/web/src/pages/ScansTab.tsx`
Lists scans for a project with status badges, progress, and finding counts. Links to scan
detail/report view.

### `apps/web/src/pages/FindingsTab.tsx`
Filterable findings table (by severity, status, verification). Supports inline triaging.

### `apps/web/src/components/layout/Shell.tsx`
Full-height sidebar + topbar layout. Sidebar links: Scan Engine, Projects, Settings.
Shows "SYSTEM ONLINE" indicator and version number.

---

### `packages/db/src/index.ts`
Exports `db` (Drizzle ORM instance over a `pg.Pool`) and re-exports all schema tables.
Reads `DATABASE_URL` from environment.

### `packages/db/src/schema/*.ts`
See [Database Schema](#database-schema) section below.

### `packages/db/drizzle.config.ts`
Drizzle Kit config — points to `DATABASE_URL`, schema glob, output dir for migrations.

### `packages/api-spec/openapi.yaml`
OpenAPI 3.1 spec for the SentinelX API. Defines all request/response shapes used to
generate the Zod schemas and React Query hooks in the sibling packages.

### `packages/api-types/src/index.ts` and `packages/api-client/src/index.ts`
Auto-generated from the OpenAPI spec. Not hand-edited. Re-generate with:
```bash
pnpm --filter @workspace/api-spec run codegen
```

---

## What Is Implemented

### ✅ Backend — Scan Engine

| Feature | File | Status |
|---------|------|--------|
| WAF/CDN detection (11 signatures) | `scanner.ts` | ✅ Done |
| WAF bypass: IP-spoofing headers (9 variants) | `scanner.ts` | ✅ Done |
| WAF bypass: Googlebot UA | `scanner.ts` | ✅ Done |
| WAF bypass: URL encoding / path normalisation | `scanner.ts` | ✅ Done |
| Direct origin IP bypass (no WAF) | `scanner.ts` | ✅ Done |
| DNS enumeration (A/AAAA/MX/TXT/NS/CAA/AXFR) | `scanner.ts` | ✅ Done |
| Subdomain discovery (crt.sh + DNS brute-force) | `scanner.ts` | ✅ Done |
| Subdomain takeover (17 service fingerprints) | `scanner.ts` | ✅ Done |
| IP geolocation + ASN (ipinfo.io) | `scanner.ts` | ✅ Done |
| WHOIS domain intelligence | `scanner.ts` | ✅ Done |
| Full port scan (nmap, all 65535 ports) | `scanner.ts` | ✅ Done |
| Service version detection (nmap -sV) | `scanner.ts` | ✅ Done |
| TLS/SSL analysis (protocols, ciphers, cert expiry) | `scanner.ts` | ✅ Done |
| HTTP security headers (HSTS/CSP/CORS/XFO/XCTO) | `scanner.ts` | ✅ Done |
| Cookie security flags (Secure/HttpOnly/SameSite) | `scanner.ts` | ✅ Done |
| Technology fingerprinting (30+ signatures) | `scanner.ts` | ✅ Done |
| 50+ sensitive path discovery (.env, .git, etc.) | `scanner.ts` | ✅ Done |
| Wayback Machine historical endpoint discovery | `scanner.ts` | ✅ Done |
| SQL injection — error-based (9 payloads, 13 params) | `scanner.ts` | ✅ Done |
| SQL injection — time-based blind (MySQL/MSSQL/PG/Oracle) | `scanner.ts` | ✅ Done |
| Reflected XSS (16 params, 2 payload types) | `scanner.ts` | ✅ Done |
| NoSQL injection (MongoDB operators, JSON + form) | `scanner.ts` | ✅ Done |
| Command injection canary (5 shell variants) | `scanner.ts` | ✅ Done |
| API surface discovery (GraphQL/Swagger/Actuator) | `scanner.ts` | ✅ Done |
| Host header injection (4 header variants) | `scanner.ts` | ✅ Done |
| CRLF injection / HTTP response splitting | `scanner.ts` | ✅ Done |
| Path traversal (9 encoding variants, Linux + Windows) | `scanner.ts` | ✅ Done |
| JWT alg:none bypass | `scanner.ts` | ✅ Done |
| JWT weak HS256 secret cracking | `scanner.ts` | ✅ Done |
| JWT missing `exp` claim | `scanner.ts` | ✅ Done |
| Log4Shell (CVE-2021-44228) surface detection | `scanner.ts` | ✅ Done |
| Spring4Shell (CVE-2022-22965) surface detection | `scanner.ts` | ✅ Done |
| Rate limiting absence on auth endpoints | `scanner.ts` | ✅ Done |
| SSTI (arithmetic canary, 15+ template engines) | `vuln-probes.ts` | ✅ Done |
| XXE (file read via XML entity injection) | `vuln-probes.ts` | ✅ Done |
| SSRF (cloud metadata endpoint access) | `vuln-probes.ts` | ✅ Done |
| Java deserialization surface detection | `vuln-probes.ts` | ✅ Done |
| OS command injection canary (deep, GET+POST) | `vuln-probes.ts` | ✅ Done |
| NoSQL injection (deep, JSON+form+URL params) | `vuln-probes.ts` | ✅ Done |
| CVE lookup via NVD API for detected tech | `vuln-probes.ts` | ✅ Done |
| Background scan worker (DB polling) | `scan-worker.ts` | ✅ Done |
| Auth header encryption (AES-256-GCM) | `auth-context.ts` | ✅ Done |
| Quick-scan one-shot endpoint | `quick-scan.ts` | ✅ Done |
| Full scans CRUD + live status polling | `scans.ts` | ✅ Done |
| SARIF 2.1 + JSON report export | `scans.ts` | ✅ Done |
| Projects CRUD | `projects.ts` | ✅ Done |
| Assets CRUD + OpenAPI spec import | `assets.ts` | ✅ Done |
| Findings CRUD + triage workflow | `findings.ts` | ✅ Done |
| Dashboard aggregate stats | `dashboard.ts` | ✅ Done |
| Health check endpoint | `health.ts` | ✅ Done |

### ✅ Database

| Feature | Status |
|---------|--------|
| PostgreSQL via Drizzle ORM | ✅ Done |
| Full schema: projects, assets, scans, findings, endpoints, activity | ✅ Done |
| Drizzle Kit migrations (`push`) | ✅ Done |

### ✅ Frontend

| Feature | Status |
|---------|--------|
| Scan Engine page (URL input → live scan → report) | ✅ Done |
| Real-time terminal log streaming | ✅ Done |
| Live finding cards (appear during scan) | ✅ Done |
| Threat level indicator (CLEAN/LOW/MODERATE/HIGH/CRITICAL) | ✅ Done |
| Collapsible finding cards with evidence, remediation, audit fields | ✅ Done |
| VERIFIED / SUSPECTED / INFORMATIONAL badges per finding | ✅ Done |
| CVSS score + CVE link (NVD) per finding | ✅ Done |
| Capability grid (12 detection categories) | ✅ Done |
| Projects list page | ✅ Done |
| Project detail — Assets / Scans / Findings tabs | ✅ Done |
| Settings page | ✅ Done |
| Sidebar layout with nav links | ✅ Done |
| Dark theme (full CSS variable system) | ✅ Done |

---

## What Is Not Yet Implemented

| Feature | Priority | Notes |
|---------|----------|-------|
| **Authentication / login** | High | No user auth on the platform itself. Anyone who can reach the URL can run scans. Needs session-based or JWT auth. |
| **Authenticated scan targets** | High | `auth-context.ts` exists but scan probes don't yet pass stored auth tokens to every HTTP request. Partially wired. |
| **Scan rate limiting / queue** | High | Worker processes one scan at a time. Concurrent scans from multiple users would queue infinitely. Needs a proper job queue (Bull/BullMQ or pg-boss). |
| **DNS-based SSRF/Log4Shell callback** | High | Log4Shell and SSRF confirmations require an out-of-band collaborator server (like Burp Collaborator / interactsh). Not implemented — current detection is surface-level only. |
| **Stored XSS detection** | Medium | Only reflected XSS is tested. Stored XSS requires posting payloads and later retrieving pages to check. |
| **DOM XSS detection** | Medium | Requires a headless browser (Playwright/Puppeteer). Not implemented — scanner uses HTTP fetch only. |
| **Clickjacking detection** | Medium | X-Frame-Options is checked in headers phase but no actual iframe embedding test is done. |
| **IDOR / Broken Object Level Auth** | Medium | Requires understanding the app's data model. Cannot be detected generically without authenticated sessions and parameter fuzzing. |
| **Business logic testing** | Medium | Price manipulation, workflow bypass, etc. — requires app-specific test cases. |
| **Scheduled/recurring scans** | Medium | No cron job or schedule configuration in the UI or backend. |
| **Team / multi-user support** | Medium | No concept of users, roles, or access control. Single-tenant only. |
| **Webhook notifications** | Low | No alerts when a scan finishes or a critical finding is detected. |
| **Email / Slack alerts** | Low | No notification integrations. |
| **OpenAPI-driven endpoint fuzzing** | Low | `endpoints` table is populated from spec import but the scanner doesn't yet iterate over each endpoint to fuzz its parameters specifically. |
| **PDF report export** | Low | JSON and SARIF export work. PDF is not implemented. |
| **Scan comparison / diffing** | Low | No ability to compare two scans of the same target over time. |
| **Mobile app** | Low | Task #2 is proposed but not started. |
| **Authorisation controls on scan targets** | Low | Task #3 is proposed but not started — no mechanism to prevent scanning unauthorised targets. |
| **GraphQL mutation fuzzing** | Low | GraphQL schema is discovered but individual mutations/queries are not fuzzed. |
| **API client React Query hooks** | Low | `packages/api-client` is generated but the frontend still uses raw `fetch()` calls in most places. |

---

## Setup & Installation

### Prerequisites

| Requirement | Version | Notes |
|-------------|---------|-------|
| Node.js | ≥ 20 | LTS recommended |
| pnpm | ≥ 9 | Enforced via `preinstall` script |
| PostgreSQL | ≥ 14 | Managed automatically on Replit |
| nmap | any | System package — installed in Nix env |
| dig (dnsutils) | any | System package — installed in Nix env |
| whois | any | System package — installed in Nix env |
| openssl | any | System package — installed in Nix env |

### On Replit (recommended — zero setup)

Everything is pre-configured. Just:
1. Open the Repl
2. The two workflows start automatically:
   - **`apps/web: web`** — React dev server
   - **`apps/api: API Server`** — Express backend + scan worker
3. The PostgreSQL database is provisioned automatically
4. `SESSION_SECRET` is set as a Replit Secret

### Local Setup

```bash
# 1. Clone the repository
git clone <repo-url>
cd sentinelx

# 2. Install dependencies (all workspaces)
pnpm install

# 3. Configure environment variables
cp .env.example .env
# Edit .env and set DATABASE_URL and SESSION_SECRET

# 4. Push the database schema
pnpm --filter @workspace/db run push

# 5. Start both services (two separate terminals)

# Terminal 1 — API server
pnpm --filter @workspace/api run dev

# Terminal 2 — Frontend
pnpm --filter @workspace/web run dev
```

### Environment File (`.env`)

Create this file at the project root:

```env
# PostgreSQL connection string (required)
DATABASE_URL=postgresql://user:password@localhost:5432/sentinelx

# Secret for AES-256-GCM encryption of stored auth tokens (required)
# Generate with: node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
SESSION_SECRET=your-64-hex-character-secret-here

# Optional overrides
PORT=3000          # API server port (default: 3000)
LOG_LEVEL=info     # Pino log level (default: info)
NODE_ENV=development
```

---

## Running the Project

### Start API Server

```bash
pnpm --filter @workspace/api run dev
```

Starts Express on `PORT` (default 3000). Automatically starts the scan worker background loop.

### Start Frontend

```bash
pnpm --filter @workspace/web run dev
```

Starts Vite dev server. The frontend proxies `/api/*` to the API server.

### Build for Production

```bash
pnpm run build
```

Builds all packages in dependency order. API server is bundled with esbuild into
`apps/api/dist/index.mjs`. Frontend is built to `apps/web/dist/public/`.

### Database Operations

```bash
# Push schema changes to the database (non-destructive)
pnpm --filter @workspace/db run push

# Generate migration files
pnpm --filter @workspace/db run generate

# Open Drizzle Studio (database GUI)
pnpm --filter @workspace/db run studio
```

### Type Checking

```bash
# Check all packages
pnpm run typecheck

# Check a specific package
pnpm --filter @workspace/api exec tsc --noEmit
```

---

## Environment Variables & Secrets

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `DATABASE_URL` | ✅ Yes | — | PostgreSQL connection string |
| `SESSION_SECRET` | ✅ Yes | — | 32+ byte secret for auth token encryption |
| `PORT` | No | `3000` | API server listen port |
| `LOG_LEVEL` | No | `info` | Pino log level (`trace`/`debug`/`info`/`warn`/`error`) |
| `NODE_ENV` | No | `development` | `production` enables stricter CORS, disables verbose errors |
| `REPL_ID` | No | — | Set automatically by Replit; triggers Replit-specific behaviour |

**On Replit:** Set `SESSION_SECRET` via **Secrets** (the lock icon in the sidebar). Never
commit it to source control. `DATABASE_URL` is injected automatically by the Replit
PostgreSQL integration.

---

## Database Schema

### `projects`

| Column | Type | Description |
|--------|------|-------------|
| `id` | serial PK | Auto-increment ID |
| `name` | text NOT NULL | Project display name |
| `description` | text | Optional description |
| `scope` | text | Target scope notes |
| `status` | text | `active` / `archived` |
| `createdAt` | timestamp | Creation time |
| `updatedAt` | timestamp | Last update time |

### `assets`

| Column | Type | Description |
|--------|------|-------------|
| `id` | serial PK | |
| `projectId` | integer FK | → projects.id |
| `value` | text | URL or IP address of the target |
| `type` | text | `url` / `ip` / `domain` |
| `status` | text | `active` / `inactive` |
| `notes` | text | Free-form notes |
| `technologies` | jsonb | Detected tech stack (set after scan) |
| `apiSpec` | text | Raw OpenAPI spec YAML/JSON |
| `apiSpecVersion` | text | Spec version string |
| `apiSpecImportedAt` | timestamp | When spec was imported |
| `createdAt` | timestamp | |

### `scans`

| Column | Type | Description |
|--------|------|-------------|
| `id` | serial PK | |
| `projectId` | integer FK | → projects.id |
| `name` | text | Human-readable scan name |
| `type` | text | Always `"full"` in current UI |
| `profile` | text | `"deep_authorized"` (default) / `"safe_active"` / `"safe_passive"` |
| `policy` | jsonb | Resolved `ScanPolicy` object (budget, timeout, flags) |
| `toolCapabilities` | jsonb | Which system tools were available at scan time |
| `authContext` | jsonb | Encrypted auth headers (if any) |
| `status` | text | `pending` / `running` / `completed` |
| `progress` | integer | 0–100 percentage |
| `findingsCount` | integer | Total findings at completion |
| `startedAt` | timestamp | |
| `completedAt` | timestamp | |
| `logs` | text | Full newline-separated terminal log |
| `createdAt` | timestamp | |

### `findings`

| Column | Type | Description |
|--------|------|-------------|
| `id` | serial PK | |
| `projectId` | integer FK | → projects.id |
| `scanId` | integer FK | → scans.id |
| `assetId` | integer FK | → assets.id |
| `endpointId` | integer FK nullable | → endpoints.id (if API scan) |
| `title` | text | Finding title |
| `description` | text | Full description |
| `severity` | text | `critical` / `high` / `medium` / `low` / `info` |
| `status` | text | `open` / `confirmed` / `mitigated` / `false_positive` |
| `verification` | text | `verified` / `suspected` / `version_match` / `informational` |
| `confidence` | integer | 0–100 confidence percentage |
| `evidenceQuality` | text | `weak` / `standard` / `strong` |
| `verificationMethod` | text | How finding was confirmed |
| `reproducibility` | text | `reproducible` / `intermittent` / `not_reproducible` / `not_tested` |
| `affectedEndpoint` | text | Specific URL that is vulnerable |
| `affectedParameter` | text | Parameter name (if applicable) |
| `negativeTests` | text | Description of negative controls run |
| `limitations` | text | Known limitations of the detection method |
| `toolInfo` | text | Which tool/technique produced the finding |
| `cvss` | real | CVSS v3 base score (0.0–10.0) |
| `cve` | text | CVE identifier (e.g. `CVE-2021-44228`) |
| `evidence` | text | Full proof / request-response snippet |
| `remediation` | text | Fix guidance |
| `createdAt` | timestamp | |
| `updatedAt` | timestamp | |

### `endpoints`

| Column | Type | Description |
|--------|------|-------------|
| `id` | serial PK | |
| `projectId` | integer FK | |
| `assetId` | integer FK | |
| `method` | text | HTTP method |
| `path` | text | Path pattern (e.g. `/api/users/{id}`) |
| `operationId` | text | OpenAPI operationId |
| `summary` | text | Short description |
| `parameters` | jsonb | Parameter definitions |
| `requestBody` | jsonb | Request body schema |
| `security` | jsonb | Security requirements |
| `source` | text | `openapi` / `wayback` / `scanner` |
| `baseUrl` | text | Base URL |
| `createdAt` | timestamp | |

### `activity`

| Column | Type | Description |
|--------|------|-------------|
| `id` | serial PK | |
| `type` | text | Event type (`scan_started`, `finding_created`, etc.) |
| `title` | text | Short event title |
| `description` | text | Event details |
| `severity` | text | Severity level (for finding events) |
| `projectId` | integer FK | |
| `projectName` | text | Denormalised for display speed |
| `createdAt` | timestamp | |

---

## API Reference

All routes are prefixed with `/api`.

### Quick Scan

```
POST /api/quick-scan
Content-Type: application/json

{
  "url": "https://target.example.com",
  "scanType": "full",           // optional, always "full"
  "profile": "deep_authorized"  // optional
}

→ 200 { "scanId": 42, "projectId": 1, "assetId": 1 }
```

### Scan Status (live polling)

```
GET /api/scans/:id/status

→ 200 {
  "scan": {
    "id": 42,
    "status": "running",       // pending | running | completed
    "progress": 67,
    "logs": "...\n...",
    "findingsCount": 5,
    ...
  },
  "findings": [ { Finding }, ... ]
}
```

### Scan Report

```
GET /api/scans/:id/report?format=json     → full JSON report
GET /api/scans/:id/report?format=sarif    → SARIF 2.1 for IDE/GitHub integration
```

### Projects

```
GET    /api/projects            → list all projects
POST   /api/projects            → create project
GET    /api/projects/:id        → get project with counts
PATCH  /api/projects/:id        → update project
DELETE /api/projects/:id        → delete project
```

### Assets

```
GET    /api/assets?projectId=1           → list assets for project
POST   /api/assets                       → add asset
POST   /api/assets/:id/import-spec       → import OpenAPI YAML/JSON
DELETE /api/assets/:id                   → delete asset
```

### Findings

```
GET    /api/findings?scanId=42           → list findings
GET    /api/findings?projectId=1         → list findings for project
PATCH  /api/findings/:id/status          → triage: open|confirmed|mitigated|false_positive
DELETE /api/findings/:id                 → delete finding
```

### Health

```
GET /api/healthz → 200 { "status": "ok", "ts": "2026-07-23T..." }
```

---

## Scanner Phases (All 21)

| # | Phase | Tool / Method | What It Finds |
|---|-------|---------------|---------------|
| 1 | WAF/CDN Detection & Bypass | HTTP fetch + response analysis | WAF vendor, IP-spoofing bypass, Googlebot bypass, direct origin IP |
| 2 | DNS Enumeration | `dig` | A/AAAA/MX/TXT/NS/CAA records, zone transfer attempt |
| 3 | IP Geolocation & ASN | ipinfo.io API | Hosting provider, country, ASN, cloud provider detection |
| 4 | WHOIS Intelligence | `whois` | Registrar, expiry, creation date, privacy protection status |
| 5 | Subdomain Discovery | crt.sh + DNS brute-force | All subdomains in cert transparency logs + common wordlist |
| 5b | Subdomain Takeover | CNAME + HTTP fetch | Dangling DNS to 17 services (GitHub Pages, S3, Netlify, Azure…) |
| 6 | Port Scanning | `nmap` -sV -T4 | All open ports, service versions, dangerous services |
| 7 | TLS/SSL Analysis | `openssl` + node:tls | Protocol versions, weak ciphers, cert expiry, HSTS preload |
| 8 | HTTP Security Headers | HTTP fetch | HSTS, CSP, X-Frame-Options, X-Content-Type, CORS, Referrer-Policy |
| 9 | Technology Fingerprinting | HTTP fetch + regex | 30+ signatures: WordPress, Next.js, React, Laravel, nginx, Apache… |
| 10 | Sensitive Path Discovery | HTTP fetch (50+ paths) | .env, .git, backup.sql, credentials.json, SSH keys, kubeconfig… |
| 11 | Wayback Machine | Wayback CDX API | Historical endpoints, old admin panels, removed sensitive pages |
| 12 | Web App Vulnerability Probes | HTTP fetch | Error SQLi, blind SQLi, XSS, NoSQL injection, command injection |
| 13 | API Surface Discovery | HTTP fetch | GraphQL introspection, Swagger UI, Spring Actuator, Telescope |
| 14 | Host Header Injection | HTTP fetch | Password-reset link poisoning via Host/X-Forwarded-Host reflection |
| 15 | CRLF Injection | HTTP fetch | HTTP response splitting via %0d%0a in redirect params |
| 16 | Path Traversal | HTTP fetch | File read via ../../../../etc/passwd (9 encoding variants) |
| 17 | JWT Weakness Detection | HTTP fetch + crypto | alg:none bypass, weak secret crack, missing exp claim |
| 18 | Log4Shell / Spring4Shell | HTTP fetch | JNDI payload injection, Spring class loader manipulation |
| 19 | Rate Limiting | HTTP fetch (10 rapid POSTs) | Absence of 429/lockout on login endpoints |
| 20 | Advanced Probes | HTTP fetch | SSTI, XXE, SSRF, Java deserialization, command injection (deep) |
| 21 | CVE Lookup | NVD API | Known CVEs for detected technology versions |

---

## Vulnerability Coverage Matrix

| Vulnerability Class | OWASP Top 10 | Detected? | Method | Confidence |
|--------------------|--------------|-----------|--------|-----------|
| SQL Injection (error-based) | A03 | ✅ | Error pattern matching + baseline diff | Suspected (72%) |
| SQL Injection (time-based blind) | A03 | ✅ | Timing comparison vs baseline | Suspected (78%) |
| Cross-Site Scripting (reflected) | A03 | ✅ | Payload reflection in HTML response | Suspected (78%) |
| Cross-Site Scripting (stored) | A03 | ❌ | Requires headless browser | — |
| DOM-based XSS | A03 | ❌ | Requires headless browser | — |
| NoSQL Injection (MongoDB) | A03 | ✅ | Operator injection + success signal | Suspected (75-80%) |
| OS Command Injection | A03 | ✅ | Canary token execution | Verified (99%) |
| Path Traversal | A01 | ✅ | File content confirmation (/etc/passwd) | Verified (99%) |
| SSTI (15+ engines) | A03 | ✅ | Arithmetic canary | Verified (95%) |
| XXE | A05 | ✅ | Entity file read | Verified (90%) |
| SSRF | A10 | ✅ | Cloud metadata access | Verified (90%) |
| Java Deserialization | A08 | ✅ | Error pattern surface detection | Suspected (65%) |
| CRLF Injection | A03 | ✅ | Injected header in response | Verified (98%) |
| Host Header Injection | A01 | ✅ | Injected value reflected | Verified (92%) |
| Subdomain Takeover | A05 | ✅ | Dangling CNAME + service indicator | Verified (96%) |
| JWT alg:none | A02 | ✅ | Algorithm field check | Verified (99%) |
| JWT weak secret | A02 | ✅ | HMAC crack against common secrets | Verified (99%) |
| Log4Shell (CVE-2021-44228) | A06 | ✅ (surface) | JNDI payload + Java error signal | Suspected (72%) |
| Spring4Shell (CVE-2022-22965) | A06 | ✅ (surface) | Class loader pattern response | Suspected (65%) |
| Sensitive File Exposure | A01 | ✅ | Direct path fetch | Verified (95%) |
| TLS Weaknesses | A02 | ✅ | openssl protocol/cipher check | Verified (98%) |
| Missing Security Headers | A05 | ✅ | Header presence check | Verified (99%) |
| Open Redirect | A01 | ✅ | Redirect location check | Suspected (70%) |
| GraphQL Introspection | A01 | ✅ | Schema query | Verified (99%) |
| Rate Limiting Absence | A07 | ✅ | 10-request flood test | Verified (85%) |
| WAF Bypass | — | ✅ | IP headers + UA tricks | Suspected (72%) |
| CORS Misconfiguration | A01 | ✅ | Origin reflection check | Verified (95%) |
| Clickjacking | A05 | ⚠️ Partial | X-Frame-Options header check only | Informational |
| IDOR | A01 | ❌ | Requires auth context | — |
| Business Logic | A04 | ❌ | App-specific | — |

---

## Technology Stack

### Backend
| Package | Version | Purpose |
|---------|---------|---------|
| `express` | 5.x | HTTP server framework |
| `drizzle-orm` | latest | Type-safe ORM |
| `pg` | latest | PostgreSQL client |
| `pino` / `pino-http` | latest | Structured JSON logging |
| `esbuild` | latest | Production bundler |
| `typescript` | 5.x | Type safety |
| `zod` | 3.x | Runtime schema validation |

### Frontend
| Package | Version | Purpose |
|---------|---------|---------|
| `react` | 19.x | UI framework |
| `vite` | 6.x | Dev server + bundler |
| `tailwindcss` | 4.x | Utility CSS |
| `@tanstack/react-query` | 5.x | Server state management |
| `framer-motion` | 11.x | Animations |
| `wouter` | 3.x | Client-side routing |
| `lucide-react` | latest | Icon set |
| Radix UI (multiple) | latest | Accessible UI primitives (shadcn/ui) |

### Infrastructure
| Tool | Purpose |
|------|---------|
| pnpm workspaces | Monorepo package management |
| Drizzle Kit | Database migrations |
| PostgreSQL | Primary data store (Replit managed) |
| Nix (on Replit) | System package management |

---

## System Tool Requirements

The scanner shells out to these system tools. On Replit, all are available by default.
For local setup, install them via your package manager.

| Tool | Install (Ubuntu/Debian) | Install (macOS) | Used For |
|------|------------------------|-----------------|----------|
| `nmap` | `apt install nmap` | `brew install nmap` | Port scanning, service detection |
| `dig` | `apt install dnsutils` | `brew install bind` | DNS enumeration |
| `whois` | `apt install whois` | `brew install whois` | Domain WHOIS |
| `openssl` | usually pre-installed | usually pre-installed | TLS/SSL analysis |

The scanner gracefully degrades if a tool is missing — `discoverToolCapabilities()` checks
availability at startup and disables the corresponding phase with a log message.

---

## Scan Profiles

| Profile | Request Budget | Timeout | Concurrency | Deep Checks | Use When |
|---------|---------------|---------|-------------|-------------|----------|
| `safe_passive` | 100 | 8s | 2 | ❌ | DNS/headers only, no active probes |
| `safe_active` | 500 | 12s | 4 | ❌ | Standard active scan, no heavy payloads |
| `deep_authorized` | 6000 | 20s | 10 | ✅ | **Default** — full exploit chain testing, authorised targets only |

> ⚠️ **Legal Notice**: Only scan systems you own or have explicit written authorisation
> to test. Unauthorised scanning may violate computer fraud laws in your jurisdiction.
> SentinelX is for authorised security testing only.

---

*Generated by SentinelX — Last updated 2026-07-23*
