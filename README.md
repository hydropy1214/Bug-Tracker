# SentinelX

**Full-stack web security reconnaissance platform.**  
Point it at a domain or IP, and a 50-phase scanner runs DNS enumeration, port scanning, TLS analysis, injection testing, CVE matching, JWT auditing, and more — surfacing findings live in a React dashboard.

---

## Table of Contents

1. [Tech Stack](#tech-stack)
2. [Repository Layout](#repository-layout)
3. [Apps](#apps)
   - [API (`apps/api`)](#api-appsapi)
   - [Web (`apps/web`)](#web-appsweb)
4. [Packages](#packages)
   - [Database (`packages/db`)](#database-packagesdb)
   - [API Types (`packages/api-types`)](#api-types-packagesapi-types)
5. [Scanner Engine](#scanner-engine)
   - [Pipeline Architecture](#pipeline-architecture)
   - [All Scan Phases](#all-scan-phases)
6. [Database Schema](#database-schema)
7. [API Routes](#api-routes)
8. [Frontend Pages & Components](#frontend-pages--components)
9. [Scripts](#scripts)
10. [Environment Variables & Secrets](#environment-variables--secrets)
11. [Setup & Running Locally](#setup--running-locally)
12. [Replit Import (Auto-Setup)](#replit-import-auto-setup)
13. [Development Conventions](#development-conventions)

---

## Tech Stack

| Layer | Technology |
|---|---|
| Frontend | React 19, Vite 7, TypeScript, Tailwind CSS v4, Radix UI, Framer Motion, Recharts, Wouter, TanStack Query |
| Backend | Express 5, TypeScript (ESM), Pino structured logging |
| Database | PostgreSQL (Replit-managed), Drizzle ORM, drizzle-zod |
| Package manager | pnpm 10 (workspace monorepo) |
| Build | esbuild (API), Vite (web), tsc project references |
| Runtime | Node 20 |

---

## Repository Layout

```
sentinelx/
├── apps/
│   ├── api/                    # Express API server + scan engine
│   └── web/                    # React dashboard (Vite)
├── packages/
│   ├── db/                     # Drizzle ORM schema + client
│   └── api-types/              # Shared Zod schemas & TypeScript types
├── scripts/
│   ├── setup.sh                # One-time install + DB migration (runs on import)
│   └── post-merge.sh           # Re-install + DB push after git merge
├── .replit                     # Replit workflow, port, and env config
├── replit.nix                  # System packages (nmap, dig, whois, nuclei, ffuf…)
├── pnpm-workspace.yaml         # Workspace members declaration
├── tsconfig.base.json          # Shared TypeScript compiler base
└── package.json                # Root scripts: build, typecheck, format
```

---

## Apps

### API (`apps/api`)

Express 5 REST API that:
- Receives scan requests and queues them for the background worker
- Streams live scan progress and findings to the frontend via polling
- Manages projects, assets, endpoints, and findings in PostgreSQL

**Entry points**

| File | Purpose |
|---|---|
| `src/index.ts` | Starts the HTTP server, binds to `PORT` (default 8080), calls `startScanWorker()` |
| `src/app.ts` | Configures Express: Helmet (no CSP), open CORS, Pino HTTP logging, body parsers, mounts `/api` router, root health probe |

**`src/lib/`**

| File | Purpose |
|---|---|
| `api-schema.ts` | Zod schemas for every API request/response body |
| `auth-context.ts` | `encryptAuthHeaders` / `decryptAuthHeaders` — AES-256-GCM encryption of per-scan auth credentials using `SESSION_SECRET` |
| `encryption.ts` | Low-level AES-256-GCM helpers (key derivation from `SESSION_SECRET` via SHA-256) |
| `logger.ts` | Pino logger instance — structured JSON in production, pretty-printed in development |
| `scan-worker.ts` | Background polling loop (every 2 s) — picks up `pending` scans, runs `scanTarget()`, writes progress + findings to the database, handles cancellation |
| `scanner/` | The full scanner engine — see [Scanner Engine](#scanner-engine) |

**Build**

`apps/api/build.mjs` drives esbuild: bundles all source into `dist/index.mjs` plus Pino worker shims. Source maps included. The dev script runs `build` then `start` (there is no native ESM watch — esbuild rebuilds on each `dev` invocation).

---

### Web (`apps/web`)

React 19 SPA served by Vite. All `/api/*` requests are proxied to the API server at `API_PORT` (8080).

**Entry points**

| File | Purpose |
|---|---|
| `index.html` | HTML shell — sets title, meta/OG tags, PWA manifest link, theme color `#00ff80` |
| `src/main.tsx` | Mounts React root into `#root` |
| `src/App.tsx` | `QueryClientProvider` + `WouterRouter` + `Toaster` — renders `Router` which wraps all pages in `Shell` |

**`src/pages/`**

| File | Route | Purpose |
|---|---|---|
| `HomeDashboard.tsx` | `/` | Overview cards (projects, assets, open findings, critical/high, active scans), finding distribution chart, severity breakdown, activity feed |
| `ScanEngine.tsx` | `/scan` | Quick-scan form — enter a target, choose scan type and profile, start a scan, watch live progress |
| `Projects.tsx` | `/projects` | Create and list projects |
| `ProjectDetail.tsx` | `/projects/:id` `/projects/:id/:tab` | Three-tab view: Assets, Findings, Scans — with per-project drill-down |
| `Scans.tsx` | `/scans` | Global scan history table |
| `Settings.tsx` | `/settings` | System / scanner configuration |
| `AssetsTab.tsx` | (sub-component) | Assets table used inside `ProjectDetail` |
| `FindingsTab.tsx` | (sub-component) | Findings table with severity filters used inside `ProjectDetail` |
| `ScansTab.tsx` | (sub-component) | Scans table used inside `ProjectDetail` |
| `Dashboard.tsx` | (sub-component) | Reusable dashboard stats grid |
| `not-found.tsx` | `*` | Animated 404 page with shield icon and "Back to Dashboard" CTA |

**`src/components/`**

| Directory | Purpose |
|---|---|
| `layout/Shell.tsx` | App shell — collapsible sidebar with brand logo (inline SVG shield+X), navigation links (Dashboard, Scan Engine, Projects, All Scans, Settings), version badge |
| `dashboard/` | Widgets specific to the dashboard: stat cards, severity charts, activity feed items, findings list |
| `ui/` | Full Radix UI + Tailwind component library — Button, Card, Dialog, Table, Badge, Select, Tabs, Tooltip, and ~30 more primitives |

**`src/hooks/`**

| File | Purpose |
|---|---|
| `useScanPolling.ts` | Polls `/api/scans/:id` on an interval when a scan is active; stops automatically on terminal states (completed / failed / cancelled); provides `progress`, `status`, and `findings` |
| `use-mobile.tsx` | Returns `true` when viewport is below the mobile breakpoint |
| `use-toast.ts` | Thin wrapper around `sonner` for imperative toasts |

**`public/`**

| File | Purpose |
|---|---|
| `favicon.svg` | SentinelX shield+X mark — dark rounded background, `#00ff80` outline and X |
| `manifest.json` | PWA manifest — name, colors, SVG icon, `display: standalone` |
| `robots.txt` | Allows all crawlers |

---

## Packages

### Database (`packages/db`)

Drizzle ORM client and all table definitions. Imported by the API as `@workspace/db`.

**`src/schema/`**

| File | Table | Key columns |
|---|---|---|
| `projects.ts` | `projects` | `id`, `name`, `description`, `scope`, `status` (active/archived), `createdAt`, `updatedAt` |
| `assets.ts` | `assets` | `id`, `projectId` (FK→projects), `type`, `value` (domain / IP / URL), `status`, `metadata` (JSON), `createdAt` |
| `endpoints.ts` | `endpoints` | `id`, `assetId` (FK→assets), `url`, `method`, `statusCode`, `responseTime`, `technologies` (JSON array) |
| `findings.ts` | `findings` | `id`, `projectId`, `scanId`, `assetId`, `endpointId`, `title`, `description`, `severity` (critical/high/medium/low/info), `status` (open/resolved/false_positive), `cvss`, `cve`, `evidence`, `remediation`, plus verification metadata |
| `scans.ts` | `scans` | `id`, `projectId`, `name`, `type`, `profile`, `policy` (JSON), `toolCapabilities`, `authContext` (AES-256-GCM), `cancelRequested`, `status`, `progress` (0-100), `findingsCount`, `wafBlocked`, `startedAt`, `completedAt`, `logs` |
| `activity.ts` | `activity` | `id`, `projectId`, `scanId`, `type`, `message`, `metadata`, `createdAt` |

All tables export a Drizzle insert schema (via `drizzle-zod`) and inferred `Insert*` / `*` TypeScript types.

**`drizzle.config.ts`** — points Drizzle Kit at `DATABASE_URL`; runs with `pnpm run push` to apply schema changes without migrations.

---

### API Types (`packages/api-types`)

Shared Zod v4 schemas and TypeScript types used by both the API (for validation) and the web (for type-safe API calls). Exported from `src/index.ts` and `src/generated/` (generated OpenAPI client stubs).

---

## Scanner Engine

All scanner code lives in `apps/api/src/lib/scanner/`.

### Pipeline Architecture

The scanner runs in **5 sequential rounds** with maximum parallelism within each round:

```
Round 1 — WAF / CDN detection
  (solo; must complete before any active probe so WAF context is available)

Round 2 — Passive recon + OSINT  [all parallel]
  DNS · IP info · WHOIS · Subdomains · Subdomain permutations · Ports ·
  TLS · HTTP headers · Tech fingerprint · Favicon hash · Sensitive paths ·
  Wayback Machine · Google dorking · GitHub dorking · Cloud buckets ·
  Email harvesting · Leak detection

Round 3 — Active web probes + surface crawl  [all parallel]
  Webapp probes · API surface scan · Attack surface discovery ·
  Parameter discovery · API leaks · Config exposure

Round 4 — Deep attack phases  [all parallel]
  Deep input testing · Host header injection · CRLF injection ·
  Path traversal · JWT weaknesses · IDOR / BOLA · HTTP request smuggling ·
  Log4Shell surface · Rate limiting · Open redirect · IP range / RDAP ·
  Nuclei · JS secrets · CORS misconfiguration · GraphQL deep scan ·
  SQLi advanced · Prototype pollution · OAuth misconfiguration ·
  vHost discovery · ffuf discovery · XSS · CVE lookup ·
  Advanced probes · Advanced tests

Round 5 — Weaponised verification  [only when policy.allowVerification]
  Open registration check · Default credentials · SQLi auth bypass ·
  IDOR with captured session
```

WAF detection gates all active probes: if a WAF challenge is detected, active probes stop, sensitive signals (SSTI, NoSQL) are suppressed, and remaining findings are downgraded to informational.

**Key files**

| File | Purpose |
|---|---|
| `orchestrator.ts` | Wires all phases together; manages the 5-round pipeline; produces the `ScanResult` with executive summary, risk grade, and compliance mapping |
| `context.ts` | `scanContext()` factory — holds the mutable scan state (WAF flag, captured session, request budget); exports `runActiveChecks`, `isWafChallengeDetected`, etc. |
| `index.ts` | Public entry: exports `scanTarget()`, `resolveScanPolicy()`, `discoverToolCapabilities()` |

### All Scan Phases

| Phase file | What it checks |
|---|---|
| `waf-detection.ts` | Detects WAF/CDN providers; probes for challenge pages and bypass headers |
| `dns.ts` | A, AAAA, MX, TXT, NS, CAA, SPF, DMARC, DNSSEC records; zone-transfer attempt |
| `ip-info.ts` | ASN, organisation, country, hosting provider via ipinfo.io |
| `whois.ts` | Domain registrar, registrant, expiry via `whois` binary |
| `subdomains.ts` | Subdomain enumeration via crt.sh + brute-force wordlist; takeover detection (dangling CNAME check) |
| `subdomain-permutations.ts` | Generates and resolves permutation-based subdomains |
| `ports.ts` | TCP port scan via `nmap` — top 1000 ports, service/version detection |
| `tls.ts` | TLS certificate chain, expiry, weak ciphers, protocol versions, HSTS |
| `headers.ts` | Security headers audit (CSP, X-Frame-Options, CORS policy, cookie flags, etc.) |
| `tech-fingerprint.ts` | CMS, framework, server, CDN identification from headers + HTML + favicon hash |
| `favicon-hash.ts` | MurmurHash of favicon — matched against known-software fingerprint database |
| `sensitive-paths.ts` | Probes 100+ common sensitive paths (`.env`, `/admin`, `/.git`, `phpinfo.php`, etc.) |
| `wayback.ts` | Queries Wayback Machine CDX API for historical endpoints and interesting paths |
| `google-dorking.ts` | Constructs Google dork queries for exposed files, login pages, and sensitive content |
| `github-dorking.ts` | Searches GitHub for leaked source, config files, and secrets tied to the target domain |
| `cloud-buckets.ts` | Probes for misconfigured S3 / GCS / Azure Blob Storage buckets |
| `email-harvesting.ts` | Collects email addresses from DNS, crt.sh, and public OSINT sources |
| `leak-detection.ts` | Checks HaveIBeenPwned and similar sources for domain-associated credential leaks |
| `webapp-probes.ts` | Login page detection, admin panels, robots.txt, sitemap, error page analysis |
| `api-surface.ts` | Discovers API endpoints from JS files, `/openapi.json`, `/swagger.json`, common API paths |
| `surface-discovery.ts` | Crawls the site to build a URL + form + parameter inventory |
| `parameter-discovery.ts` | Fuzzes parameters on discovered endpoints |
| `api-leaks.ts` | Looks for exposed API keys, tokens, and secrets in JS bundles and responses |
| `config-exposure.ts` | Checks for exposed configuration files (.env, config.yml, database.yml, etc.) |
| `deep-input-testing.ts` | Parameterised SSTI, NoSQL injection, and polyglot payload tests across all discovered inputs |
| `host-header.ts` | Host header injection — cache poisoning, SSRF via Host, X-Forwarded-Host manipulation |
| `crlf.ts` | CRLF injection in paths, headers, and redirects |
| `path-traversal.ts` | Directory traversal via URL paths, query params, and upload endpoints |
| `jwt.ts` | JWT audit — 25 weak secrets, `alg:none`, RS256→HS256 confusion, JKU/JWK injection, empty signature, expired token acceptance |
| `idor.ts` | IDOR / BOLA — increments numeric IDs in paths and params, checks for cross-user data exposure |
| `request-smuggling.ts` | HTTP/1.1 request smuggling — CL.TE and TE.CL variants |
| `log4shell.ts` | Log4Shell surface detection — injects JNDI payloads into headers and inputs |
| `rate-limiting.ts` | Tests login, registration, and API endpoints for missing rate limiting |
| `open-redirect.ts` | Open redirect in `redirect`, `return_url`, `next`, and similar parameters |
| `ip-range.ts` | RDAP-based ASN/IP range lookup; identifies sibling hosts in the same network block |
| `nuclei.ts` | Runs the `nuclei` binary with critical/high/medium severity templates against the target |
| `js-secrets.ts` | Static analysis of all JS bundles for API keys, tokens, and private credentials |
| `cors-bypass.ts` | CORS misconfiguration — tests `attacker.com` origin reflection, null origin, credentials leakage |
| `graphql-deep.ts` | GraphQL introspection, batch queries, field-level injection, and DoS via deeply nested queries |
| `sqli-advanced.ts` | 30+ SQL injection patterns — boolean-based blind, time-based blind, JSON/cookie/header injection, error-based |
| `prototype-pollution.ts` | Client-side and server-side prototype pollution via `__proto__`, `constructor.prototype` |
| `oauth-misconfig.ts` | OAuth 2.0 misconfigurations — open redirect in `redirect_uri`, state parameter CSRF, token leakage |
| `vhost-discovery.ts` | Virtual host enumeration via wordlist fuzzing on the resolved IP |
| `ffuf-discovery.ts` | Content/directory discovery using the `ffuf` binary with a curated wordlist |
| `xss.ts` | Reflected and stored XSS — tests inputs, headers, and URL fragments |
| `cve-lookup.ts` | Maps detected software versions against known CVEs |
| `advanced-probes.ts` | Miscellaneous advanced checks: SSRF, XXE, template injection in non-web contexts |
| `advanced/` | Specialised sub-modules for complex multi-step attack chains |
| `compliance.ts` | Maps all findings to OWASP Top 10, PCI DSS, and NIST frameworks |
| `verification/active.ts` | Weaponised confirmation probes: open registration, default credentials, SQLi auth bypass, session-based IDOR |

---

## Database Schema

Six tables, all with cascade deletes top-down (`projects` → `assets`/`scans` → `endpoints`/`findings` → `activity`).

```
projects
  └── assets        (projectId FK)
        └── endpoints   (assetId FK)
  └── scans         (projectId FK)
        └── findings    (scanId FK, assetId FK, endpointId FK)
  └── activity      (projectId FK, scanId FK)
```

All timestamps are `timestamp with time zone`. All tables have covering indexes on their most-queried foreign keys and status columns.

---

## API Routes

All routes are mounted under `/api`. Defined in `apps/api/src/routes/`.

| Method | Path | Handler file | Purpose |
|---|---|---|---|
| `GET` | `/api/healthz` | `health.ts` | Liveness check — returns `{ ok: true, version }` |
| `GET` | `/api/dashboard/stats` | `dashboard.ts` | Aggregate counts: projects, assets, open findings, critical/high, active scans |
| `GET` | `/api/dashboard/severity-breakdown` | `dashboard.ts` | Finding counts grouped by severity |
| `GET` | `/api/dashboard/recent-findings` | `dashboard.ts` | Latest 10 open findings across all projects |
| `GET` | `/api/dashboard/activity` | `dashboard.ts` | Latest 20 activity log entries |
| `GET` | `/api/projects` | `projects.ts` | List all projects |
| `POST` | `/api/projects` | `projects.ts` | Create a project |
| `GET` | `/api/projects/:id` | `projects.ts` | Get a single project |
| `PATCH` | `/api/projects/:id` | `projects.ts` | Update project name/description/scope/status |
| `DELETE` | `/api/projects/:id` | `projects.ts` | Delete project (cascades to all children) |
| `GET` | `/api/projects/:id/assets` | `assets.ts` | List assets for a project |
| `POST` | `/api/projects/:id/assets` | `assets.ts` | Add an asset to a project |
| `GET` | `/api/projects/:id/findings` | `findings.ts` | List findings for a project (filterable by severity/status) |
| `PATCH` | `/api/findings/:id` | `findings.ts` | Update finding status (open/resolved/false_positive) |
| `GET` | `/api/projects/:id/scans` | `scans.ts` | List scans for a project |
| `GET` | `/api/scans` | `scans.ts` | List all scans (global history) |
| `GET` | `/api/scans/:id` | `scans.ts` | Get scan detail including live progress, logs, and findings |
| `POST` | `/api/scans` | `scans.ts` | Create and queue a new scan |
| `POST` | `/api/scans/:id/cancel` | `scans.ts` | Request cancellation of an in-progress scan |
| `POST` | `/api/quick-scan` | `quick-scan.ts` | One-shot scan with auto project/asset creation |
| `GET` | `/api/settings` | `settings.ts` | Read scanner settings |
| `PATCH` | `/api/settings` | `settings.ts` | Update scanner settings |

---

## Frontend Pages & Components

### Routing

Wouter handles client-side routing. The router base is `import.meta.env.BASE_URL` (stripped of trailing slash) to support Replit's path-based proxy.

| Path | Component |
|---|---|
| `/` | `HomeDashboard` |
| `/scan` | `ScanEngine` |
| `/projects` | `Projects` |
| `/projects/:id` | `ProjectDetail` (defaults to assets tab) |
| `/projects/:id/:tab` | `ProjectDetail` (tab: `assets` / `findings` / `scans`) |
| `/scans` | `Scans` |
| `/settings` | `Settings` |
| `/dashboard` | Redirects → `/` |
| `*` | `NotFound` |

### Live Scan Polling

`useScanPolling` polls `GET /api/scans/:id` every 2 seconds while `status` is `pending` or `running`. It stops automatically when the scan reaches a terminal state. The hook is ref-stable — callbacks don't cause duplicate timers.

---

## Scripts

| Script | File | Run with |
|---|---|---|
| First-time setup | `scripts/setup.sh` | `bash scripts/setup.sh` — installs deps + pushes DB schema |
| Post-merge hook | `scripts/post-merge.sh` | Auto-run by Replit after a branch merge — same as setup |

**`scripts/setup.sh`** is idempotent: `pnpm install --frozen-lockfile` is a no-op if `node_modules` is already populated; `pnpm --filter @workspace/db run push` is a no-op if the schema is already current.

---

## Environment Variables & Secrets

All values are pre-configured in `.replit` under `[userenv.shared]` and should not need manual changes in normal development.

| Variable | Type | Value | Notes |
|---|---|---|---|
| `SESSION_SECRET` | **Secret** (encrypted) | set | Used to derive the AES-256 key for encrypting per-scan auth headers; must never be committed |
| `DATABASE_URL` | Runtime-managed | auto | Provisioned by Replit's PostgreSQL integration; do not set manually |
| `PORT` | Shared env | `5173` | Port the Vite dev server binds to; used by Replit's preview proxy to route to the web app |
| `API_PORT` | Shared env | `8080` | Port the Express API server binds to; must match the Vite proxy target in `vite.config.ts` |
| `BASE_PATH` | Shared env | `/` | Injected into Vite as the base URL prefix; missing this causes a blank page |
| `NODE_ENV` | Shared env | `development` | Controls Pino pretty-printing and Vite plugin activation |

---

## Setup & Running Locally

### Prerequisites

- Node 20+
- pnpm 10+ (`npm install -g pnpm`)
- PostgreSQL (or a `DATABASE_URL` pointing to a managed instance)

### Steps

```bash
# 1. Clone
git clone https://github.com/your-org/sentinelx.git
cd sentinelx

# 2. Set environment variables
export SESSION_SECRET="your-random-secret"
export DATABASE_URL="postgresql://user:pass@host:5432/sentinelx"

# 3. Install all workspace dependencies
pnpm install

# 4. Push the database schema (creates all 6 tables)
pnpm --filter @workspace/db run push

# 5. Start both services (in separate terminals)
PORT=8080 pnpm --filter @workspace/api run dev   # API on :8080
pnpm --filter @workspace/web run dev              # Web on :5173
```

Open `http://localhost:5173`. The Vite dev server proxies all `/api/*` requests to `:8080` automatically.

### Useful root-level scripts

```bash
pnpm typecheck      # Type-check all packages (zero errors enforced)
pnpm build          # Full production build (typecheck + all packages)
pnpm format:check   # Prettier check on scanner + core files
```

---

## Replit Import (Auto-Setup)

When you import this repository into Replit and press **Run**, the **Project** workflow fires in order:

1. **`bash scripts/setup.sh`** — installs all `node_modules` and pushes the DB schema  
2. **`apps/api: API Server`** — builds and starts Express on port 8080  
3. **`apps/web: web`** — starts Vite on port 5173

The `.replit` file contains `[[ports]]` declarations that route port 5173 to Replit's external port 80 (the web preview) and expose port 8080 separately. No manual setup steps are required.

The only requirement is that `SESSION_SECRET` is set as a Replit Secret before the first run. All other env vars are pre-declared in `.replit → [userenv.shared]`.

---

## Development Conventions

- **TypeScript strict mode** is enabled everywhere. `pnpm typecheck` must pass with zero errors.
- **ESM throughout** — all packages use `"type": "module"`.
- **Pino for all server logging** — never use `console.log` in API code.
- **Drizzle over raw SQL** — all database access goes through the Drizzle client from `@workspace/db`.
- **Zod for validation** — request bodies are validated with Zod schemas before any business logic.
- **No `node_modules` in git** — the lockfile (`pnpm-lock.yaml`) is committed; modules are restored by `pnpm install`.
- **pnpm only** — the root `preinstall` script rejects npm and yarn with an explicit error.
- **Scanner phases are additive** — each phase returns an array of `RealFinding` objects and never throws; failures are caught and returned as informational findings so one bad phase cannot abort the entire scan.
