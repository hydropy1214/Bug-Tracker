# SentinelX — Security Scanner

SentinelX is a full-stack web security reconnaissance and vulnerability scanning platform. Point it at a domain or IP address and it runs a 28-phase scan covering DNS, port scanning, TLS, WAF detection, injection testing (SQLi, XSS, SSTI, XXE, SSRF, NoSQLi), JWT weaknesses, CVE matching, path traversal, HTTP smuggling, CORS misconfigurations, and more.

---

## Architecture

```
apps/
  api/          Express 5 · TypeScript — scan engine + REST API
  web/          React 19 · Vite 7 · Tailwind 4 — dashboard UI

packages/
  db/           Drizzle ORM schema + PostgreSQL client
  api-client/   Orval-generated TypeScript client (React Query hooks)
  api-types/    Zod schemas and TypeScript types (from OpenAPI spec)
  api-spec/     OpenAPI 3.1 specification (openapi.yaml)
```

---

## Quick Start

### Prerequisites

| Tool | Version |
|------|---------|
| Node.js | 20+ |
| pnpm | 10+ |

### Required Environment Variables

| Variable | Where | Notes |
|----------|-------|-------|
| `DATABASE_URL` | Runtime-managed | Provisioned automatically by Replit |
| `SESSION_SECRET` | Secret | AES-256-GCM key for encrypting auth headers in scans |
| `API_PORT` | Shared env | Port the API dev server binds to (e.g. `8080`) — used by the Vite proxy |

Optional:

| Variable | Default | Notes |
|----------|---------|-------|
| `ALLOWED_ORIGINS` | _(none)_ | Comma-separated list of allowed CORS origins in production |
| `NODE_ENV` | `development` | Set to `production` in deployed environments |

### Install & run

```bash
pnpm install

# Push the database schema (first run only, or after schema changes)
pnpm --filter @workspace/db push

# Start both services in separate terminals:
pnpm --filter @workspace/web run dev      # frontend — http://localhost:{PORT}
pnpm --filter @workspace/api run dev      # API — http://localhost:{API_PORT}
```

In Replit, both workflows start automatically. The Vite dev server proxies `/api/*` requests to the API service.

---

## Scan Engine

### Scan types

| Type | Description |
|------|-------------|
| `recon` | DNS, WHOIS, subdomain discovery, technology fingerprinting |
| `enumeration` | Port scanning, service banners, API surface mapping |
| `vulnerability` | CVE checks, injection testing, misconfigurations |
| `full` | All phases combined (default for Quick Scan) |

### Scan profiles

| Profile | Description |
|---------|-------------|
| `passive` | Read-only — no active probes |
| `safe_active` | Active checks with harmless canary payloads |
| `deep_authorized` | Full depth scan (default) |
| `authenticated` | Uses auth headers for session-authenticated scanning |
| `lab` | Unrestricted — for isolated lab environments only |

### 28 scan phases

1. WAF/CDN detection  
2. DNS enumeration (A, MX, TXT, NS, CNAME, PTR)  
3. Subdomain discovery (crt.sh, brute-force, DNS zone transfer)  
4. Port scanning (nmap 65535 ports)  
5. TLS/SSL analysis (protocols, cipher suites, cert expiry, HSTS)  
5b. WHOIS lookup  
6. IP geolocation & ASN  
7. Wayback Machine historical URL analysis  
8. HTTP security headers audit  
9. Technology fingerprinting (WordPress, Nginx, Next.js, Laravel, …)  
10. Sensitive path discovery (50+ paths: .env, .git, backup.sql, …)  
11. Web application probes (CORS, cookies, TRACE, HTTPS enforcement)  
11b. Config/debug endpoint exposure  
12. API surface discovery (GraphQL, Swagger, Spring Actuator, …)  
13. Deep input testing — SQL injection (30+ patterns, boolean, JSON/cookie/header)  
13b. XSS reflection testing  
13c. SSTI (Server-Side Template Injection with arithmetic canary + RCE escalation)  
13d. Path traversal  
13e. CRLF injection  
14. Advanced: SSRF (cloud metadata), CMDi (time-based + canary)  
15. Advanced: NoSQLi (operator injection), XXE (file read)  
16. JWT weakness detection (alg:none, weak HS256 secrets, missing exp, JKU/JWK confusion, RS256→HS256)  
17. Log4Shell / Spring4Shell surface detection  
18. IDOR / BOLA testing  
19. HTTP request smuggling (CL.TE, TE.CL)  
20. Host header injection (password-reset link poisoning)  
21. Rate limiting detection  
22. CVE matching (NVD API cross-reference against detected versions)  
23. Compliance mapping (OWASP Top 10, PCI-DSS, NIST 800-53)  
24. Bounded weaponized verification (open registration, default creds, SQLi auth bypass)  
25–28. IDOR, GraphQL introspection, restricted endpoint verification  

---

## API Reference

Base path: `/api`

### Health

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/healthz` | Health check |

### Quick Scan

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/quick-scan` | Start a quick scan (creates project + asset + scan automatically) |

**Body:**
```json
{
  "url": "https://example.com",
  "scanType": "full",
  "profile": "deep_authorized",
  "authHeaders": { "Authorization": "Bearer token" }
}
```

### Projects

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/projects` | List all projects |
| POST | `/api/projects` | Create project |
| GET | `/api/projects/:id` | Get project |
| PATCH | `/api/projects/:id` | Update project |
| DELETE | `/api/projects/:id` | Delete project |

### Assets

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/projects/:projectId/assets` | List assets |
| POST | `/api/projects/:projectId/assets` | Add asset |
| PATCH | `/api/assets/:id` | Update asset |
| DELETE | `/api/assets/:id` | Delete asset |
| POST | `/api/assets/:id/import` | Import OpenAPI spec |
| GET | `/api/projects/:projectId/endpoints` | List imported endpoints |

### Scans

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/scans` | Global scan history |
| GET | `/api/projects/:projectId/scans` | Scans for a project |
| POST | `/api/projects/:projectId/scans` | Start a scan |
| GET | `/api/scans/:id` | Get scan |
| POST | `/api/scans/:id/stop` | Stop/cancel scan |
| GET | `/api/scans/:id/status` | Poll scan status + live findings |
| GET | `/api/scans/:id/report` | Download report (JSON or `?format=sarif`) |
| GET | `/api/scans/:id/diff/:baselineId` | Diff two scans |

### Findings

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/projects/:projectId/findings` | List findings |
| POST | `/api/projects/:projectId/findings` | Create manual finding |
| GET | `/api/findings/:id` | Get finding |
| PATCH | `/api/findings/:id` | Update finding |
| DELETE | `/api/findings/:id` | Delete finding |

### Dashboard

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/dashboard/stats` | Summary counts |
| GET | `/api/dashboard/activity` | Recent activity feed |
| GET | `/api/dashboard/severity-breakdown` | Open finding severity counts |

---

## Security Notes

- **Auth header encryption**: Scan auth headers are encrypted with AES-256-GCM using a SHA-256 digest of `SESSION_SECRET` before being stored in the database — they are never stored in plain text.
- **Canary-based verification**: Active probes use bounded, harmless canary tokens — no real exploitation occurs unless the `lab` profile is selected intentionally.
- **WAF-aware**: When a WAF challenge is detected, active probes are suspended and remaining findings are downgraded to informational.
- **Rate limiting**: API is rate-limited to 300 req/min globally and 10 scan initiations/min per IP.
- **CORS**: In production, only Replit preview domains and `ALLOWED_ORIGINS` are accepted.

---

## Development

```bash
# Type-check all packages
pnpm typecheck

# Format scanner + dashboard code
pnpm format:check

# Push schema changes after editing packages/db/src/schema/
pnpm --filter @workspace/db push
```

### Regenerating the API client (after changing openapi.yaml)

```bash
cd packages/api-types && npx orval
cd packages/api-client && npx orval
```
