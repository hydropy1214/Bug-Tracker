# SentinelX — Replit Project Notes

## Project Overview

SentinelX is a professional self-hosted web vulnerability scanner.
It runs real system tools (nmap, dig, whois, openssl) and performs
28 scanning phases: WAF bypass, subdomain takeover, blind SQLi,
JWT cracking, Log4Shell, CRLF injection, path traversal, SSTI,
XXE, SSRF, open registration exploitation, default credential
brute-force, SQL injection auth bypass, enhanced command injection
with file-read canary, and IDOR with captured session.
Every finding uses baseline comparison or canary tokens — no false positives.

**Full documentation: see `README.md`**

---

## Architecture

```
apps/web/              ← React 19 frontend (Vite + Tailwind v4)
apps/api/              ← Express 5 backend + background scan worker
packages/db/           ← Drizzle ORM + PostgreSQL schema
packages/api-spec/     ← OpenAPI 3.1 spec
packages/api-types/    ← Generated Zod schemas (from spec)
packages/api-client/   ← Generated React Query hooks (from spec)
```

---

## Replit-Specific Setup

### Workflows (auto-start)

- **`apps/web: web`** — `pnpm --filter @workspace/web run dev`
- **`apps/api: API Server`** — `pnpm --filter @workspace/api run dev`

### Secrets Required

| Secret | Purpose |
|--------|---------|
| `SESSION_SECRET` | AES-256-GCM encryption of stored auth tokens |

Set via: Replit sidebar → Secrets (lock icon) → Add secret.

### Database

PostgreSQL is provisioned automatically by Replit. `DATABASE_URL` is injected
into the environment. To push schema changes:

```bash
pnpm --filter @workspace/db run push
```

### System Tools

All required tools are available in the Replit Nix environment:
`nmap`, `dig`, `whois`, `openssl`

---

## Development Commands

```bash
# Install all workspace dependencies
pnpm install

# Push DB schema (run after first install or schema changes)
pnpm --filter @workspace/db run push

# Start API server
pnpm --filter @workspace/api run dev

# Start frontend
pnpm --filter @workspace/web run dev

# Type check all packages
pnpm run typecheck

# Build all packages
pnpm run build

# Drizzle Studio (database GUI)
pnpm --filter @workspace/db run studio
```

---

## User Preferences

- Scanner always runs `scanType: "full"` + `profile: "deep_authorized"` — no UI selectors
- Every finding must use baseline comparison, canary tokens, or confirmed content markers
- `"suspected"` verification for signals; `"verified"` only for confirmed findings
- No false positives: if uncertain, report as suspected with < 80% confidence
- Dark theme throughout
- Monospace / terminal aesthetic for scan output

---

## Key Environment Variables

| Variable | Source | Required |
|----------|--------|----------|
| `DATABASE_URL` | Replit PostgreSQL integration | ✅ |
| `SESSION_SECRET` | Replit Secret | ✅ |
| `PORT` | Replit workflow | auto |
| `NODE_ENV` | Replit | auto |
| `REPL_ID` | Replit | auto |

---

## Legal Notice

SentinelX is for authorised security testing only.
Only scan systems you own or have explicit written permission to test.
