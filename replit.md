# SentinelX

A professional vulnerability scanning and management platform with a dark cyber-themed UI.

## Stack

- **Frontend**: React 19, Vite, Wouter, Tailwind CSS v4, shadcn/ui, TanStack Query, Framer Motion — `artifacts/sentinelx/`
- **Backend**: Express 5 (Node.js) with a background scan worker — `artifacts/api-server/`
- **Database**: PostgreSQL (Replit managed) with Drizzle ORM — `lib/db/`
- **API spec**: OpenAPI 3.1 in `lib/api-spec/openapi.yaml`; generated clients in `lib/api-client-react/` and `lib/api-zod/`
- **Monorepo**: pnpm workspaces

## How to Run

Workflows are pre-configured — the app starts automatically.

| Service | Workflow name |
|---------|---------------|
| Web app | `artifacts/sentinelx: web` |
| API server | `artifacts/api-server: API Server` |
| Mockup sandbox | `artifacts/mockup-sandbox: Component Preview Server` |

## Manual Commands

```bash
# Install dependencies
pnpm install

# Push database schema
pnpm --filter @workspace/db run push

# Regenerate API clients after changing openapi.yaml
pnpm --filter @workspace/api-spec run generate
```

## Scanner

The API server uses real system tools (`nmap`, `dig`, `whois`, `openssl`) plus external APIs (crt.sh, ipinfo.io, Wayback Machine) for security analysis. These are available in the Replit environment via `replit.nix`.

## Environment

- `DATABASE_URL` — managed automatically by Replit (do not set manually)
- `SESSION_SECRET` — set as a Replit Secret

## User Preferences

<!-- Add any remembered preferences here -->
