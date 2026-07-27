# SentinelX — Replit Setup

## Project overview

SentinelX is a full-stack web security scanner. It runs 28-phase scans (DNS, ports, TLS, injection testing, CVE matching, JWT analysis, and more) against a target domain or IP and displays live results in a React dashboard.

**Stack:** React 19 + Vite 7 (frontend) · Express 5 + TypeScript (API) · PostgreSQL + Drizzle ORM (database) · pnpm workspace monorepo

## How to run

Two workflows are configured and start automatically:

| Workflow | Command | Description |
|----------|---------|-------------|
| `apps/web: web` | `pnpm --filter @workspace/web run dev` | Vite dev server (frontend) |
| `apps/api: API Server` | `pnpm --filter @workspace/api run dev` | Express API + scan worker |

The frontend proxies all `/api/*` requests to the API server via the Vite proxy (configured in `apps/web/vite.config.ts`).

## Required secrets / env vars

| Key | Type | Notes |
|-----|------|-------|
| `SESSION_SECRET` | Secret ✓ | Already set — used to encrypt scan auth headers (AES-256-GCM) |
| `DATABASE_URL` | Runtime-managed ✓ | Provisioned automatically — do not set manually |
| `API_PORT` | Shared env | Port the API binds to; must match so the Vite proxy can reach it |
| `NODE_ENV` | Shared env | Set to `development` (already configured) |

## First-time database setup

The database schema is pushed on first run via:

```bash
pnpm --filter @workspace/db push
```

This creates the tables: `projects`, `assets`, `endpoints`, `findings`, `scans`, `activity`.

## Key file locations

| Path | Purpose |
|------|---------|
| `apps/api/src/app.ts` | Express app — middleware (helmet, CORS, rate limiting) |
| `apps/api/src/routes/` | API route handlers |
| `apps/api/src/lib/scan-worker.ts` | Background scan queue processor |
| `apps/api/src/lib/scanner/orchestrator.ts` | 28-phase scan orchestrator |
| `apps/api/src/lib/scanner/phases/` | Individual scan phase modules |
| `apps/api/src/lib/auth-context.ts` | AES-256-GCM auth header encryption |
| `apps/web/src/pages/Dashboard.tsx` | Quick scan UI + live results |
| `apps/web/src/pages/Projects.tsx` | Project management |
| `apps/web/src/pages/Scans.tsx` | Global scan history |
| `packages/db/src/schema/` | Drizzle ORM table definitions |
| `packages/api-spec/openapi.yaml` | OpenAPI 3.1 contract |

## User preferences

- Keep the existing monorepo structure (`apps/`, `packages/`)
- Do not migrate the database away from Replit's managed PostgreSQL
- TypeScript strict mode is enabled — maintain it
- Pino for structured logging in the API (never `console.log` in server code)
