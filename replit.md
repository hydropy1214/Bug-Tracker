# SentinelX

Enterprise Bug Bounty & Attack Surface Management Platform. Provides project management, asset discovery (domains, IPs, API endpoints), security scanning with real-time updates, and AI-assisted analysis.

## Stack

- **Frontend:** React 19, Vite, Tailwind CSS, shadcn/ui, TanStack Query, Wouter
- **Backend:** Node.js + Express (TypeScript), built with esbuild
- **Database:** PostgreSQL via Drizzle ORM
- **Shared libs:** `lib/db` (schema), `lib/api-spec` (OpenAPI), `lib/api-zod` (Zod types), `lib/api-client-react` (generated React hooks)

## How to run

All services start automatically via configured workflows:

| Workflow | Command | Purpose |
|---|---|---|
| `artifacts/sentinelx: web` | `pnpm --filter @workspace/sentinelx run dev` | React frontend (Vite) |
| `artifacts/api-server: API Server` | `pnpm --filter @workspace/api-server run dev` | Express API + scan worker |

## Environment

- `DATABASE_URL` — Replit-managed PostgreSQL (set automatically, no action needed)
- All other env vars are runtime-managed by Replit

## Schema

Push schema changes to the DB with:
```
pnpm --filter @workspace/db run push
```

## User preferences
