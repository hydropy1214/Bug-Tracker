# SentinelX

A security scanning platform with a React frontend and an Express API backend, organized as a pnpm monorepo.

## Architecture

| Layer | Location | Port |
|-------|----------|------|
| Web frontend (React + Vite) | `apps/web` | `$PORT` (Vite dev server) |
| API server (Express + TypeScript) | `apps/api` | `8080` (`API_PORT`) |
| Database package (Drizzle ORM + PostgreSQL) | `packages/db` | — |
| Shared types / API spec | `packages/api-types`, `packages/api-spec` | — |

## Running the project

Two workflows run automatically:

- **apps/web: web** — `pnpm --filter @workspace/web run dev`
- **apps/api: API Server** — `pnpm --filter @workspace/api run dev` (builds via `esbuild` then starts)

## Environment variables

| Variable | Where set | Purpose |
|----------|-----------|---------|
| `DATABASE_URL` | Replit DB (auto) | PostgreSQL connection string |
| `SESSION_SECRET` | Replit Secrets | AES-256-GCM key for scan header encryption |
| `API_PORT` | `.env` / workflow | API listen port (default `8080`) |

## Database migrations

```bash
cd packages/db && pnpm run push       # apply schema
cd packages/db && pnpm run push-force # force-apply (destructive)
```

## User preferences

- Keep existing monorepo structure — do not restructure or migrate.
