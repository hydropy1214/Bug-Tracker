# SentinelX

A security vulnerability management and scanning platform for DevSecOps teams. Manage projects (targets), track assets (domains, IPs, APIs), record findings with CVSS/CVE data, and launch simulated security scans.

## Run & Operate

- `pnpm --filter @workspace/sentinelx run dev` — run the frontend (Vite, port from `PORT`)
- `pnpm --filter @workspace/api-server run dev` — run the API server (builds then starts, port from `PORT`)
- `pnpm run typecheck` — full typecheck across all packages
- `pnpm run build` — typecheck + build all packages
- `pnpm --filter @workspace/api-spec run codegen` — regenerate API hooks and Zod schemas from OpenAPI spec
- `pnpm --filter @workspace/db run push` — push DB schema to dev database (run after schema changes)

## Stack

- pnpm workspaces, Node.js 24, TypeScript 5.9
- **Frontend:** React 19, Vite 7, TailwindCSS 4, shadcn/ui, Recharts, Framer Motion, wouter (routing), TanStack Query
- **API:** Express 5, built with esbuild to CJS
- **DB:** PostgreSQL (Replit managed) + Drizzle ORM
- **Validation:** Zod v4, drizzle-zod
- **API codegen:** Orval (from OpenAPI spec in `lib/api-spec/openapi.yaml`)

## Where things live

| Path | Purpose |
|---|---|
| `artifacts/sentinelx/` | React/Vite frontend |
| `artifacts/api-server/` | Express 5 API server |
| `lib/db/src/schema/` | Drizzle schema (source of truth for DB) |
| `lib/api-spec/openapi.yaml` | OpenAPI spec (source of truth for API contract) |
| `lib/api-client-react/src/generated/` | Auto-generated React hooks (from Orval codegen) |
| `lib/api-zod/src/generated/` | Auto-generated Zod validators (from Orval codegen) |

## Architecture decisions

- **OpenAPI-first:** The spec in `lib/api-spec/openapi.yaml` drives both the React query hooks (`lib/api-client-react`) and the Zod request validators (`lib/api-zod`). Run codegen after changing the spec.
- **Scan worker in-process:** `artifacts/api-server/src/lib/scan-worker.ts` runs as a `setInterval` loop inside the API server process. It picks up pending scans, ticks progress every 4 s, and surfaces simulated findings for `vulnerability`/`full` scan types. In production this should move to a dedicated worker process or queue.
- **No auth:** The app is currently single-tenant with no authentication. All data is shared.

## Product

- **Dashboard:** Stats overview, severity breakdown pie chart, recent activity feed
- **Projects:** Create/edit/delete security projects with scope definitions and status
- **Assets:** Track domains, IPs, API endpoints, and wildcard scopes per project with technology tags
- **Findings:** Record vulnerabilities with severity, CVSS, CVE, evidence, and remediation notes
- **Scans:** Launch recon/enumeration/vulnerability/full scans; progress updates live; vulnerability/full scans auto-surface findings

## User preferences

_Populate as you build — explicit user instructions worth remembering across sessions._

## Gotchas

- **Codegen:** After editing `lib/api-spec/openapi.yaml`, always run `pnpm --filter @workspace/api-spec run codegen` followed by `pnpm run typecheck:libs` to regenerate hooks and validators.
- **Schema changes:** After editing Drizzle schema files in `lib/db/src/schema/`, run `pnpm --filter @workspace/db run push` to apply to the dev database.
- **`DATABASE_URL` is runtime-managed** by Replit — do not set it manually.

## Pointers

- See the `pnpm-workspace` skill for workspace structure, TypeScript setup, and package details
