# SentinelX

A professional vulnerability scanning and management platform — a TypeScript pnpm monorepo with a dark cyber-themed UI.

## Architecture

- **`artifacts/sentinelx/`** — React 19 + Vite frontend (Wouter routing, Tailwind v4, shadcn/ui, TanStack Query, Framer Motion)
- **`artifacts/api-server/`** — Express 5 backend + background scan worker
- **`lib/db/`** — Drizzle ORM schema (PostgreSQL, runtime-managed `DATABASE_URL`)
- **`lib/api-spec/`** — OpenAPI spec (source of truth); `lib/api-zod/` and `lib/api-client-react/` are generated from it via orval
- **`lib/api-client-react/`** — Generated TanStack Query hooks used by the frontend

## How to Run

Dependencies are managed by pnpm workspaces. After cloning:

```bash
pnpm install
pnpm --filter @workspace/db run push   # apply schema to the database
```

Three workflows are configured (Replit manages them automatically):
- **API Server** — `pnpm --filter @workspace/api-server run dev`
- **SentinelX web** — `pnpm --filter @workspace/sentinelx run dev`

## Scanner

The backend runs real non-destructive security tools:
- `nmap` — TCP port scanning + service detection
- `dig` — DNS record enumeration (A, AAAA, MX, TXT, NS, SOA, CAA, AXFR)
- `whois` — Domain registration intel
- `openssl` / `tls` — TLS/SSL certificate inspection
- `fetch` — HTTP header analysis, CORS, cookies, redirect chains
- `crt.sh` — Certificate transparency for subdomain discovery
- `ipinfo.io` — IP geolocation and ASN
- Wayback Machine CDX API — historical endpoint discovery

Scans are queued to the database and picked up by a poll-based worker (`scan-worker.ts`). Progress and logs stream live to the frontend.

## Regenerating API Types

If you change `lib/api-spec/openapi.yaml`, regenerate the clients:

```bash
pnpm --filter @workspace/api-spec run generate
```

## User Preferences

- Keep the dark cyber/terminal aesthetic throughout
- Real tools only — no mock/simulated scanner output
