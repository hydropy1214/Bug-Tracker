---
name: SentinelX preview routing
description: How the Replit proxy routes the web app vs API, and fixes applied to prevent "Cannot GET /" in the preview pane.
---

# SentinelX Preview Routing

## Rule
The Replit proxy routes by artifact `localPort` + `paths`. Web artifact owns `/` → port 5173 (Vite). API artifact owns `/api` → port 8080 (Express).

**Why:** The shared `PORT` env var (5173) must stay exclusively owned by the web app. If the API workflow also advertises PORT=8080, the proxy can get confused and route `/` to the API, showing "Cannot GET /" in the preview.

## How to apply
- API server reads `process.env.API_PORT ?? process.env.PORT` — `API_PORT=8080` is in shared env so it takes precedence in dev.
- API workflow must NOT set `PORT=8080` inline (the artifact system injects it from `localPort` anyway).
- `app.ts` has a root `GET /` handler returning `{"service":"SentinelX API","status":"ok"}` so Replit's health probe returns 200 instead of "Cannot GET /".

## Port map
| Service | Port | Artifact path |
|---------|------|---------------|
| Vite (web) | 5173 | `apps/web` |
| Express (API) | 8080 | `apps/api` |

## DB fix applied
`dashboard/recent-findings` used `ANY(${array}::text[])` which Drizzle sent as a PostgreSQL record tuple. Fixed by using `inArray(findingsTable.severity, severityFilter)` from drizzle-orm.
