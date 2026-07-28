---
name: SentinelX Replit preview
description: Root cause of the routing bug, the permanent fix, and how to verify the app is healthy.
---

## Root cause (confirmed 2026-07-28)

The project uses `apps/api` and `apps/web` (non-standard layout — no `artifacts/` dir).  
When `.replit` has **manual** `[[workflows.workflow]]` entries with the same names as artifact-managed workflows (`apps/web: web`, `apps/api: API Server`), the manual entries **override** the artifact-managed ones.  
Artifact-managed workflows inject proxy routing metadata (which path each port owns). Manual ones do not.  
Without that injection the Replit proxy routes **all** traffic to whichever port opens first — typically 8080 (the API, which builds and starts faster than Vite). The user sees the API server instead of the React dashboard.

## Permanent fix applied

1. **Removed** the manual `apps/web: web` and `apps/api: API Server` workflow definitions from `.replit`. Only the `Project` orchestrator workflow remains; it calls `workflow.run` to trigger the artifact-managed sub-workflows (same names, now owned by the artifact system).
2. **Fixed** the API's `GET /` handler — it was returning `<meta http-equiv="refresh" content="0; url=/">`, causing an infinite redirect loop whenever the proxy accidentally routed root to port 8080. Changed to `res.json({ service: "sentinelx-api", health: "/api/healthz" })`.

**Rule: NEVER add manual `[[workflows.workflow]]` definitions for `apps/web: web` or `apps/api: API Server` to `.replit`. The artifact system owns those workflow names.**

## How to verify the app is healthy

1. `curl -s "https://$REPLIT_DEV_DOMAIN/"` → should return Vite HTML (`<!DOCTYPE html>` …)
2. `curl -s "https://$REPLIT_DEV_DOMAIN/api/healthz"` → `{"status":"ok"}`
3. API logs should show `/api/dashboard/*` and `/api/scans` requests (from browser) — **not** a flood of `GET /`
4. Browser console: `[vite] connected`

## Screenshot tool note

`localhost:80` is always connection-refused from within the container (proxy is external infrastructure). The screenshot tool always fails for this layout. Verify health via curl + API logs instead.
