---
name: SentinelX Replit preview
description: Why localhost:80 is always refused, how the preview actually works, and how to verify the app is healthy.
---

The SentinelX project uses `apps/api` and `apps/web` (non-standard — artifacts/ dir doesn't exist). Replit's shared proxy at `localhost:80` is **external infrastructure that only starts for artifacts in `artifacts/`**. Since the layout is `apps/`, `curl localhost:80` always returns connection refused from within the container — this is expected and permanent.

**The preview IS working for the user** despite localhost:80 being unreachable from the shell. Verify health this way:
- `curl localhost:5173/` → returns HTML (Vite web app running on 0.0.0.0)
- `curl localhost:8080/api/healthz` → returns `{"status":"ok"}`
- Browser console logs showing `[vite] connected` confirm the user's preview is live
- `/proc/net/tcp` hex port 0x1435=5173 and 0x1F90=8080 should both show state 0A (LISTEN) on 0.0.0.0

**Screenshot tool always fails** (`ERR_CONNECTION_REFUSED at http://127.0.0.1:80/`) — this is a tooling limitation of the non-standard layout, not an application failure.

**Why:** The screenshot tool and the pnpm-workspace skill's "use localhost:80" guidance both assume artifacts live in `artifacts/`. The proxy that would listen at port 80 inside the container is not started because no `artifacts/` directory exists.

**How to apply:** When asked to verify the app visually or take screenshots, confirm ports are listening via /proc/net/tcp and check browser console logs instead of attempting screenshots. Report to the user that the preview works in their browser but screenshots via the tool are unavailable for this layout.

**Workflows:** Both `apps/web: web` (waitForPort=5173) and `apps/api: API Server` (waitForPort=8080) are in `.replit`. The `waitForPort` fields were added to both workflow tasks so Replit's runtime can signal readiness correctly.
