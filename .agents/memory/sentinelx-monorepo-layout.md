---
name: SentinelX monorepo layout
description: The production folder layout and Replit artifact metadata constraint for SentinelX.
---

SentinelX uses `apps/api` and `apps/web` for runnable services, with shared libraries under `packages/`. Replit artifact IDs remain stable when directories move, and artifact manifests must be updated through the validated replacement flow rather than edited in place.

**Why:** The platform registers artifacts independently from their filesystem paths; direct manifest edits are rejected and stale paths can break managed workflows or production asset lookup.

**How to apply:** Keep workspace globs, package names, TypeScript references, generated-code destinations, and artifact build paths aligned whenever the monorepo is reorganized. Use the artifact validation flow for any `.replit-artifact/artifact.toml` change.