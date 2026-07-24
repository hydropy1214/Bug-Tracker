---
name: SentinelX refactor boundaries
description: Compatibility-first scanner extraction, cancellation semantics, and generated API contract rules.
---

The scanner refactor is intentionally compatibility-first: the public scanner facade and phase modules can migrate individual phases without changing the legacy orchestrator’s routes or finding behavior.

**Why:** The live scanner contains more phases than the original brief describes, and moving the full implementation at once would risk scan lifecycle and recovery regressions.

**How to apply:** Add new phase logic behind the facade, preserve existing exports until all consumers migrate, and keep WAF state asset-scoped.

Scan cancellation is a terminal `canceled` status. Pending scans transition immediately; running scans set a database cancellation request that the worker checks before writes and before completion.

**Why:** A UI-only stop flag could allow a worker to mark a user-stopped scan completed after the final probe.

**How to apply:** Any future worker completion path must use a cancellation-aware conditional update and treat a failed completion update as cancellation.