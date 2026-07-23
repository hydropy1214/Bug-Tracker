---
name: SentinelX scan recovery
description: Durable scan restart, browser rehydration, and monotonic progress behavior
---

## Rule

Scan records left in `running` state must be re-queued on API startup, while the browser keeps the active scan ID and target in local storage until the scan reaches a terminal state. Progress writes must be monotonic because scanner log callbacks can complete out of order during parallel phases.

**Why:** Browser refreshes and API restarts are expected interruptions, and concurrent probe/log activity can otherwise make a healthy scan appear stuck or move backward.

**How to apply:** Preserve the database-backed scan ID/status as the source of truth, prevent duplicate worker pickup, clear browser state on completed/failed/missing scans, and use a database-side maximum when updating progress.