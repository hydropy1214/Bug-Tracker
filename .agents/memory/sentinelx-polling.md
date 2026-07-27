---
name: SentinelX polling reliability
description: Live scan polling must keep its callback identities stable to avoid duplicate timers.
---

Live scan polling callbacks should be memoized before they are passed into the polling hook; otherwise a render can retrigger scan restoration and create duplicate timers that flood the status endpoint.

**Why:** A transient UI state update during an active scan previously caused many simultaneous status requests instead of one controlled polling loop.

**How to apply:** Keep polling lifecycle callbacks stable with `useCallback`, and surface sustained retry failures without stopping the scan automatically.