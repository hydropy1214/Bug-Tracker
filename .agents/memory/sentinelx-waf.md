---
name: SentinelX WAF challenge handling
description: Durable scanner behavior when a target serves a WAF challenge response
---

WAF challenge state must remain scoped to the current asset scan. A detected challenge suspends active probes while passive and informational checks continue; SSTI and NoSQL findings are suppressed, and other challenge-tainted findings are downgraded to informational with low confidence and an explicit false-positive limitation.

**Why:** Challenge pages commonly contain dynamic hexadecimal identifiers and reflected input, which can create false positives and make further active requests inappropriate.

**How to apply:** Keep detection at every HTTP probe boundary, emit the suspension warning once per asset, and carry the result through scanner output, persistence, API reports, and the dashboard.