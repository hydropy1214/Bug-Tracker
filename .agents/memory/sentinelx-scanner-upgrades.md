---
name: SentinelX scanner upgrades
description: Phase count, key techniques, and design constraints for the SentinelX active scanner
---

# SentinelX Scanner Upgrades

## Current phase count: 28

Phases 1–23 were original. Phases 24–28 were added in the July 2026 upgrade session.

## New phases added (July 2026)

| Phase | Name | Location |
|-------|------|----------|
| 24 | Open Registration Exploitation | `scanner.ts` → `checkOpenRegistration()` |
| 25 | Default Credential Brute-Force | `scanner.ts` → `checkDefaultCredentials()` |
| 26 | SQL Injection Authentication Bypass | `scanner.ts` → `checkSqliAuthBypass()` |
| 27 | Enhanced Command Injection (canary + file-read) | `vuln-probes.ts` → `checkCommandInjectionDeep()` |
| 28 | IDOR with Captured Session | `scanner.ts` → `checkIdorWithCapturedSession()` |

## Key design rules

**Why:** Budget 8000 — don't exceed 50 requests for brute-force/registration total.

**capturedSession:** `ScanContext.capturedSession` (added to interface) stores the session cookie from the first of Phases 24/25/26 that succeeds. Phase 28 reads it via `getCapturedSession()`. `storeCapturedSession()` is first-write-wins.

**WAF gate:** All new phases call `activeProbesAllowed()` at entry — they return early if a WAF challenge has been detected. SSTI probe loop also explicitly skips parameters when baseline returns 429 or Cloudflare 403.

**Session masking:** Session cookies are masked as `first12chars****last4chars` in evidence strings before being stored in findings.

**Phase 27 exports:** `checkCommandInjectionDeep` is exported from `vuln-probes.ts` and imported dynamically in scanner.ts Phase 27 block (same pattern as Phase 22).

**SSTI WAF skip (July 2026):** Added explicit 429 / Cloudflare-403 check after baseline probe in `checkSSTI` — breaks the payload loop for that parameter.

## How to apply

- When adding a new active probe phase, always wrap the call in `runActiveChecks()` in the orchestrator.
- When a phase captures credentials/session, call `storeCapturedSession(cookie)` — Phase 28 will automatically pick it up.
- Phase 27's `SENTINELX_CMDI_CANARY` uses a runtime-random suffix so it cannot be filtered by static WAF rules.
