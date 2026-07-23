---
name: SentinelX scanner setup
description: Architecture of the scan engine, new endpoints, and advanced probe locations
---

## Key architecture

- **Quick scan flow**: `POST /api/quick-scan` → creates temp project + asset + scan record → scan worker picks it up within 3s → poll `GET /api/scans/:id/status` every 1.5s
- **Scan worker** polls `scansTable` for `status='pending'` every 3s and runs `scanTarget()` from `scanner.ts`
- **Phases 1–12** are in `scanner.ts`; **Phase 13** (SSTI, XXE, SSRF, Deserialization) and **Phase 14** (CVE NVD lookup) were added after Phase 12 in the `scanTarget` orchestrator

## New files
- `artifacts/api-server/src/lib/vuln-probes.ts` — SSTI, XXE, SSRF, Deserialization, CVE NVD lookup
- `artifacts/api-server/src/routes/quick-scan.ts` — POST /quick-scan endpoint

## Modified files
- `artifacts/api-server/src/routes/scans.ts` — added `GET /scans/:id/status` (returns scan + findings joined)
- `artifacts/api-server/src/routes/index.ts` — registers `quickScanRouter`
- `artifacts/api-server/src/lib/scanner.ts` — added Phase 13/14 at the end of `scanTarget()`

## Frontend (single-page scanner)
- `artifacts/sentinelx/src/pages/Dashboard.tsx` — complete redesign: URL input, scan type picker, live terminal, findings cards with expandable evidence
- `artifacts/sentinelx/src/components/layout/Shell.tsx` — removed Projects nav item
- `artifacts/sentinelx/src/App.tsx` — removed project/asset routes, only `/` and `/settings`

## Why
- User wanted single-URL entry point instead of multi-project management
- SSTI uses math evaluation ({{7*7}}→49) as safe, non-destructive proof of template execution
- CVE lookup uses NVD free API (rate-limited: ~700ms delay between calls, no key needed)
- Scanner already had SQLi, XSS, open redirect in `checkWebApp` (Phase 11); new probes are additive

## Caution
- NVD API has no-key rate limit of ~5 req/30s; the `lookupCvesForTechs` function adds 700ms delay per lookup
- Phase 13/14 only run for `vulnerability` and `full` scan types
- The `vuln-probes.ts` imports `Target` and `LogFn` types from `scanner.ts` — keep in sync if those types change
- The scan worker requires the managed PostgreSQL schema to be pushed before startup; an empty database causes repeated missing-table worker errors

## Evidence classification policy

- `verified` is reserved for direct, bounded evidence from the target, such as a file-content marker, metadata service response, XML file read, or a non-destructive command canary.
- `version_match` means an observed product/version falls within an NVD vulnerable CPE range; it is not exploit verification and must be described as correlation.
- `suspected` is used for heuristic signals that need analyst confirmation, including database error responses, reflected markup, deserialization text, and historical archive URLs.
- Baseline comparisons and content-specific markers are required where generic 200 responses, SPA shells, or custom 404 pages could create false positives.

**Why:** Security findings that overstate exploitability reduce trust and can cause incorrect remediation priorities.

**How to apply:** New probes must provide differentiated evidence and explicitly state what was not tested. Do not assign a CVE, RCE claim, or confirmed severity from product names, open ports, headers, or generic error text alone.

## Durable implementation constraints

- Cross-scan comparison must use stable target identity and finding location, not transient project, asset, or finding IDs. Quick scans intentionally create new records for each run.
- The repository's generated API validation uses Zod 3. OpenAPI response schemas must be concrete; empty `type: object` responses can generate Zod 4-only helpers and fail library typechecks.
