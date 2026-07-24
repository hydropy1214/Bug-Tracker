/**
 * Scan Worker
 *
 * Picks up pending scans and runs the real HTTP security scanner against
 * each asset in the project. Progress is updated live as each check phase
 * completes. Findings are written to the database as they are detected.
 */

import { and, eq, sql } from "drizzle-orm";
import {
  db,
  scansTable,
  activityTable,
  findingsTable,
  assetsTable,
  projectsTable,
} from "@workspace/db";
import { discoverToolCapabilities, resolveScanPolicy, scanTarget, type ScanType } from "./scanner/index";
import { decryptAuthHeaders } from "./encryption";
import { logger } from "./logger";

const TICK_MS = 2_000; // keep the queue responsive without busy-polling the database
const SCANNER_PHASE_COUNT = 24;

class ScanCanceledError extends Error {
  constructor() {
    super("Scan canceled by user");
    this.name = "ScanCanceledError";
  }
}

// Track scans currently being processed to avoid double-pickup
const activeScans = new Set<number>();

// ─── Progress phases per scan type ────────────────────────────────────────────
// These mirror the real scanner phases so the log/progress stays in sync with
// what the scanner is actually doing.

const PHASE_LABELS: Record<string, string[]> = {
  recon: [
    "Probing target reachability...",
    "Checking HTTP security headers...",
    "Inspecting SSL/TLS certificate...",
    "Finalising recon report...",
  ],
  enumeration: [
    "Probing target reachability...",
    "Checking HTTP security headers...",
    "Scanning for exposed sensitive paths...",
    "Finalising enumeration report...",
  ],
  vulnerability: [
    "Probing target reachability...",
    "Checking HTTP security headers...",
    "Inspecting SSL/TLS certificate...",
    "Scanning for exposed sensitive paths (deep)...",
    "Testing CORS policy...",
    "Checking cookie security attributes...",
    "Testing HTTP TRACE method...",
    "Checking HTTPS enforcement...",
    "Compiling vulnerability report...",
  ],
  full: [
    "Probing target reachability...",
    "Checking HTTP security headers...",
    "Inspecting SSL/TLS certificate...",
    "Scanning for exposed sensitive paths (deep)...",
    "Testing CORS policy...",
    "Checking cookie security attributes...",
    "Testing HTTP TRACE method...",
    "Checking HTTPS enforcement...",
    "Analysing attack surface...",
    "Compiling full scan report...",
  ],
};

// ─── Helpers ──────────────────────────────────────────────────────────────────

async function appendLog(scanId: number, line: string): Promise<void> {
  await db
    .update(scansTable)
    .set({ logs: sql`COALESCE(${scansTable.logs}, '') || ${line + "\n"}` })
    .where(eq(scansTable.id, scanId));
}

async function setProgress(scanId: number, progress: number): Promise<void> {
  await db
    .update(scansTable)
    .set({
      progress: sql`GREATEST(COALESCE(${scansTable.progress}, 0), ${Math.min(progress, 100)})`,
    })
    .where(eq(scansTable.id, scanId));
}

async function throwIfCanceled(scanId: number): Promise<void> {
  const [scan] = await db
    .select({ status: scansTable.status, cancelRequested: scansTable.cancelRequested })
    .from(scansTable)
    .where(eq(scansTable.id, scanId));
  if (scan?.status === "canceled" || scan?.cancelRequested) {
    throw new ScanCanceledError();
  }
}

// ─── Core scan processor ──────────────────────────────────────────────────────

async function processScan(scan: typeof scansTable.$inferSelect): Promise<void> {
  await throwIfCanceled(scan.id);
  const log = async (msg: string) => {
    await throwIfCanceled(scan.id);
    await appendLog(scan.id, msg);
  };

  logger.info({ scanId: scan.id, type: scan.type }, "Scan started");
  const policy = resolveScanPolicy(scan.profile);
  const capabilities = await discoverToolCapabilities();
  const capabilityJson = JSON.stringify(capabilities);
  const wasInterrupted = Boolean(scan.startedAt);

  if (wasInterrupted) {
    await db.delete(findingsTable).where(eq(findingsTable.scanId, scan.id));
    await appendLog(scan.id, `[${new Date().toISOString()}] Previous worker stopped during this scan; restarting safely from the beginning.`);
  }

  // Mark running
  await db
    .update(scansTable)
    .set({
      status: "running",
      progress: 0,
      startedAt: new Date(),
      logs: wasInterrupted
        ? sql`COALESCE(${scansTable.logs}, '')`
        : "",
      wafBlocked: false,
      findingsCount: 0,
      policy: JSON.stringify(policy),
      toolCapabilities: capabilityJson,
    })
    .where(and(eq(scansTable.id, scan.id), eq(scansTable.status, "pending")));

  await throwIfCanceled(scan.id);

  // Load assets for this project
  const assets = await db
    .select()
    .from(assetsTable)
    .where(eq(assetsTable.projectId, scan.projectId));

  const phases = PHASE_LABELS[scan.type] ?? PHASE_LABELS.vulnerability;
  const totalPhases = phases.length;
  let currentPhase = 0;

  const advancePhase = async (label?: string) => {
    currentPhase++;
    const progress = Math.round((currentPhase / totalPhases) * 95); // reserve last 5% for DB writes
    await setProgress(scan.id, progress);
    if (label) await log(`[${new Date().toISOString()}] ${label}`);
  };

  await log(`[${new Date().toISOString()}] Scan initialised — type: ${scan.type}, profile: ${policy.profile}, assets: ${assets.length}`);
  await log(`[${new Date().toISOString()}] Policy: ${policy.requestBudget} request budget · ${policy.verificationRequestBudget} verification request cap · ${policy.timeoutMs}ms timeout · ${policy.maxConcurrency} concurrency`);
  await log(`[${new Date().toISOString()}] Tools available: ${capabilities.filter((tool) => tool.available).map((tool) => `${tool.name}${tool.version ? ` (${tool.version})` : ""}`).join(", ") || "built-in HTTP only"}`);
  await log(`[${new Date().toISOString()}] Tools unavailable: ${capabilities.filter((tool) => !tool.available).map((tool) => tool.name).join(", ") || "none"}`);

  if (assets.length === 0) {
    await log(`[${new Date().toISOString()}] No assets found for this project. Add assets (domains, IPs, API endpoints) to enable scanning.`);
    await throwIfCanceled(scan.id);
    await db
      .update(scansTable)
      .set({ status: "completed", progress: 100, completedAt: new Date(), findingsCount: 0 })
      .where(and(eq(scansTable.id, scan.id), eq(scansTable.cancelRequested, false)));
    activeScans.delete(scan.id);
    return;
  }

  // ── Run real scanner against each asset ──────────────────────────────────
  let totalFindingsAdded = 0;
  let wafBlocked = false;
  const seenTitles = new Set<string>(); // deduplicate same finding across assets

  for (const asset of assets) {
    await throwIfCanceled(scan.id);
    await log(`[${new Date().toISOString()}] Scanning asset: ${asset.value} (${asset.type})`);

    // Decrypt auth headers if the scan has an auth context stored
    let authHeaders: Record<string, string> | undefined;
    if (scan.authContext) {
      try {
        authHeaders = decryptAuthHeaders(scan.authContext);
        await log(`[${new Date().toISOString()}] Authenticated scanning: decrypted auth context (${Object.keys(authHeaders).length} header(s))`);
      } catch {
        await log(`[${new Date().toISOString()}] Warning: failed to decrypt authContext — scanning unauthenticated`);
      }
    }

    // Wire the scanner's log output into the scan's log stream
    const scanResult = await scanTarget(
      asset.value,
      asset.type,
      scan.type as ScanType,
      async (msg) => {
        await throwIfCanceled(scan.id);
        await log(msg);
        // Scanner logs carry the authoritative phase number. Use it for
        // progress so long-running phases (notably nmap) do not look frozen.
        const phaseMatch = msg.match(/\[Phase\s+(\d+)(?:[a-z])?\]/i);
        if (phaseMatch) {
          const scannerPhase = Number.parseInt(phaseMatch[1]!, 10);
          if (Number.isFinite(scannerPhase)) {
            currentPhase = Math.max(currentPhase, Math.min(scannerPhase, SCANNER_PHASE_COUNT));
            await setProgress(
              scan.id,
              Math.max(1, Math.min(94, Math.round((currentPhase / SCANNER_PHASE_COUNT) * 95))),
            );
            return;
          }
        }

        // Keep a small amount of movement inside the current phase without
        // regressing when multiple log lines arrive out of order.
        const phaseIdx = Math.min(currentPhase, totalPhases - 2);
        const subProgress = Math.round(((phaseIdx + 0.5) / totalPhases) * 95);
        await setProgress(scan.id, Math.max(1, subProgress));
      },
      policy,
      authHeaders,
    );
    const assetFindings = scanResult.findings;
    wafBlocked ||= scanResult.wafBlocked;
    if (scanResult.wafBlocked) {
      await db
        .update(scansTable)
        .set({ wafBlocked: true })
        .where(eq(scansTable.id, scan.id));
    }

    // Insert real findings (deduplicate by title across assets)
    for (const finding of assetFindings) {
      const dedupeKey = `${finding.title}::${asset.id}`;
      if (seenTitles.has(dedupeKey)) continue;
      seenTitles.add(dedupeKey);

      await db.insert(findingsTable).values({
        projectId: scan.projectId,
        scanId: scan.id,
        assetId: asset.id,
        title: finding.title,
        description: finding.description,
        severity: finding.severity,
        verification: finding.verification ?? "verified",
        // `verified` is reserved for direct evidence from bounded Phase 24
        // verification; legacy scanner metadata must not imply canary proof.
        verified: finding.verified ?? false,
        confidence: Math.max(0, Math.min(100, Math.round(finding.confidence ?? 80))),
        evidenceQuality: finding.evidenceQuality ?? "standard",
        verificationMethod: finding.verificationMethod ?? null,
        reproducibility: finding.reproducibility ?? "not_tested",
        affectedEndpoint: finding.affectedEndpoint ?? null,
        affectedParameter: finding.affectedParameter ?? null,
        negativeTests: finding.negativeTests ?? null,
        limitations: finding.limitations ?? null,
        toolInfo: finding.toolInfo ?? capabilityJson,
        status: "open",
        cvss: finding.cvss,
        cve: finding.cve ?? null,
        remediation: finding.remediation,
        evidence: finding.evidence,
      });
      totalFindingsAdded++;
    }

    // Advance progress after each asset
    currentPhase = Math.min(currentPhase + 1, totalPhases - 1);
    await setProgress(scan.id, Math.round((currentPhase / totalPhases) * 95));
  }

  // ── Completion ────────────────────────────────────────────────────────────
  await throwIfCanceled(scan.id);
  await log(`[${new Date().toISOString()}] Scan complete — ${totalFindingsAdded} finding(s) recorded.`);
  await setProgress(scan.id, 100);

  const [completedScan] = await db
    .update(scansTable)
    .set({
      status: "completed",
      progress: 100,
      completedAt: new Date(),
      findingsCount: totalFindingsAdded,
      wafBlocked,
    })
    .where(and(eq(scansTable.id, scan.id), eq(scansTable.cancelRequested, false)))
    .returning({ id: scansTable.id });
  if (!completedScan) throw new ScanCanceledError();

  // Log activity
  const [project] = await db
    .select({ name: projectsTable.name })
    .from(projectsTable)
    .where(eq(projectsTable.id, scan.projectId));

  await db.insert(activityTable).values({
    type: "scan_completed",
    title: `Scan completed: ${scan.name}`,
    description: `${scan.type} scan finished for ${project?.name ?? "project"}${totalFindingsAdded > 0 ? ` — ${totalFindingsAdded} finding(s) discovered` : " — no issues found"}`,
    severity: totalFindingsAdded > 0 ? "medium" : null,
    projectId: scan.projectId,
    projectName: project?.name ?? null,
  });

  logger.info({ scanId: scan.id, findingsAdded: totalFindingsAdded }, "Scan completed");
}

// ─── Worker loop ──────────────────────────────────────────────────────────────

async function pickUpPendingScans(): Promise<void> {
  const pending = await db
    .select()
    .from(scansTable)
    .where(eq(scansTable.status, "pending"))
    .limit(5);

  for (const scan of pending) {
    if (activeScans.has(scan.id)) continue;
    activeScans.add(scan.id);

    // Run each scan as a detached async task so the worker loop stays free
    processScan(scan)
      .catch((err) => {
        if (err instanceof ScanCanceledError) {
          db.update(scansTable)
            .set({
              status: "canceled",
              cancelRequested: false,
              completedAt: new Date(),
              logs: sql`COALESCE(${scansTable.logs}, '') || ${`[${new Date().toISOString()}] Scan canceled by user.\n`}`,
            })
            .where(eq(scansTable.id, scan.id))
            .catch(() => {});
          return;
        }
        logger.error({ scanId: scan.id, err }, "Scan failed");
        // Mark the scan as failed so the dashboard can explain what happened
        db.update(scansTable)
          .set({
            status: "failed",
            cancelRequested: false,
            completedAt: new Date(),
            logs: sql`COALESCE(${scansTable.logs}, '') || ${`[${new Date().toISOString()}] Scan failed: ${err?.message ?? String(err)}\n`}`,
          })
          .where(eq(scansTable.id, scan.id))
          .catch(() => {});
      })
      .finally(() => {
        activeScans.delete(scan.id);
      });
  }
}

async function recoverInterruptedScans(): Promise<void> {
  const interrupted = await db
    .select({ id: scansTable.id })
    .from(scansTable)
    .where(eq(scansTable.status, "running"));

  for (const scan of interrupted) {
    await db.delete(findingsTable).where(eq(findingsTable.scanId, scan.id));
    await db
      .update(scansTable)
      .set({
        status: "pending",
        progress: 0,
        completedAt: null,
        wafBlocked: false,
        cancelRequested: false,
        logs: sql`COALESCE(${scansTable.logs}, '') || ${`[${new Date().toISOString()}] API worker restarted; scan queued for safe recovery.\n`}`,
      })
      .where(eq(scansTable.id, scan.id));
    logger.warn({ scanId: scan.id }, "Recovered interrupted scan");
  }
}

export function startScanWorker(): void {
  logger.info("Scan worker started (real HTTP scanner active)");
  let ready = false;
  void recoverInterruptedScans()
    .then(() => {
      ready = true;
      return pickUpPendingScans();
    })
    .catch((err) => logger.error({ err }, "Scan recovery failed"));

  setInterval(() => {
    if (!ready) return;
    pickUpPendingScans().catch((err) =>
      logger.error({ err }, "Scan worker loop error"),
    );
  }, TICK_MS);
}
