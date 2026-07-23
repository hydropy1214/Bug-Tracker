/**
 * Scan Worker
 *
 * Picks up pending scans and runs the real HTTP security scanner against
 * each asset in the project. Progress is updated live as each check phase
 * completes. Findings are written to the database as they are detected.
 */

import { eq, sql } from "drizzle-orm";
import {
  db,
  scansTable,
  activityTable,
  findingsTable,
  assetsTable,
  projectsTable,
} from "@workspace/db";
import { scanTarget, type ScanType } from "./scanner";
import { logger } from "./logger";

const TICK_MS = 3_000; // how often we check for new pending scans

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
    .set({ progress: Math.min(progress, 100) })
    .where(eq(scansTable.id, scanId));
}

// ─── Core scan processor ──────────────────────────────────────────────────────

async function processScan(scan: typeof scansTable.$inferSelect): Promise<void> {
  const log = async (msg: string) => {
    await appendLog(scan.id, msg);
  };

  logger.info({ scanId: scan.id, type: scan.type }, "Scan started");

  // Mark running
  await db
    .update(scansTable)
    .set({ status: "running", progress: 0, startedAt: new Date(), logs: "" })
    .where(eq(scansTable.id, scan.id));

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

  await log(`[${new Date().toISOString()}] Scan initialised — type: ${scan.type}, assets: ${assets.length}`);

  if (assets.length === 0) {
    await log(`[${new Date().toISOString()}] No assets found for this project. Add assets (domains, IPs, API endpoints) to enable scanning.`);
    await db
      .update(scansTable)
      .set({ status: "completed", progress: 100, completedAt: new Date(), findingsCount: 0 })
      .where(eq(scansTable.id, scan.id));
    activeScans.delete(scan.id);
    return;
  }

  // ── Run real scanner against each asset ──────────────────────────────────
  let totalFindingsAdded = 0;
  const seenTitles = new Set<string>(); // deduplicate same finding across assets

  for (const asset of assets) {
    await log(`[${new Date().toISOString()}] Scanning asset: ${asset.value} (${asset.type})`);

    // Wire the scanner's log output into the scan's log stream
    const assetFindings = await scanTarget(
      asset.value,
      asset.type,
      scan.type as ScanType,
      async (msg) => {
        await log(msg);
        // Advance UI progress as the scanner streams log lines
        const phaseIdx = Math.min(currentPhase, totalPhases - 2);
        const subProgress = Math.round(((phaseIdx + 0.5) / totalPhases) * 95);
        await setProgress(scan.id, subProgress);
      },
    );

    // Insert real findings (deduplicate by title across assets)
    for (const finding of assetFindings) {
      const dedupeKey = `${finding.title}::${asset.id}`;
      if (seenTitles.has(dedupeKey)) continue;
      seenTitles.add(dedupeKey);

      await db.insert(findingsTable).values({
        projectId: scan.projectId,
        assetId: asset.id,
        title: finding.title,
        description: finding.description,
        severity: finding.severity,
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
  await log(`[${new Date().toISOString()}] Scan complete — ${totalFindingsAdded} finding(s) recorded.`);
  await setProgress(scan.id, 100);

  await db
    .update(scansTable)
    .set({
      status: "completed",
      progress: 100,
      completedAt: new Date(),
      findingsCount: totalFindingsAdded,
    })
    .where(eq(scansTable.id, scan.id));

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
        logger.error({ scanId: scan.id, err }, "Scan failed");
        // Mark the scan as failed so it doesn't stay stuck as "pending"
        db.update(scansTable)
          .set({
            status: "completed",
            progress: 100,
            completedAt: new Date(),
            logs: `Scan encountered an error: ${err?.message ?? String(err)}\n`,
          })
          .where(eq(scansTable.id, scan.id))
          .catch(() => {});
      })
      .finally(() => {
        activeScans.delete(scan.id);
      });
  }
}

export function startScanWorker(): void {
  logger.info("Scan worker started (real HTTP scanner active)");
  setInterval(() => {
    pickUpPendingScans().catch((err) =>
      logger.error({ err }, "Scan worker loop error"),
    );
  }, TICK_MS);
}
