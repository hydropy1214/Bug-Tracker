import { Router, type IRouter } from "express";
import { eq, desc, and } from "drizzle-orm";
import { db, scansTable, activityTable, projectsTable, findingsTable, assetsTable } from "@workspace/db";
import { resolveScanPolicy } from "../lib/scanner";
import {
  ListScansParams,
  CreateScanParams,
  CreateScanBody,
  GetScanParams,
} from "@workspace/api-zod";

const router: IRouter = Router();

router.get("/projects/:projectId/scans", async (req, res): Promise<void> => {
  const raw = Array.isArray(req.params.projectId) ? req.params.projectId[0] : req.params.projectId;
  const params = ListScansParams.safeParse({ projectId: parseInt(raw, 10) });
  if (!params.success) {
    res.status(400).json({ error: params.error.message });
    return;
  }

  const scans = await db
    .select()
    .from(scansTable)
    .where(eq(scansTable.projectId, params.data.projectId))
    .orderBy(scansTable.createdAt);

  res.json(scans);
});

router.post("/projects/:projectId/scans", async (req, res): Promise<void> => {
  const rawProjectId = Array.isArray(req.params.projectId) ? req.params.projectId[0] : req.params.projectId;
  const params = CreateScanParams.safeParse({ projectId: parseInt(rawProjectId, 10) });
  if (!params.success) {
    res.status(400).json({ error: params.error.message });
    return;
  }

  const parsed = CreateScanBody.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: parsed.error.message });
    return;
  }

  const [scan] = await db
    .insert(scansTable)
    .values({
      projectId: params.data.projectId,
      name: parsed.data.name,
      type: parsed.data.type,
      profile: parsed.data.profile ?? "safe_active",
      policy: JSON.stringify(resolveScanPolicy(parsed.data.profile)),
      status: "pending",
      progress: 0,
      findingsCount: 0,
    })
    .returning();

  // Log activity
  const [project] = await db
    .select({ name: projectsTable.name })
    .from(projectsTable)
    .where(eq(projectsTable.id, params.data.projectId));

  await db.insert(activityTable).values({
    type: "scan_completed",
    title: `Scan queued: ${parsed.data.name}`,
    description: `${parsed.data.type} scan initiated for ${project?.name ?? "project"}`,
    severity: null,
    projectId: params.data.projectId,
    projectName: project?.name ?? null,
  });

  res.status(201).json(scan);
});

router.get("/scans/:id", async (req, res): Promise<void> => {
  const raw = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
  const params = GetScanParams.safeParse({ id: parseInt(raw, 10) });
  if (!params.success) {
    res.status(400).json({ error: params.error.message });
    return;
  }

  const [scan] = await db
    .select()
    .from(scansTable)
    .where(eq(scansTable.id, params.data.id));

  if (!scan) {
    res.status(404).json({ error: "Scan not found" });
    return;
  }

  res.json(scan);
});

// GET /scans/:id/status — polling endpoint used by the quick-scan UI
// Returns the scan record plus all findings discovered so far.
router.get("/scans/:id/status", async (req, res): Promise<void> => {
  const raw = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
  const id = parseInt(raw, 10);
  if (isNaN(id)) {
    res.status(400).json({ error: "Invalid scan id" });
    return;
  }

  const [scan] = await db
    .select()
    .from(scansTable)
    .where(eq(scansTable.id, id));

  if (!scan) {
    res.status(404).json({ error: "Scan not found" });
    return;
  }

  const findings = await db
    .select()
    .from(findingsTable)
    .where(eq(findingsTable.scanId, scan.id))
    .orderBy(desc(findingsTable.createdAt));

  res.json({ scan, findings });
});

type ReportFinding = typeof findingsTable.$inferSelect;

function severityCounts(findings: ReportFinding[]) {
  return findings.reduce<Record<string, number>>((counts, finding) => {
    counts[finding.severity] = (counts[finding.severity] ?? 0) + 1;
    return counts;
  }, {});
}

function findingKey(finding: ReportFinding, assetValue?: string): string {
  return [
    finding.title.trim().toLowerCase(),
    (assetValue ?? `asset:${finding.assetId ?? "unknown"}`).trim().toLowerCase(),
    finding.affectedEndpoint ?? "",
    finding.affectedParameter ?? "",
    finding.cve ?? "",
  ].join("|");
}

function buildTechnicalReport(scan: typeof scansTable.$inferSelect, findings: ReportFinding[]) {
  const confirmed = findings.filter((finding) => ["verified", "version_match"].includes(finding.verification));
  const suspected = findings.filter((finding) => finding.verification === "suspected");
  return {
    schemaVersion: "sentinelx.technical-report.v1",
    generatedAt: new Date().toISOString(),
    scan: {
      id: scan.id,
      projectId: scan.projectId,
      name: scan.name,
      type: scan.type,
      profile: scan.profile,
      status: scan.status,
      startedAt: scan.startedAt,
      completedAt: scan.completedAt,
      policy: scan.policy ? JSON.parse(scan.policy) : null,
      toolCapabilities: scan.toolCapabilities ? JSON.parse(scan.toolCapabilities) : [],
    },
    summary: {
      total: findings.length,
      confirmed: confirmed.length,
      suspected: suspected.length,
      severity: severityCounts(findings),
      reproducible: findings.filter((finding) => finding.reproducibility === "reproducible").length,
    },
    findings,
  };
}

function buildSarif(scan: typeof scansTable.$inferSelect, findings: ReportFinding[]) {
  const levelFor = (severity: string) =>
    severity === "critical" || severity === "high" ? "error" : severity === "medium" ? "warning" : "note";
  return {
    version: "2.1.0",
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    runs: [{
      tool: {
        driver: {
          name: "SentinelX",
          informationUri: "https://sentinelx.security",
          version: "0.1",
          rules: findings.map((finding) => ({
            id: finding.title.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, ""),
            name: finding.title,
            shortDescription: { text: finding.title },
            help: { text: finding.remediation ?? "Review the evidence and remediation guidance in the technical report." },
          })),
        },
      },
      automationDetails: { id: `sentinelx/scan/${scan.id}` },
      properties: {
        scanId: scan.id,
        profile: scan.profile,
        verificationPolicy: "Findings are evidence-classified; suspected signals are not confirmed exploits.",
      },
      results: findings.map((finding) => ({
        ruleId: finding.title.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, ""),
        level: levelFor(finding.severity),
        message: {
          text: `${finding.description ?? finding.title} Verification: ${finding.verification}; confidence: ${finding.confidence}%.`,
        },
        locations: [{
          physicalLocation: {
            artifactLocation: { uri: finding.affectedEndpoint ?? `asset:${finding.assetId ?? "unknown"}` },
          },
        }],
        properties: {
          findingId: finding.id,
          severity: finding.severity,
          verification: finding.verification,
          confidence: finding.confidence,
          evidenceQuality: finding.evidenceQuality,
          reproducibility: finding.reproducibility,
          cve: finding.cve,
        },
      })),
    }],
  };
}

async function loadScanWithFindings(id: number) {
  const [scan] = await db.select().from(scansTable).where(eq(scansTable.id, id));
  if (!scan) return null;
  const findings = await db.select().from(findingsTable)
    .where(eq(findingsTable.scanId, scan.id))
    .orderBy(desc(findingsTable.createdAt));
  return { scan, findings };
}

router.get("/scans/:id/report", async (req, res): Promise<void> => {
  const raw = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
  const id = parseInt(raw, 10);
  if (Number.isNaN(id)) {
    res.status(400).json({ error: "Invalid scan id" });
    return;
  }
  const loaded = await loadScanWithFindings(id);
  if (!loaded) {
    res.status(404).json({ error: "Scan not found" });
    return;
  }

  const format = req.query.format === "sarif" ? "sarif" : "json";
  if (format === "sarif") {
    res.setHeader("Content-Type", "application/sarif+json");
    res.setHeader("Content-Disposition", `attachment; filename="sentinelx-scan-${id}.sarif"`);
    res.json(buildSarif(loaded.scan, loaded.findings));
    return;
  }

  res.setHeader("Content-Type", "application/json");
  res.setHeader("Content-Disposition", `attachment; filename="sentinelx-scan-${id}.json"`);
  res.json(buildTechnicalReport(loaded.scan, loaded.findings));
});

router.get("/scans/:id/diff/:baselineId", async (req, res): Promise<void> => {
  const currentId = parseInt(String(req.params.id), 10);
  const baselineId = parseInt(String(req.params.baselineId), 10);
  if (Number.isNaN(currentId) || Number.isNaN(baselineId) || currentId === baselineId) {
    res.status(400).json({ error: "Two different valid scan ids are required" });
    return;
  }
  const [current, baseline] = await Promise.all([loadScanWithFindings(currentId), loadScanWithFindings(baselineId)]);
  if (!current || !baseline) {
    res.status(404).json({ error: "Current or baseline scan not found" });
    return;
  }

  const [baselineAssets, currentAssets] = await Promise.all([
    db.select({ id: assetsTable.id, value: assetsTable.value })
      .from(assetsTable)
      .where(eq(assetsTable.projectId, baseline.scan.projectId)),
    db.select({ id: assetsTable.id, value: assetsTable.value })
      .from(assetsTable)
      .where(eq(assetsTable.projectId, current.scan.projectId)),
  ]);
  const baselineAssetValues = new Map(baselineAssets.map((asset) => [asset.id, asset.value]));
  const currentAssetValues = new Map(currentAssets.map((asset) => [asset.id, asset.value]));
  const baselineMap = new Map(
    baseline.findings.map((finding) => [
      findingKey(finding, baselineAssetValues.get(finding.assetId ?? -1)),
      finding,
    ]),
  );
  const currentMap = new Map(
    current.findings.map((finding) => [
      findingKey(finding, currentAssetValues.get(finding.assetId ?? -1)),
      finding,
    ]),
  );
  const introduced: ReportFinding[] = [];
  const resolved: ReportFinding[] = [];
  const changed: Array<{ before: ReportFinding; after: ReportFinding }> = [];
  const unchanged: ReportFinding[] = [];

  for (const [key, finding] of currentMap) {
    const before = baselineMap.get(key);
    if (!before) {
      introduced.push(finding);
      continue;
    }
    const materiallyChanged =
      before.severity !== finding.severity ||
      before.verification !== finding.verification ||
      before.status !== finding.status ||
      before.confidence !== finding.confidence;
    if (materiallyChanged) changed.push({ before, after: finding });
    else unchanged.push(finding);
  }
  for (const [key, finding] of baselineMap) {
    if (!currentMap.has(key)) resolved.push(finding);
  }

  res.json({
    schemaVersion: "sentinelx.scan-diff.v1",
    generatedAt: new Date().toISOString(),
    baseline: { id: baseline.scan.id, name: baseline.scan.name, completedAt: baseline.scan.completedAt },
    current: { id: current.scan.id, name: current.scan.name, completedAt: current.scan.completedAt },
    summary: {
      introduced: introduced.length,
      resolved: resolved.length,
      changed: changed.length,
      unchanged: unchanged.length,
    },
    introduced,
    resolved,
    changed,
    unchanged,
  });
});

export default router;
