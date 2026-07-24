import { Router, type IRouter } from "express";
import { eq } from "drizzle-orm";
import { db, findingsTable, activityTable, projectsTable } from "@workspace/db";
import {
  ListFindingsParams,
  CreateFindingParams,
  CreateFindingBody,
  GetFindingParams,
  UpdateFindingParams,
  UpdateFindingBody,
  DeleteFindingParams,
} from "@workspace/api-types";

const router: IRouter = Router();

router.get("/projects/:projectId/findings", async (req, res): Promise<void> => {
  const raw = Array.isArray(req.params.projectId) ? req.params.projectId[0] : req.params.projectId;
  const params = ListFindingsParams.safeParse({ projectId: parseInt(raw, 10) });
  if (!params.success) {
    res.status(400).json({ error: params.error.message });
    return;
  }

  const findings = await db
    .select()
    .from(findingsTable)
    .where(eq(findingsTable.projectId, params.data.projectId))
    .orderBy(findingsTable.createdAt);

  res.json(findings);
});

router.post("/projects/:projectId/findings", async (req, res): Promise<void> => {
  const rawProjectId = Array.isArray(req.params.projectId) ? req.params.projectId[0] : req.params.projectId;
  const params = CreateFindingParams.safeParse({ projectId: parseInt(rawProjectId, 10) });
  if (!params.success) {
    res.status(400).json({ error: params.error.message });
    return;
  }

  const parsed = CreateFindingBody.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: parsed.error.message });
    return;
  }

  const [finding] = await db
    .insert(findingsTable)
    .values({
      projectId: params.data.projectId,
      scanId: parsed.data.scanId ?? null,
      title: parsed.data.title,
      description: parsed.data.description,
      severity: parsed.data.severity,
      status: parsed.data.status ?? "open",
      verification: parsed.data.verification ?? "verified",
      confidence: parsed.data.confidence ?? 80,
      evidenceQuality: parsed.data.evidenceQuality ?? "standard",
      verificationMethod: parsed.data.verificationMethod ?? null,
      reproducibility: parsed.data.reproducibility ?? "not_tested",
      affectedEndpoint: parsed.data.affectedEndpoint ?? null,
      affectedParameter: parsed.data.affectedParameter ?? null,
      negativeTests: parsed.data.negativeTests ?? null,
      limitations: parsed.data.limitations ?? null,
      toolInfo: parsed.data.toolInfo ?? null,
      assetId: parsed.data.assetId ?? null,
      cvss: parsed.data.cvss ?? null,
      cve: parsed.data.cve ?? null,
      evidence: parsed.data.evidence ?? null,
      remediation: parsed.data.remediation ?? null,
    })
    .returning();

  // Log activity
  const [project] = await db
    .select({ name: projectsTable.name })
    .from(projectsTable)
    .where(eq(projectsTable.id, params.data.projectId));

  await db.insert(activityTable).values({
    type: "finding_created",
    title: `New ${parsed.data.severity} finding`,
    description: `${parsed.data.title} discovered in ${project?.name ?? "project"}`,
    severity: parsed.data.severity,
    projectId: params.data.projectId,
    projectName: project?.name ?? null,
  });

  res.status(201).json(finding);
});

router.get("/findings/:id", async (req, res): Promise<void> => {
  const raw = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
  const params = GetFindingParams.safeParse({ id: parseInt(raw, 10) });
  if (!params.success) {
    res.status(400).json({ error: params.error.message });
    return;
  }

  const [finding] = await db
    .select()
    .from(findingsTable)
    .where(eq(findingsTable.id, params.data.id));

  if (!finding) {
    res.status(404).json({ error: "Finding not found" });
    return;
  }

  res.json(finding);
});

router.patch("/findings/:id", async (req, res): Promise<void> => {
  const raw = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
  const params = UpdateFindingParams.safeParse({ id: parseInt(raw, 10) });
  if (!params.success) {
    res.status(400).json({ error: params.error.message });
    return;
  }

  const parsed = UpdateFindingBody.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: parsed.error.message });
    return;
  }

  // Fetch the original finding before updating so we can detect status changes
  const [original] = await db
    .select()
    .from(findingsTable)
    .where(eq(findingsTable.id, params.data.id));

  if (!original) {
    res.status(404).json({ error: "Finding not found" });
    return;
  }

  type FindingUpdate = {
    updatedAt: Date;
    title?: string;
    description?: string;
    severity?: string;
    status?: string;
    verification?: string;
    confidence?: number;
    scanId?: number | null;
    evidenceQuality?: string;
    verificationMethod?: string;
    reproducibility?: string;
    affectedEndpoint?: string;
    affectedParameter?: string;
    negativeTests?: string;
    limitations?: string;
    toolInfo?: string;
    cvss?: number;
    cve?: string;
    evidence?: string;
    remediation?: string;
  };

  const updateData: FindingUpdate = { updatedAt: new Date() };
  if (parsed.data.title !== undefined) updateData.title = parsed.data.title;
  if (parsed.data.description !== undefined) updateData.description = parsed.data.description;
  if (parsed.data.severity !== undefined) updateData.severity = parsed.data.severity;
  if (parsed.data.status !== undefined) updateData.status = parsed.data.status;
  if (parsed.data.verification !== undefined) updateData.verification = parsed.data.verification;
  if (parsed.data.confidence !== undefined) updateData.confidence = parsed.data.confidence;
  if (parsed.data.scanId !== undefined) updateData.scanId = parsed.data.scanId;
  if (parsed.data.evidenceQuality !== undefined) updateData.evidenceQuality = parsed.data.evidenceQuality;
  if (parsed.data.verificationMethod !== undefined) updateData.verificationMethod = parsed.data.verificationMethod;
  if (parsed.data.reproducibility !== undefined) updateData.reproducibility = parsed.data.reproducibility;
  if (parsed.data.affectedEndpoint !== undefined) updateData.affectedEndpoint = parsed.data.affectedEndpoint;
  if (parsed.data.affectedParameter !== undefined) updateData.affectedParameter = parsed.data.affectedParameter;
  if (parsed.data.negativeTests !== undefined) updateData.negativeTests = parsed.data.negativeTests;
  if (parsed.data.limitations !== undefined) updateData.limitations = parsed.data.limitations;
  if (parsed.data.toolInfo !== undefined) updateData.toolInfo = parsed.data.toolInfo;
  if (parsed.data.cvss !== undefined) updateData.cvss = parsed.data.cvss;
  if (parsed.data.cve !== undefined) updateData.cve = parsed.data.cve;
  if (parsed.data.evidence !== undefined) updateData.evidence = parsed.data.evidence;
  if (parsed.data.remediation !== undefined) updateData.remediation = parsed.data.remediation;

  const [finding] = await db
    .update(findingsTable)
    .set(updateData)
    .where(eq(findingsTable.id, params.data.id))
    .returning();

  if (!finding) {
    res.status(404).json({ error: "Finding not found" });
    return;
  }

  // Log activity when status changes — compare new status against the original record
  if (parsed.data.status && parsed.data.status !== original.status) {
    const [project] = await db
      .select({ name: projectsTable.name })
      .from(projectsTable)
      .where(eq(projectsTable.id, finding.projectId));

    const statusLabel: Record<string, string> = {
      resolved: "resolved",
      in_progress: "moved to in-progress",
      wont_fix: "marked won't fix",
      open: "reopened",
    };
    await db.insert(activityTable).values({
      type: "finding_updated",
      title: `Finding ${statusLabel[parsed.data.status] ?? "updated"}`,
      description: `${finding.title} ${statusLabel[parsed.data.status] ?? "updated"} in ${project?.name ?? "project"}`,
      severity: finding.severity,
      projectId: finding.projectId,
      projectName: project?.name ?? null,
    });
  }

  res.json(finding);
});

router.delete("/findings/:id", async (req, res): Promise<void> => {
  const raw = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
  const params = DeleteFindingParams.safeParse({ id: parseInt(raw, 10) });
  if (!params.success) {
    res.status(400).json({ error: params.error.message });
    return;
  }

  const [finding] = await db
    .delete(findingsTable)
    .where(eq(findingsTable.id, params.data.id))
    .returning();

  if (!finding) {
    res.status(404).json({ error: "Finding not found" });
    return;
  }

  // Log activity
  const [project] = await db
    .select({ name: projectsTable.name })
    .from(projectsTable)
    .where(eq(projectsTable.id, finding.projectId));

  await db.insert(activityTable).values({
    type: "finding_deleted",
    title: `Finding closed: ${finding.title}`,
    description: `${finding.severity} finding removed from ${project?.name ?? "project"}`,
    severity: finding.severity,
    projectId: finding.projectId,
    projectName: project?.name ?? null,
  });

  res.sendStatus(204);
});

export default router;
