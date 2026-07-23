import { Router, type IRouter } from "express";
import { eq } from "drizzle-orm";
import { db, scansTable, activityTable, projectsTable } from "@workspace/db";
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

export default router;
