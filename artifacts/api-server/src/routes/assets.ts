import { Router, type IRouter } from "express";
import { eq } from "drizzle-orm";
import { db, assetsTable } from "@workspace/db";
import {
  ListAssetsParams,
  CreateAssetParams,
  CreateAssetBody,
  UpdateAssetParams,
  UpdateAssetBody,
  DeleteAssetParams,
} from "@workspace/api-zod";

const router: IRouter = Router();

router.get("/projects/:projectId/assets", async (req, res): Promise<void> => {
  const raw = Array.isArray(req.params.projectId) ? req.params.projectId[0] : req.params.projectId;
  const params = ListAssetsParams.safeParse({ projectId: parseInt(raw, 10) });
  if (!params.success) {
    res.status(400).json({ error: params.error.message });
    return;
  }

  const assets = await db
    .select()
    .from(assetsTable)
    .where(eq(assetsTable.projectId, params.data.projectId))
    .orderBy(assetsTable.createdAt);

  res.json(assets);
});

router.post("/projects/:projectId/assets", async (req, res): Promise<void> => {
  const rawProjectId = Array.isArray(req.params.projectId) ? req.params.projectId[0] : req.params.projectId;
  const params = CreateAssetParams.safeParse({ projectId: parseInt(rawProjectId, 10) });
  if (!params.success) {
    res.status(400).json({ error: params.error.message });
    return;
  }

  const parsed = CreateAssetBody.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: parsed.error.message });
    return;
  }

  const [asset] = await db
    .insert(assetsTable)
    .values({
      projectId: params.data.projectId,
      value: parsed.data.value,
      type: parsed.data.type,
      notes: parsed.data.notes,
      technologies: parsed.data.technologies ?? [],
    })
    .returning();

  res.status(201).json(asset);
});

router.patch("/assets/:id", async (req, res): Promise<void> => {
  const raw = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
  const params = UpdateAssetParams.safeParse({ id: parseInt(raw, 10) });
  if (!params.success) {
    res.status(400).json({ error: params.error.message });
    return;
  }

  const parsed = UpdateAssetBody.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: parsed.error.message });
    return;
  }

  type AssetUpdate = {
    value?: string;
    type?: string;
    status?: string;
    notes?: string;
    technologies?: string[];
  };
  const updateData: AssetUpdate = {};
  if (parsed.data.value !== undefined) updateData.value = parsed.data.value;
  if (parsed.data.type !== undefined) updateData.type = parsed.data.type;
  if (parsed.data.status !== undefined) updateData.status = parsed.data.status;
  if (parsed.data.notes !== undefined) updateData.notes = parsed.data.notes;
  if (parsed.data.technologies !== undefined) updateData.technologies = parsed.data.technologies;

  const [asset] = await db
    .update(assetsTable)
    .set(updateData)
    .where(eq(assetsTable.id, params.data.id))
    .returning();

  if (!asset) {
    res.status(404).json({ error: "Asset not found" });
    return;
  }

  res.json(asset);
});

router.delete("/assets/:id", async (req, res): Promise<void> => {
  const raw = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
  const params = DeleteAssetParams.safeParse({ id: parseInt(raw, 10) });
  if (!params.success) {
    res.status(400).json({ error: params.error.message });
    return;
  }

  const [asset] = await db
    .delete(assetsTable)
    .where(eq(assetsTable.id, params.data.id))
    .returning();

  if (!asset) {
    res.status(404).json({ error: "Asset not found" });
    return;
  }

  res.sendStatus(204);
});

export default router;
