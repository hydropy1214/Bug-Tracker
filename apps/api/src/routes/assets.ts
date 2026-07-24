import { Router, type IRouter } from "express";
import { eq, and } from "drizzle-orm";
import { db, assetsTable, endpointsTable } from "@workspace/db";
import {
  ListAssetsParams,
  CreateAssetParams,
  CreateAssetBody,
  UpdateAssetParams,
  UpdateAssetBody,
  DeleteAssetParams,
} from "@workspace/api-types";
import { parseOpenApiJson } from "../lib/api-schema";

const router: IRouter = Router();

router.get("/projects/:projectId/endpoints", async (req, res): Promise<void> => {
  const projectId = parseInt(String(req.params.projectId), 10);
  if (Number.isNaN(projectId)) {
    res.status(400).json({ error: "Invalid project id" });
    return;
  }
  const endpoints = await db.select().from(endpointsTable).where(eq(endpointsTable.projectId, projectId));
  res.json(endpoints);
});

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

router.post("/assets/:id/import", async (req, res): Promise<void> => {
  const assetId = parseInt(String(req.params.id), 10);
  if (Number.isNaN(assetId)) {
    res.status(400).json({ error: "Invalid asset id" });
    return;
  }
  const [asset] = await db.select().from(assetsTable).where(eq(assetsTable.id, assetId));
  if (!asset) {
    res.status(404).json({ error: "Asset not found" });
    return;
  }

  const input = req.body as { spec?: unknown; source?: string; baseUrl?: string };
  if (input.spec === undefined) {
    res.status(400).json({ error: "spec is required; provide an OpenAPI/Swagger JSON object or JSON string" });
    return;
  }
  let parsed;
  try {
    parsed = parseOpenApiJson(input.spec);
  } catch (error) {
    res.status(400).json({ error: error instanceof Error ? error.message : "Invalid OpenAPI document" });
    return;
  }

  const source = typeof input.source === "string" && input.source.trim() ? input.source.trim() : "import";
  const baseUrl = typeof input.baseUrl === "string" && input.baseUrl.trim()
    ? input.baseUrl.trim()
    : parsed.baseUrl;
  await db.transaction(async (tx) => {
    await tx.delete(endpointsTable).where(eq(endpointsTable.assetId, asset.id));
    if (parsed.endpoints.length > 0) {
      await tx.insert(endpointsTable).values(parsed.endpoints.map((endpoint) => ({
        projectId: asset.projectId,
        assetId: asset.id,
        method: endpoint.method,
        path: endpoint.path,
        operationId: endpoint.operationId,
        summary: endpoint.summary,
        parameters: JSON.stringify(endpoint.parameters),
        requestBody: endpoint.requestBody ? JSON.stringify(endpoint.requestBody) : null,
        security: endpoint.security ? JSON.stringify(endpoint.security) : null,
        source,
        baseUrl,
      })));
    }
    await tx.update(assetsTable)
      .set({
        type: "api",
        apiSpec: JSON.stringify(input.spec),
        apiSpecVersion: parsed.version,
        apiSpecImportedAt: new Date(),
      })
      .where(eq(assetsTable.id, asset.id));
  });

  res.status(200).json({
    assetId: asset.id,
    projectId: asset.projectId,
    version: parsed.version,
    baseUrl,
    imported: parsed.endpoints.length,
  });
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
