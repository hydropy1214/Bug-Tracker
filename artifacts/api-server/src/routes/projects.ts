import { Router, type IRouter } from "express";
import { eq, sql } from "drizzle-orm";
import { db, projectsTable, assetsTable, findingsTable } from "@workspace/db";
import {
  CreateProjectBody,
  GetProjectParams,
  UpdateProjectParams,
  UpdateProjectBody,
  DeleteProjectParams,
} from "@workspace/api-zod";

const router: IRouter = Router();

router.get("/projects", async (_req, res): Promise<void> => {
  const projects = await db.select().from(projectsTable).orderBy(projectsTable.createdAt);

  const enriched = await Promise.all(
    projects.map(async (p) => {
      const [assetRow] = await db
        .select({ count: sql<number>`count(*)::int` })
        .from(assetsTable)
        .where(eq(assetsTable.projectId, p.id));

      const [findingRow] = await db
        .select({ count: sql<number>`count(*)::int` })
        .from(findingsTable)
        .where(eq(findingsTable.projectId, p.id));

      const [criticalRow] = await db
        .select({ count: sql<number>`count(*)::int` })
        .from(findingsTable)
        .where(
          sql`${findingsTable.projectId} = ${p.id} AND ${findingsTable.severity} = 'critical'`
        );

      const [highRow] = await db
        .select({ count: sql<number>`count(*)::int` })
        .from(findingsTable)
        .where(
          sql`${findingsTable.projectId} = ${p.id} AND ${findingsTable.severity} = 'high'`
        );

      return {
        ...p,
        assetCount: assetRow?.count ?? 0,
        findingCount: findingRow?.count ?? 0,
        criticalCount: criticalRow?.count ?? 0,
        highCount: highRow?.count ?? 0,
      };
    })
  );

  res.json(enriched);
});

router.post("/projects", async (req, res): Promise<void> => {
  const parsed = CreateProjectBody.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: parsed.error.message });
    return;
  }

  const { name, description, scope, status } = parsed.data;
  const [project] = await db
    .insert(projectsTable)
    .values({ name, description, scope, status: status ?? "active" })
    .returning();

  res.status(201).json({
    ...project,
    assetCount: 0,
    findingCount: 0,
    criticalCount: 0,
    highCount: 0,
  });
});

router.get("/projects/:id", async (req, res): Promise<void> => {
  const raw = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
  const params = GetProjectParams.safeParse({ id: parseInt(raw, 10) });
  if (!params.success) {
    res.status(400).json({ error: params.error.message });
    return;
  }

  const [project] = await db
    .select()
    .from(projectsTable)
    .where(eq(projectsTable.id, params.data.id));

  if (!project) {
    res.status(404).json({ error: "Project not found" });
    return;
  }

  const [assetRow] = await db
    .select({ count: sql<number>`count(*)::int` })
    .from(assetsTable)
    .where(eq(assetsTable.projectId, project.id));

  const [findingRow] = await db
    .select({ count: sql<number>`count(*)::int` })
    .from(findingsTable)
    .where(eq(findingsTable.projectId, project.id));

  const [criticalRow] = await db
    .select({ count: sql<number>`count(*)::int` })
    .from(findingsTable)
    .where(
      sql`${findingsTable.projectId} = ${project.id} AND ${findingsTable.severity} = 'critical'`
    );

  const [highRow] = await db
    .select({ count: sql<number>`count(*)::int` })
    .from(findingsTable)
    .where(
      sql`${findingsTable.projectId} = ${project.id} AND ${findingsTable.severity} = 'high'`
    );

  res.json({
    ...project,
    assetCount: assetRow?.count ?? 0,
    findingCount: findingRow?.count ?? 0,
    criticalCount: criticalRow?.count ?? 0,
    highCount: highRow?.count ?? 0,
  });
});

router.patch("/projects/:id", async (req, res): Promise<void> => {
  const raw = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
  const params = UpdateProjectParams.safeParse({ id: parseInt(raw, 10) });
  if (!params.success) {
    res.status(400).json({ error: params.error.message });
    return;
  }

  const parsed = UpdateProjectBody.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: parsed.error.message });
    return;
  }

  const [project] = await db
    .update(projectsTable)
    .set({ ...parsed.data, updatedAt: new Date() })
    .where(eq(projectsTable.id, params.data.id))
    .returning();

  if (!project) {
    res.status(404).json({ error: "Project not found" });
    return;
  }

  const [assetRow] = await db
    .select({ count: sql<number>`count(*)::int` })
    .from(assetsTable)
    .where(eq(assetsTable.projectId, project.id));

  const [findingRow] = await db
    .select({ count: sql<number>`count(*)::int` })
    .from(findingsTable)
    .where(eq(findingsTable.projectId, project.id));

  const [criticalRow] = await db
    .select({ count: sql<number>`count(*)::int` })
    .from(findingsTable)
    .where(
      sql`${findingsTable.projectId} = ${project.id} AND ${findingsTable.severity} = 'critical'`
    );

  const [highRow] = await db
    .select({ count: sql<number>`count(*)::int` })
    .from(findingsTable)
    .where(
      sql`${findingsTable.projectId} = ${project.id} AND ${findingsTable.severity} = 'high'`
    );

  res.json({
    ...project,
    assetCount: assetRow?.count ?? 0,
    findingCount: findingRow?.count ?? 0,
    criticalCount: criticalRow?.count ?? 0,
    highCount: highRow?.count ?? 0,
  });
});

router.delete("/projects/:id", async (req, res): Promise<void> => {
  const raw = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
  const params = DeleteProjectParams.safeParse({ id: parseInt(raw, 10) });
  if (!params.success) {
    res.status(400).json({ error: params.error.message });
    return;
  }

  const [project] = await db
    .delete(projectsTable)
    .where(eq(projectsTable.id, params.data.id))
    .returning();

  if (!project) {
    res.status(404).json({ error: "Project not found" });
    return;
  }

  res.sendStatus(204);
});

export default router;
