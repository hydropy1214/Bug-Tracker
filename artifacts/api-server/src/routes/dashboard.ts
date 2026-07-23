import { Router, type IRouter } from "express";
import { eq, sql } from "drizzle-orm";
import { db, projectsTable, assetsTable, findingsTable, scansTable, activityTable } from "@workspace/db";
import { GetDashboardActivityQueryParams } from "@workspace/api-zod";

const router: IRouter = Router();

router.get("/dashboard/stats", async (_req, res): Promise<void> => {
  const [totalProjectsRow] = await db
    .select({ count: sql<number>`count(*)::int` })
    .from(projectsTable);

  const [activeProjectsRow] = await db
    .select({ count: sql<number>`count(*)::int` })
    .from(projectsTable)
    .where(eq(projectsTable.status, "active"));

  const [totalAssetsRow] = await db
    .select({ count: sql<number>`count(*)::int` })
    .from(assetsTable);

  const [totalFindingsRow] = await db
    .select({ count: sql<number>`count(*)::int` })
    .from(findingsTable);

  const [openFindingsRow] = await db
    .select({ count: sql<number>`count(*)::int` })
    .from(findingsTable)
    .where(eq(findingsTable.status, "open"));

  const [criticalFindingsRow] = await db
    .select({ count: sql<number>`count(*)::int` })
    .from(findingsTable)
    .where(sql`${findingsTable.severity} = 'critical' AND ${findingsTable.status} != 'resolved'`);

  const [highFindingsRow] = await db
    .select({ count: sql<number>`count(*)::int` })
    .from(findingsTable)
    .where(sql`${findingsTable.severity} = 'high' AND ${findingsTable.status} != 'resolved'`);

  const [runningScansRow] = await db
    .select({ count: sql<number>`count(*)::int` })
    .from(scansTable)
    .where(sql`${scansTable.status} = 'running' OR ${scansTable.status} = 'pending'`);

  const [completedScansRow] = await db
    .select({ count: sql<number>`count(*)::int` })
    .from(scansTable)
    .where(eq(scansTable.status, "completed"));

  res.json({
    totalProjects: totalProjectsRow?.count ?? 0,
    activeProjects: activeProjectsRow?.count ?? 0,
    totalAssets: totalAssetsRow?.count ?? 0,
    totalFindings: totalFindingsRow?.count ?? 0,
    openFindings: openFindingsRow?.count ?? 0,
    criticalFindings: criticalFindingsRow?.count ?? 0,
    highFindings: highFindingsRow?.count ?? 0,
    runningScans: runningScansRow?.count ?? 0,
    completedScans: completedScansRow?.count ?? 0,
  });
});

router.get("/dashboard/activity", async (req, res): Promise<void> => {
  const queryParams = GetDashboardActivityQueryParams.safeParse(req.query);
  const limit = queryParams.success ? (queryParams.data.limit ?? 20) : 20;

  const activity = await db
    .select()
    .from(activityTable)
    .orderBy(sql`${activityTable.createdAt} desc`)
    .limit(limit);

  res.json(activity);
});

router.get("/dashboard/severity-breakdown", async (_req, res): Promise<void> => {
  const severities = ["critical", "high", "medium", "low", "info"] as const;

  const counts = await Promise.all(
    severities.map(async (s) => {
      const [row] = await db
        .select({ count: sql<number>`count(*)::int` })
        .from(findingsTable)
        .where(sql`${findingsTable.severity} = ${s} AND ${findingsTable.status} != 'resolved'`);
      return [s, row?.count ?? 0] as const;
    })
  );

  res.json(Object.fromEntries(counts));
});

export default router;
