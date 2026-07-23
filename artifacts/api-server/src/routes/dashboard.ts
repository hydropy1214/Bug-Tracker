import { Router, type IRouter } from "express";
import { eq, sql, and } from "drizzle-orm";
import {
  db,
  projectsTable,
  assetsTable,
  findingsTable,
  scansTable,
  activityTable,
} from "@workspace/db";
import { GetDashboardActivityQueryParams } from "@workspace/api-zod";

const router: IRouter = Router();

// GET /dashboard/stats
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
    .where(
      and(
        eq(findingsTable.severity, "critical"),
        eq(findingsTable.status, "open"),
      ),
    );

  const [highFindingsRow] = await db
    .select({ count: sql<number>`count(*)::int` })
    .from(findingsTable)
    .where(
      and(
        eq(findingsTable.severity, "high"),
        eq(findingsTable.status, "open"),
      ),
    );

  // "running" = active scans; include pending in the running count so the
  // dashboard accurately reflects scans in-flight (queued + executing)
  const [runningScansRow] = await db
    .select({ count: sql<number>`count(*)::int` })
    .from(scansTable)
    .where(sql`${scansTable.status} IN ('running', 'pending')`);

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

// GET /dashboard/activity?limit=N
router.get("/dashboard/activity", async (req, res): Promise<void> => {
  const parsed = GetDashboardActivityQueryParams.safeParse(req.query);
  const limit = parsed.success ? (parsed.data.limit ?? 20) : 20;

  const activity = await db
    .select()
    .from(activityTable)
    .orderBy(sql`${activityTable.createdAt} DESC`)
    .limit(Math.min(limit, 100));

  res.json(activity);
});

// GET /dashboard/severity-breakdown
// Counts open findings only — consistent with criticalFindings/highFindings in /stats
router.get("/dashboard/severity-breakdown", async (_req, res): Promise<void> => {
  const rows = await db
    .select({
      severity: findingsTable.severity,
      count: sql<number>`count(*)::int`,
    })
    .from(findingsTable)
    .where(eq(findingsTable.status, "open"))
    .groupBy(findingsTable.severity);

  const breakdown: Record<string, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };

  for (const row of rows) {
    if (row.severity in breakdown) {
      breakdown[row.severity] = row.count;
    }
  }

  res.json(breakdown);
});

export default router;
