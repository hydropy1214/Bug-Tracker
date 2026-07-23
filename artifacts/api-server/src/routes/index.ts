import { Router, type IRouter } from "express";
import healthRouter from "./health";
import projectsRouter from "./projects";
import assetsRouter from "./assets";
import findingsRouter from "./findings";
import scansRouter from "./scans";
import dashboardRouter from "./dashboard";
import quickScanRouter from "./quick-scan";

const router: IRouter = Router();

router.use(healthRouter);
router.use(quickScanRouter);
router.use(projectsRouter);
router.use(assetsRouter);
router.use(findingsRouter);
router.use(scansRouter);
router.use(dashboardRouter);

export default router;
