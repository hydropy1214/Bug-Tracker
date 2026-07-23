/**
 * Quick Scan Route
 *
 * POST /quick-scan
 * Accepts a URL and scan type, creates a temporary project + asset,
 * queues the scan, and returns the IDs for polling.
 */

import { Router, type IRouter } from "express";
import { db, projectsTable, assetsTable, scansTable, activityTable } from "@workspace/db";
import { resolveScanPolicy, type ScanProfile } from "../lib/scanner";
import { encryptAuthHeaders } from "../lib/auth-context";

const router: IRouter = Router();

router.post("/quick-scan", async (req, res): Promise<void> => {
  const { url, scanType = "full", profile = "deep_authorized", authHeaders } = req.body as {
    url?: string;
    scanType?: string;
    profile?: string;
    authHeaders?: Record<string, string>;
  };

  if (!url || typeof url !== "string") {
    res.status(400).json({ error: "url is required" });
    return;
  }

  const VALID_SCAN_TYPES = ["recon", "enumeration", "vulnerability", "full"];
  if (!VALID_SCAN_TYPES.includes(scanType)) {
    res.status(400).json({ error: `scanType must be one of: ${VALID_SCAN_TYPES.join(", ")}` });
    return;
  }
  const validProfiles = ["passive", "safe_active", "deep_authorized", "authenticated", "lab"];
  if (!validProfiles.includes(profile)) {
    res.status(400).json({ error: `profile must be one of: ${validProfiles.join(", ")}` });
    return;
  }
  const policy = resolveScanPolicy(profile);
  if (authHeaders !== undefined && (!authHeaders || typeof authHeaders !== "object" || Array.isArray(authHeaders))) {
    res.status(400).json({ error: "authHeaders must be an object of header names to values" });
    return;
  }

  // Normalise URL and determine asset type
  let normalised = url.trim();
  if (!/^https?:\/\//i.test(normalised)) {
    normalised = `https://${normalised}`;
  }

  let parsedUrl: URL;
  try {
    parsedUrl = new URL(normalised);
  } catch {
    res.status(400).json({ error: "Invalid URL — please include the full address (e.g. https://example.com)" });
    return;
  }

  const hostname = parsedUrl.hostname;
  const isIp = /^\d{1,3}(\.\d{1,3}){3}$/.test(hostname);
  const assetType = isIp ? "ip" : "domain";

  // Create a fresh project scoped to this quick scan
  const [project] = await db
    .insert(projectsTable)
    .values({
      name: hostname,
      description: `Quick scan initiated for ${normalised} using ${policy.profile} profile`,
      scope: normalised,
      status: "active",
    })
    .returning();

  if (!project) {
    res.status(500).json({ error: "Failed to create project" });
    return;
  }

  // Create the target asset
  const [asset] = await db
    .insert(assetsTable)
    .values({
      projectId: project.id,
      value: normalised,
      type: assetType,
      status: "active",
    })
    .returning();

  if (!asset) {
    res.status(500).json({ error: "Failed to create asset" });
    return;
  }

  // Queue the scan
  const scanName = `${scanType.charAt(0).toUpperCase() + scanType.slice(1)} scan — ${hostname}`;
  const [scan] = await db
    .insert(scansTable)
    .values({
      projectId: project.id,
      name: scanName,
      type: scanType,
      profile,
      policy: JSON.stringify(policy),
      authContext: authHeaders ? encryptAuthHeaders(authHeaders) : null,
      status: "pending",
      progress: 0,
      findingsCount: 0,
    })
    .returning();

  if (!scan) {
    res.status(500).json({ error: "Failed to create scan" });
    return;
  }

  // Log activity
  await db.insert(activityTable).values({
    type: "scan_started",
    title: `Quick scan started: ${hostname}`,
    description: `${scanType} scan queued for ${normalised}`,
    severity: null,
    projectId: project.id,
    projectName: hostname,
  });

  res.status(201).json({
    projectId: project.id,
    assetId: asset.id,
    scanId: scan.id,
    target: normalised,
    hostname,
    scanType,
    profile,
    policy,
  });
});

export default router;
