import { pgTable, text, serial, timestamp, integer, real, boolean, index } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod/v4";
import { projectsTable } from "./projects";
import { assetsTable } from "./assets";
import { scansTable } from "./scans";
import { endpointsTable } from "./endpoints";

export const findingsTable = pgTable("findings", {
  id: serial("id").primaryKey(),
  projectId: integer("project_id").notNull().references(() => projectsTable.id, { onDelete: "cascade" }),
  scanId: integer("scan_id").references(() => scansTable.id, { onDelete: "set null" }),
  assetId: integer("asset_id").references(() => assetsTable.id, { onDelete: "set null" }),
  endpointId: integer("endpoint_id").references(() => endpointsTable.id, { onDelete: "set null" }),
  title: text("title").notNull(),
  description: text("description"),
  severity: text("severity").notNull().default("medium"),
  status: text("status").notNull().default("open"),
  verification: text("verification").notNull().default("verified"),
  verified: boolean("verified").notNull().default(false),
  confidence: integer("confidence").notNull().default(80),
  evidenceQuality: text("evidence_quality").notNull().default("standard"),
  verificationMethod: text("verification_method"),
  reproducibility: text("reproducibility").notNull().default("not_tested"),
  affectedEndpoint: text("affected_endpoint"),
  affectedParameter: text("affected_parameter"),
  negativeTests: text("negative_tests"),
  limitations: text("limitations"),
  toolInfo: text("tool_info"),
  cvss: real("cvss"),
  cve: text("cve"),
  evidence: text("evidence"),
  remediation: text("remediation"),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow().$onUpdate(() => new Date()),
}, (table) => ({
  scanIdIdx: index("findings_scan_id_idx").on(table.scanId),
  projectIdIdx: index("findings_project_id_idx").on(table.projectId),
  assetIdIdx: index("findings_asset_id_idx").on(table.assetId),
  statusIdx: index("findings_status_idx").on(table.status),
}));

export const insertFindingSchema = createInsertSchema(findingsTable).omit({ id: true, createdAt: true, updatedAt: true });
export type InsertFinding = z.infer<typeof insertFindingSchema>;
export type Finding = typeof findingsTable.$inferSelect;
