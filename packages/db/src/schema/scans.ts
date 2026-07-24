import { pgTable, text, serial, timestamp, integer, boolean, index } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod/v4";
import { projectsTable } from "./projects";

export const scansTable = pgTable("scans", {
  id: serial("id").primaryKey(),
  projectId: integer("project_id").notNull().references(() => projectsTable.id, { onDelete: "cascade" }),
  name: text("name").notNull(),
  type: text("type").notNull().default("recon"),
  profile: text("profile").notNull().default("safe_active"),
  policy: text("policy"),
  toolCapabilities: text("tool_capabilities"),
  authContext: text("auth_context"),
  cancelRequested: boolean("cancel_requested").notNull().default(false),
  status: text("status").notNull().default("pending"),
  progress: integer("progress").notNull().default(0),
  findingsCount: integer("findings_count").notNull().default(0),
  wafBlocked: boolean("waf_blocked").notNull().default(false),
  startedAt: timestamp("started_at", { withTimezone: true }),
  completedAt: timestamp("completed_at", { withTimezone: true }),
  logs: text("logs"),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
}, (table) => ({
  projectIdIdx: index("scans_project_id_idx").on(table.projectId),
  statusIdx: index("scans_status_idx").on(table.status),
  createdAtIdx: index("scans_created_at_idx").on(table.createdAt),
}));

export const insertScanSchema = createInsertSchema(scansTable).omit({ id: true, createdAt: true });
export type InsertScan = z.infer<typeof insertScanSchema>;
export type Scan = typeof scansTable.$inferSelect;
