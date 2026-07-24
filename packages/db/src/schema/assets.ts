import { pgTable, text, serial, timestamp, integer, index } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod/v4";
import { projectsTable } from "./projects";

export const assetsTable = pgTable("assets", {
  id: serial("id").primaryKey(),
  projectId: integer("project_id").notNull().references(() => projectsTable.id, { onDelete: "cascade" }),
  value: text("value").notNull(),
  type: text("type").notNull().default("domain"),
  status: text("status").notNull().default("active"),
  notes: text("notes"),
  technologies: text("technologies").array().notNull().default([]),
  apiSpec: text("api_spec"),
  apiSpecVersion: text("api_spec_version"),
  apiSpecImportedAt: timestamp("api_spec_imported_at", { withTimezone: true }),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
}, (table) => ({
  projectIdIdx: index("assets_project_id_idx").on(table.projectId),
  statusIdx: index("assets_status_idx").on(table.status),
}));

export const insertAssetSchema = createInsertSchema(assetsTable).omit({ id: true, createdAt: true });
export type InsertAsset = z.infer<typeof insertAssetSchema>;
export type Asset = typeof assetsTable.$inferSelect;
