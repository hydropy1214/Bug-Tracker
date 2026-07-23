import { pgTable, text, serial, timestamp, integer } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod/v4";
import { projectsTable } from "./projects";
import { assetsTable } from "./assets";

export const endpointsTable = pgTable("endpoints", {
  id: serial("id").primaryKey(),
  projectId: integer("project_id").notNull().references(() => projectsTable.id, { onDelete: "cascade" }),
  assetId: integer("asset_id").references(() => assetsTable.id, { onDelete: "cascade" }),
  method: text("method").notNull(),
  path: text("path").notNull(),
  operationId: text("operation_id"),
  summary: text("summary"),
  parameters: text("parameters"),
  requestBody: text("request_body"),
  security: text("security"),
  source: text("source").notNull().default("manual"),
  baseUrl: text("base_url"),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow().$onUpdate(() => new Date()),
});

export const insertEndpointSchema = createInsertSchema(endpointsTable).omit({
  id: true,
  createdAt: true,
  updatedAt: true,
});
export type InsertEndpoint = z.infer<typeof insertEndpointSchema>;
export type Endpoint = typeof endpointsTable.$inferSelect;