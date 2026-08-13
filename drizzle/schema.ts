import { boolean, double, int, mysqlEnum, mysqlTable, text, timestamp, uniqueIndex, varchar } from "drizzle-orm/mysql-core";

export const users = mysqlTable("users", {
  id: int("id").autoincrement().primaryKey(),
  openId: varchar("openId", { length: 64 }).notNull().unique(),
  name: text("name"), email: varchar("email", { length: 320 }), loginMethod: varchar("loginMethod", { length: 64 }),
  role: mysqlEnum("role", ["user", "admin"]).default("user").notNull(),
  createdAt: timestamp("createdAt").defaultNow().notNull(), updatedAt: timestamp("updatedAt").defaultNow().onUpdateNow().notNull(), lastSignedIn: timestamp("lastSignedIn").defaultNow().notNull(),
});

export const datasets = mysqlTable("datasets", {
  id: int("id").autoincrement().primaryKey(), userId: int("userId").notNull(), name: varchar("name", { length: 255 }).notNull(), storageKey: varchar("storageKey", { length: 512 }).notNull(), fileSize: int("fileSize").notNull(), packetCount: int("packetCount").default(0).notNull(), flowCount: int("flowCount").default(0).notNull(), protocolJson: text("protocolJson").notNull(),
  label: mysqlEnum("label", ["benign", "malicious", "unlabeled"]).default("unlabeled").notNull(), trafficClass: varchar("trafficClass", { length: 32 }).default("unlabeled").notNull(), annotationSetId: int("annotationSetId"), annotationSnapshotJson: text("annotationSnapshotJson"),
  extractionStatus: mysqlEnum("extractionStatus", ["ready", "failed"]).default("ready").notNull(), errorMessage: text("errorMessage"), createdAt: timestamp("createdAt").defaultNow().notNull(), updatedAt: timestamp("updatedAt").defaultNow().onUpdateNow().notNull(),
}, table => [uniqueIndex("datasets_user_name_idx").on(table.userId, table.name)]);

export const flowFeatures = mysqlTable("flowFeatures", {
  id: int("id").autoincrement().primaryKey(), datasetId: int("datasetId").notNull(), flowKey: varchar("flowKey", { length: 512 }).notNull(), sourceIp: varchar("sourceIp", { length: 64 }).notNull(), sourcePort: int("sourcePort").notNull(), destinationIp: varchar("destinationIp", { length: 64 }).notNull(), destinationPort: int("destinationPort").notNull(), transportProtocol: varchar("transportProtocol", { length: 16 }).notNull(), applicationProtocol: varchar("applicationProtocol", { length: 32 }).default("UNKNOWN").notNull(),
  packetCount: int("packetCount").notNull(), byteCount: int("byteCount").notNull(), upPackets: int("upPackets").notNull(), downPackets: int("downPackets").notNull(), upBytes: int("upBytes").notNull(), downBytes: int("downBytes").notNull(), durationMs: double("durationMs").notNull(), avgPacketLength: double("avgPacketLength").notNull(), stdPacketLength: double("stdPacketLength").notNull(), avgIatMs: double("avgIatMs").notNull(), stdIatMs: double("stdIatMs").notNull(), uplinkRatio: double("uplinkRatio").notNull(), spltJson: text("spltJson").notNull(), nfstreamJson: text("nfstreamJson"), tlsVersion: varchar("tlsVersion", { length: 32 }).default("UNKNOWN").notNull(), ja3: varchar("ja3", { length: 64 }), sniVisibility: mysqlEnum("sniVisibility", ["visible", "not_observed"]).default("not_observed").notNull(), sni: varchar("sni", { length: 255 }), createdAt: timestamp("createdAt").defaultNow().notNull(),
}, table => [uniqueIndex("flow_features_dataset_key_idx").on(table.datasetId, table.flowKey)]);

export const modelVersions = mysqlTable("modelVersions", {
  id: int("id").autoincrement().primaryKey(), userId: int("userId").notNull(), versionName: varchar("versionName", { length: 64 }).notNull(), algorithm: mysqlEnum("algorithm", ["logistic_regression", "gaussian_nb", "lightgbm_kitnet"]).notNull(), featureSetJson: text("featureSetJson").notNull(), classSetJson: text("classSetJson").notNull(), annotationSetId: int("annotationSetId"), annotationSnapshotJson: text("annotationSnapshotJson"), metricsJson: text("metricsJson").notNull(), modelJson: text("modelJson").notNull(), trainedDatasetIdsJson: text("trainedDatasetIdsJson").notNull(), isActive: boolean("isActive").default(false).notNull(), createdAt: timestamp("createdAt").defaultNow().notNull(),
}, table => [uniqueIndex("model_versions_user_version_idx").on(table.userId, table.versionName)]);

export const trainingJobs = mysqlTable("trainingJobs", {
  id: int("id").autoincrement().primaryKey(), userId: int("userId").notNull(), status: mysqlEnum("status", ["running", "completed", "failed"]).default("running").notNull(), progress: int("progress").default(0).notNull(), algorithm: mysqlEnum("algorithm", ["logistic_regression", "gaussian_nb", "lightgbm_kitnet"]).notNull(), datasetIdsJson: text("datasetIdsJson").notNull(), featureSetJson: text("featureSetJson").notNull(), classSetJson: text("classSetJson").notNull(), annotationSetId: int("annotationSetId"), annotationSnapshotJson: text("annotationSnapshotJson"), modelVersionId: int("modelVersionId"), errorMessage: text("errorMessage"), createdAt: timestamp("createdAt").defaultNow().notNull(), updatedAt: timestamp("updatedAt").defaultNow().onUpdateNow().notNull(),
});

export const uploadTasks = mysqlTable("uploadTasks", {
  id: int("id").autoincrement().primaryKey(), userId: int("userId").notNull(), fileName: varchar("fileName", { length: 255 }).notNull(), storageKey: varchar("storageKey", { length: 512 }).notNull(), fileSize: int("fileSize").notNull(), label: mysqlEnum("label", ["benign", "malicious", "unlabeled"]).default("unlabeled").notNull(), trafficClass: varchar("trafficClass", { length: 32 }).default("unlabeled").notNull(), annotationSetId: int("annotationSetId"), annotationSnapshotJson: text("annotationSnapshotJson"), status: mysqlEnum("status", ["queued", "processing", "completed", "failed"]).default("queued").notNull(), progress: int("progress").default(0).notNull(), datasetId: int("datasetId"), errorMessage: text("errorMessage"), createdAt: timestamp("createdAt").defaultNow().notNull(), updatedAt: timestamp("updatedAt").defaultNow().onUpdateNow().notNull(),
});

export const detectionTasks = mysqlTable("detectionTasks", {
  id: int("id").autoincrement().primaryKey(), userId: int("userId").notNull(), modelVersionId: int("modelVersionId").notNull(), annotationSetId: int("annotationSetId"), annotationSnapshotJson: text("annotationSnapshotJson"), fileName: varchar("fileName", { length: 255 }).notNull(), storageKey: varchar("storageKey", { length: 512 }).notNull(), status: mysqlEnum("status", ["completed", "failed"]).default("completed").notNull(), totalFlows: int("totalFlows").default(0).notNull(), highRiskFlows: int("highRiskFlows").default(0).notNull(), averageRisk: double("averageRisk").default(0).notNull(), summaryJson: text("summaryJson").notNull(), errorMessage: text("errorMessage"), createdAt: timestamp("createdAt").defaultNow().notNull(),
});

export const detectionFlows = mysqlTable("detectionFlows", {
  id: int("id").autoincrement().primaryKey(), taskId: int("taskId").notNull(), flowKey: varchar("flowKey", { length: 512 }).notNull(), sourceIp: varchar("sourceIp", { length: 64 }).notNull(), sourcePort: int("sourcePort").notNull(), destinationIp: varchar("destinationIp", { length: 64 }).notNull(), destinationPort: int("destinationPort").notNull(), transportProtocol: varchar("transportProtocol", { length: 16 }).notNull(), riskScore: double("riskScore").notNull(), predictedClass: varchar("predictedClass", { length: 32 }).default("unlabeled").notNull(), classScoresJson: text("classScoresJson").notNull(), reasonsJson: text("reasonsJson").notNull(), featureJson: text("featureJson").notNull(), nfstreamJson: text("nfstreamJson"), createdAt: timestamp("createdAt").defaultNow().notNull(),
});

export const operationLogs = mysqlTable("operationLogs", {
  id: int("id").autoincrement().primaryKey(),
  userId: int("userId").notNull(),
  action: varchar("action", { length: 64 }).notNull(),
  entityType: varchar("entityType", { length: 64 }).notNull(),
  entityId: int("entityId"),
  summary: varchar("summary", { length: 255 }).notNull(),
  metadataJson: text("metadataJson").notNull(),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
});

export const apiKeys = mysqlTable("apiKeys", {
  id: int("id").autoincrement().primaryKey(), userId: int("userId").notNull(), name: varchar("name", { length: 80 }).notNull(), keyPrefix: varchar("keyPrefix", { length: 16 }).notNull(), keyHash: varchar("keyHash", { length: 64 }).notNull(), isActive: boolean("isActive").default(true).notNull(), lastUsedAt: timestamp("lastUsedAt"), createdAt: timestamp("createdAt").defaultNow().notNull(),
});

export const annotationSets = mysqlTable("annotationSets", {
  id: int("id").autoincrement().primaryKey(),
  userId: int("userId").notNull(),
  name: varchar("name", { length: 96 }).notNull(),
  description: varchar("description", { length: 255 }),
  labelsJson: text("labelsJson").notNull(),
  isActive: boolean("isActive").default(true).notNull(),
  isDefault: boolean("isDefault").default(false).notNull(),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
  updatedAt: timestamp("updatedAt").defaultNow().onUpdateNow().notNull(),
}, table => [uniqueIndex("annotation_sets_user_name_idx").on(table.userId, table.name)]);

export type User = typeof users.$inferSelect;
export type InsertUser = typeof users.$inferInsert;
