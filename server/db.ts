import { and, desc, eq, inArray } from "drizzle-orm";
import { createHash, randomBytes } from "node:crypto";
import { drizzle } from "drizzle-orm/mysql2";
import {
  apiKeys,
  datasets,
  detectionFlows,
  detectionTasks,
  flowFeatures,
  InsertUser,
  modelVersions,
  trainingJobs,
  uploadTasks,
  users,
} from "../drizzle/schema";
import { ENV } from "./_core/env";
import type { FeatureName, ModelAlgorithm, TrafficClass } from "./modelEngine";
import type { FlowFeature } from "./trafficAnalysis";

let _db: ReturnType<typeof drizzle> | null = null;

export async function getDb() {
  if (!_db && process.env.DATABASE_URL) {
    try { _db = drizzle(process.env.DATABASE_URL); } catch (error) { console.warn("[Database] Failed to connect:", error); }
  }
  return _db;
}

async function requiredDb() {
  const db = await getDb();
  if (!db) throw new Error("数据库当前不可用，请稍后重试");
  return db;
}

export async function upsertUser(user: InsertUser): Promise<void> {
  if (!user.openId) throw new Error("User openId is required for upsert");
  const db = await getDb();
  if (!db) return;
  const values: InsertUser = { openId: user.openId, lastSignedIn: user.lastSignedIn ?? new Date() };
  const updateSet: Record<string, unknown> = { lastSignedIn: values.lastSignedIn };
  (["name", "email", "loginMethod"] as const).forEach(field => {
    if (user[field] !== undefined) { values[field] = user[field] ?? null; updateSet[field] = user[field] ?? null; }
  });
  values.role = user.role ?? (user.openId === ENV.ownerOpenId ? "admin" : "user");
  updateSet.role = values.role;
  await db.insert(users).values(values).onDuplicateKeyUpdate({ set: updateSet });
}

export async function getUserByOpenId(openId: string) {
  const db = await getDb();
  if (!db) return undefined;
  const result = await db.select().from(users).where(eq(users.openId, openId)).limit(1);
  return result[0];
}

function legacyLabel(trafficClass: TrafficClass | "unlabeled") {
  return trafficClass === "benign" ? "benign" : trafficClass === "unlabeled" ? "unlabeled" : "malicious";
}

export async function createDataset(input: { userId: number; name: string; storageKey: string; fileSize: number; packetCount: number; flowCount: number; protocolDistribution: Record<string, number>; trafficClass: TrafficClass | "unlabeled" }) {
  const db = await requiredDb();
  const inserted = await db.insert(datasets).values({ ...input, label: legacyLabel(input.trafficClass), protocolJson: JSON.stringify(input.protocolDistribution) });
  return Number(inserted[0].insertId);
}

export async function createUploadTask(input: { userId: number; fileName: string; storageKey: string; fileSize: number; trafficClass: TrafficClass | "unlabeled" }) {
  const db = await requiredDb();
  const result = await db.insert(uploadTasks).values({ ...input, label: legacyLabel(input.trafficClass) });
  return Number(result[0].insertId);
}

export async function getUploadTask(userId: number, taskId: number) {
  const db = await requiredDb();
  const rows = await db.select().from(uploadTasks).where(and(eq(uploadTasks.id, taskId), eq(uploadTasks.userId, userId))).limit(1);
  return rows[0];
}

export async function updateUploadTask(taskId: number, values: { status?: "queued" | "processing" | "completed" | "failed"; progress?: number; datasetId?: number; errorMessage?: string }) {
  const db = await requiredDb();
  await db.update(uploadTasks).set(values).where(eq(uploadTasks.id, taskId));
}

export async function insertFlowFeatures(datasetId: number, flows: FlowFeature[]) {
  const db = await requiredDb();
  for (let offset = 0; offset < flows.length; offset += 400) {
    await db.insert(flowFeatures).values(flows.slice(offset, offset + 400).map(flow => ({
      datasetId,
      flowKey: flow.flowKey,
      sourceIp: flow.sourceIp,
      sourcePort: flow.sourcePort,
      destinationIp: flow.destinationIp,
      destinationPort: flow.destinationPort,
      transportProtocol: flow.transportProtocol,
      applicationProtocol: flow.applicationProtocol,
      packetCount: flow.packetCount,
      byteCount: flow.byteCount,
      upPackets: flow.upPackets,
      downPackets: flow.downPackets,
      upBytes: flow.upBytes,
      downBytes: flow.downBytes,
      durationMs: flow.durationMs,
      avgPacketLength: flow.avgPacketLength,
      stdPacketLength: flow.stdPacketLength,
      avgIatMs: flow.avgIatMs,
      stdIatMs: flow.stdIatMs,
      uplinkRatio: flow.uplinkRatio,
      spltJson: JSON.stringify(flow.splt),
      tlsVersion: flow.tlsVersion,
      ja3: flow.ja3,
      sniVisibility: flow.sniVisibility,
      sni: flow.sni,
    })));
  }
}

export async function listDatasets(userId: number) {
  const db = await requiredDb();
  return db.select().from(datasets).where(eq(datasets.userId, userId)).orderBy(desc(datasets.createdAt));
}

export async function getDataset(userId: number, datasetId: number) {
  const db = await requiredDb();
  const rows = await db.select().from(datasets).where(and(eq(datasets.id, datasetId), eq(datasets.userId, userId))).limit(1);
  return rows[0];
}

export async function updateDatasetLabel(userId: number, datasetId: number, trafficClass: TrafficClass | "unlabeled") {
  const db = await requiredDb();
  await db.update(datasets).set({ trafficClass, label: legacyLabel(trafficClass) }).where(and(eq(datasets.id, datasetId), eq(datasets.userId, userId)));
}

export async function deleteDataset(userId: number, datasetId: number) {
  const db = await requiredDb();
  const dataset = await getDataset(userId, datasetId);
  if (!dataset) throw new Error("数据集不存在或无访问权限");
  await db.delete(flowFeatures).where(eq(flowFeatures.datasetId, datasetId));
  await db.delete(datasets).where(and(eq(datasets.id, datasetId), eq(datasets.userId, userId)));
}

export async function listDatasetFeatures(userId: number, datasetId: number, limit = 50) {
  const dataset = await getDataset(userId, datasetId);
  if (!dataset) throw new Error("数据集不存在或无访问权限");
  const db = await requiredDb();
  return db.select().from(flowFeatures).where(eq(flowFeatures.datasetId, datasetId)).limit(limit);
}

function toFlowFeature(row: typeof flowFeatures.$inferSelect): FlowFeature {
  return {
    flowKey: row.flowKey,
    sourceIp: row.sourceIp,
    sourcePort: row.sourcePort,
    destinationIp: row.destinationIp,
    destinationPort: row.destinationPort,
    transportProtocol: row.transportProtocol as "TCP" | "UDP",
    applicationProtocol: row.applicationProtocol as "TLS" | "QUIC" | "UNKNOWN",
    packetCount: row.packetCount,
    byteCount: row.byteCount,
    upPackets: row.upPackets,
    downPackets: row.downPackets,
    upBytes: row.upBytes,
    downBytes: row.downBytes,
    durationMs: row.durationMs,
    avgPacketLength: row.avgPacketLength,
    stdPacketLength: row.stdPacketLength,
    avgIatMs: row.avgIatMs,
    stdIatMs: row.stdIatMs,
    uplinkRatio: row.uplinkRatio,
    splt: JSON.parse(row.spltJson),
    tlsVersion: row.tlsVersion,
    ja3: row.ja3,
    sniVisibility: row.sniVisibility,
    sni: row.sni,
  };
}

export async function getTrainingSamples(userId: number, datasetIds: number[]) {
  const db = await requiredDb();
  const owned = await db.select().from(datasets).where(and(eq(datasets.userId, userId), inArray(datasets.id, datasetIds)));
  if (owned.length !== datasetIds.length) throw new Error("训练数据集中存在无权限或不存在的记录");
  const labels = new Map(owned.map(dataset => [dataset.id, dataset.trafficClass]));
  if (Array.from(owned).some(dataset => dataset.trafficClass === "unlabeled")) throw new Error("训练集不能包含未标注数据");
  const rows = await db.select().from(flowFeatures).where(inArray(flowFeatures.datasetId, datasetIds));
  return rows.map(row => ({ flow: toFlowFeature(row), label: labels.get(row.datasetId) as TrafficClass }));
}

export async function createTrainingJob(input: { userId: number; algorithm: ModelAlgorithm; datasetIds: number[]; featureSet: FeatureName[]; classSet: TrafficClass[] }) {
  const db = await requiredDb();
  const result = await db.insert(trainingJobs).values({ userId: input.userId, algorithm: input.algorithm, datasetIdsJson: JSON.stringify(input.datasetIds), featureSetJson: JSON.stringify(input.featureSet), classSetJson: JSON.stringify(input.classSet), progress: 10 });
  return Number(result[0].insertId);
}

export async function updateTrainingJob(jobId: number, values: { status?: "running" | "completed" | "failed"; progress?: number; modelVersionId?: number; errorMessage?: string }) {
  const db = await requiredDb();
  await db.update(trainingJobs).set(values).where(eq(trainingJobs.id, jobId));
}

export async function getTrainingJob(userId: number, jobId: number) {
  const db = await requiredDb();
  const rows = await db.select().from(trainingJobs).where(and(eq(trainingJobs.id, jobId), eq(trainingJobs.userId, userId))).limit(1);
  return rows[0];
}

export async function createModel(input: { userId: number; versionName: string; algorithm: ModelAlgorithm; featureSet: FeatureName[]; classSet: TrafficClass[]; metrics: unknown; payload: unknown; datasetIds: number[]; isActive: boolean }) {
  const db = await requiredDb();
  const result = await db.insert(modelVersions).values({
    userId: input.userId,
    versionName: input.versionName,
    algorithm: input.algorithm,
    featureSetJson: JSON.stringify(input.featureSet),
    classSetJson: JSON.stringify(input.classSet),
    metricsJson: JSON.stringify(input.metrics),
    modelJson: JSON.stringify(input.payload),
    trainedDatasetIdsJson: JSON.stringify(input.datasetIds),
    isActive: input.isActive,
  });
  return Number(result[0].insertId);
}

export async function listModels(userId: number) {
  const db = await requiredDb();
  return db.select().from(modelVersions).where(eq(modelVersions.userId, userId)).orderBy(desc(modelVersions.createdAt));
}

export async function getModel(userId: number, modelId: number) {
  const db = await requiredDb();
  const rows = await db.select().from(modelVersions).where(and(eq(modelVersions.id, modelId), eq(modelVersions.userId, userId))).limit(1);
  return rows[0];
}

export async function getActiveModel(userId: number) {
  const db = await requiredDb();
  const rows = await db.select().from(modelVersions).where(and(eq(modelVersions.userId, userId), eq(modelVersions.isActive, true))).limit(1);
  return rows[0];
}

export async function activateModel(userId: number, modelId: number) {
  const db = await requiredDb();
  const model = await getModel(userId, modelId);
  if (!model) throw new Error("模型不存在或无访问权限");
  await db.update(modelVersions).set({ isActive: false }).where(eq(modelVersions.userId, userId));
  await db.update(modelVersions).set({ isActive: true }).where(eq(modelVersions.id, modelId));
}

export async function createApiKey(userId: number, name: string) {
  const rawKey = `tg_${randomBytes(24).toString("base64url")}`;
  const db = await requiredDb();
  const result = await db.insert(apiKeys).values({ userId, name, keyPrefix: rawKey.slice(0, 12), keyHash: createHash("sha256").update(rawKey).digest("hex") });
  return { id: Number(result[0].insertId), rawKey, keyPrefix: rawKey.slice(0, 12), name };
}

export async function listApiKeys(userId: number) {
  const db = await requiredDb();
  return db.select({ id: apiKeys.id, name: apiKeys.name, keyPrefix: apiKeys.keyPrefix, isActive: apiKeys.isActive, lastUsedAt: apiKeys.lastUsedAt, createdAt: apiKeys.createdAt }).from(apiKeys).where(eq(apiKeys.userId, userId)).orderBy(desc(apiKeys.createdAt));
}

export async function resolveApiKey(rawKey: string) {
  const db = await requiredDb();
  const hash = createHash("sha256").update(rawKey).digest("hex");
  const rows = await db.select().from(apiKeys).where(and(eq(apiKeys.keyHash, hash), eq(apiKeys.isActive, true))).limit(1);
  if (!rows[0]) return undefined;
  await db.update(apiKeys).set({ lastUsedAt: new Date() }).where(eq(apiKeys.id, rows[0].id));
  return rows[0];
}

export async function revokeApiKey(userId: number, apiKeyId: number) {
  const db = await requiredDb();
  await db.update(apiKeys).set({ isActive: false }).where(and(eq(apiKeys.id, apiKeyId), eq(apiKeys.userId, userId)));
}

export async function createDetectionTask(input: { userId: number; modelVersionId: number; fileName: string; storageKey: string; totalFlows: number; highRiskFlows: number; averageRisk: number; summary: unknown }) {
  const db = await requiredDb();
  const result = await db.insert(detectionTasks).values({ ...input, summaryJson: JSON.stringify(input.summary) });
  return Number(result[0].insertId);
}

export async function insertDetectionFlows(taskId: number, flows: Array<{ flow: FlowFeature; score: number; predictedClass: TrafficClass; classScores: Record<string, number>; reasons: string[]; featureValues: Record<string, number> }>) {
  const db = await requiredDb();
  for (let offset = 0; offset < flows.length; offset += 400) {
    await db.insert(detectionFlows).values(flows.slice(offset, offset + 400).map(entry => ({
      taskId,
      flowKey: entry.flow.flowKey,
      sourceIp: entry.flow.sourceIp,
      sourcePort: entry.flow.sourcePort,
      destinationIp: entry.flow.destinationIp,
      destinationPort: entry.flow.destinationPort,
      transportProtocol: entry.flow.transportProtocol,
      riskScore: entry.score,
      predictedClass: entry.predictedClass,
      classScoresJson: JSON.stringify(entry.classScores),
      reasonsJson: JSON.stringify(entry.reasons),
      featureJson: JSON.stringify(entry.featureValues),
    })));
  }
}

export async function listDetectionTasks(userId: number) {
  const db = await requiredDb();
  return db.select().from(detectionTasks).where(eq(detectionTasks.userId, userId)).orderBy(desc(detectionTasks.createdAt));
}

export async function getDetectionTask(userId: number, taskId: number) {
  const db = await requiredDb();
  const tasks = await db.select().from(detectionTasks).where(and(eq(detectionTasks.id, taskId), eq(detectionTasks.userId, userId))).limit(1);
  if (!tasks[0]) return undefined;
  const flows = await db.select().from(detectionFlows).where(eq(detectionFlows.taskId, taskId)).orderBy(desc(detectionFlows.riskScore)).limit(1000);
  return { task: tasks[0], flows };
}

export async function dashboard(userId: number) {
  const [datasetRows, modelRows, taskRows] = await Promise.all([listDatasets(userId), listModels(userId), listDetectionTasks(userId)]);
  return { datasetCount: datasetRows.length, modelCount: modelRows.length, detectionCount: taskRows.length, recentTasks: taskRows.slice(0, 5), activeModel: modelRows.find(model => model.isActive) ?? null };
}
