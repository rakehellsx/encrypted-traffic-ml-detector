import { and, count, desc, eq, inArray, like, or } from "drizzle-orm";
import { createHash, randomBytes } from "node:crypto";
import { drizzle } from "drizzle-orm/mysql2";
import {
  apiKeys,
  annotationSets,
  datasets,
  detectionFlows,
  detectionTasks,
  flowFeatures,
  InsertUser,
  modelVersions,
  operationLogs,
  trainingJobs,
  uploadTasks,
  users,
} from "../drizzle/schema";
import { ENV } from "./_core/env";
import type { FeatureName, ModelAlgorithm, TrafficClass } from "./modelEngine";
import type { FlowFeature } from "./trafficAnalysis";
import { DEFAULT_ANNOTATION_LABELS, type AnnotationLabel, type AnnotationSetSnapshot } from "@shared/annotationSets";

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

const PUBLIC_WORKSPACE_OPEN_ID = "trafficguard_public_workspace";

export async function getPublicWorkspaceUser() {
  let user = await getUserByOpenId(PUBLIC_WORKSPACE_OPEN_ID);
  if (!user) {
    await upsertUser({ openId: PUBLIC_WORKSPACE_OPEN_ID, name: "TrafficGuard 公共工作区", loginMethod: "public", role: "admin" });
    user = await getUserByOpenId(PUBLIC_WORKSPACE_OPEN_ID);
  }
  if (!user) throw new Error("公共工作区初始化失败，请稍后重试");
  return user;
}

function legacyLabel(trafficClass: TrafficClass | "unlabeled") {
  return trafficClass === "benign" ? "benign" : trafficClass === "unlabeled" ? "unlabeled" : "malicious";
}

function toAnnotationSnapshot(row: typeof annotationSets.$inferSelect): AnnotationSetSnapshot {
  return { id: row.id, name: row.name, description: row.description ?? undefined, labels: JSON.parse(row.labelsJson) as AnnotationLabel[], isActive: row.isActive, isDefault: row.isDefault };
}

export async function ensureDefaultAnnotationSet(userId: number) {
  const db = await requiredDb();
  const existing = await db.select().from(annotationSets).where(eq(annotationSets.userId, userId)).orderBy(desc(annotationSets.isDefault), desc(annotationSets.createdAt));
  if (existing.length) return existing;
  const result = await db.insert(annotationSets).values({ userId, name: "默认标注集", description: "内置的多分类标注定义，可复制后编辑", labelsJson: JSON.stringify(DEFAULT_ANNOTATION_LABELS), isDefault: true, isActive: true });
  const id = Number(result[0].insertId);
  await logOperation({ userId, action: "annotation_set.created", entityType: "annotation_set", entityId: id, summary: "已初始化默认标注集", metadata: { name: "默认标注集" } });
  return db.select().from(annotationSets).where(eq(annotationSets.userId, userId)).orderBy(desc(annotationSets.isDefault), desc(annotationSets.createdAt));
}

export async function listAnnotationSets(userId: number) { return (await ensureDefaultAnnotationSet(userId)).map(toAnnotationSnapshot); }
export async function getAnnotationSet(userId: number, annotationSetId?: number) {
  const sets = await ensureDefaultAnnotationSet(userId);
  const target = annotationSetId ? sets.find(set => set.id === annotationSetId) : sets.find(set => set.isDefault && set.isActive) ?? sets.find(set => set.isActive);
  if (!target || !target.isActive) throw new Error("标注集不存在或已停用");
  return toAnnotationSnapshot(target);
}
export async function createAnnotationSet(input: { userId: number; name: string; description?: string; labels: AnnotationLabel[]; isDefault?: boolean }) {
  const db = await requiredDb();
  if (input.isDefault) await db.update(annotationSets).set({ isDefault: false }).where(eq(annotationSets.userId, input.userId));
  const result = await db.insert(annotationSets).values({ userId: input.userId, name: input.name, description: input.description ?? null, labelsJson: JSON.stringify(input.labels), isDefault: Boolean(input.isDefault), isActive: true });
  const id = Number(result[0].insertId);
  await logOperation({ userId: input.userId, action: "annotation_set.created", entityType: "annotation_set", entityId: id, summary: `已创建标注集：${input.name}`, metadata: { labels: input.labels } });
  return id;
}
export async function updateAnnotationSet(input: { userId: number; id: number; name?: string; description?: string; labels?: AnnotationLabel[]; isActive?: boolean; isDefault?: boolean }) {
  const db = await requiredDb(); const current = (await db.select().from(annotationSets).where(and(eq(annotationSets.id, input.id), eq(annotationSets.userId, input.userId))).limit(1))[0]; if (!current) throw new Error("标注集不存在");
  if (input.isDefault) await db.update(annotationSets).set({ isDefault: false }).where(eq(annotationSets.userId, input.userId));
  const values: Record<string, unknown> = {}; if (input.name !== undefined) values.name = input.name; if (input.description !== undefined) values.description = input.description; if (input.labels !== undefined) values.labelsJson = JSON.stringify(input.labels); if (input.isActive !== undefined) values.isActive = input.isActive; if (input.isDefault !== undefined) values.isDefault = input.isDefault;
  await db.update(annotationSets).set(values).where(eq(annotationSets.id, input.id)); await logOperation({ userId: input.userId, action: "annotation_set.updated", entityType: "annotation_set", entityId: input.id, summary: `已更新标注集：${input.name ?? current.name}`, metadata: values });
}
export async function deleteAnnotationSet(userId: number, id: number) { const db = await requiredDb(); const current = (await db.select().from(annotationSets).where(and(eq(annotationSets.id, id), eq(annotationSets.userId, userId))).limit(1))[0]; if (!current) throw new Error("标注集不存在"); if (current.isDefault) throw new Error("默认标注集不能删除，请先设置其他默认集"); await db.delete(annotationSets).where(eq(annotationSets.id, id)); await logOperation({ userId, action: "annotation_set.deleted", entityType: "annotation_set", entityId: id, summary: `已删除标注集：${current.name}`, metadata: {} }); }

export async function createDataset(input: { userId: number; name: string; storageKey: string; fileSize: number; packetCount: number; flowCount: number; protocolDistribution: Record<string, number>; trafficClass: TrafficClass | "unlabeled"; annotationSetId?: number; annotationSnapshot?: AnnotationSetSnapshot }) {
  const db = await requiredDb();
  const inserted = await db.insert(datasets).values({ ...input, annotationSnapshotJson: input.annotationSnapshot ? JSON.stringify(input.annotationSnapshot) : null, label: legacyLabel(input.trafficClass), protocolJson: JSON.stringify(input.protocolDistribution) });
  const id = Number(inserted[0].insertId);
  await logOperation({ userId: input.userId, action: "dataset.created", entityType: "dataset", entityId: id, summary: `已保存训练数据集：${input.name}`, metadata: { trafficClass: input.trafficClass, annotationSetId: input.annotationSetId, packetCount: input.packetCount, flowCount: input.flowCount } });
  return id;
}

export async function createUploadTask(input: { userId: number; fileName: string; storageKey: string; fileSize: number; trafficClass: TrafficClass | "unlabeled"; annotationSetId?: number; annotationSnapshot?: AnnotationSetSnapshot }) {
  const db = await requiredDb();
  const result = await db.insert(uploadTasks).values({ ...input, annotationSnapshotJson: input.annotationSnapshot ? JSON.stringify(input.annotationSnapshot) : null, label: legacyLabel(input.trafficClass) });
  const id = Number(result[0].insertId);
  await logOperation({ userId: input.userId, action: "upload.created", entityType: "upload_task", entityId: id, summary: `已创建 PCAP 解析任务：${input.fileName}`, metadata: { trafficClass: input.trafficClass, annotationSetId: input.annotationSetId, fileSize: input.fileSize } });
  return id;
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
      nfstreamJson: flow.nfstream ? JSON.stringify(flow.nfstream) : null,
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

export async function updateDatasetLabel(userId: number, datasetId: number, trafficClass: TrafficClass | "unlabeled", annotationSet?: AnnotationSetSnapshot) {
  const db = await requiredDb();
  await db.update(datasets).set({ trafficClass, label: legacyLabel(trafficClass), annotationSetId: annotationSet?.id ?? null, annotationSnapshotJson: annotationSet ? JSON.stringify(annotationSet) : null }).where(and(eq(datasets.id, datasetId), eq(datasets.userId, userId)));
  await logOperation({ userId, action: "dataset.labeled", entityType: "dataset", entityId: datasetId, summary: `已更新训练数据集类别为：${trafficClass}`, metadata: { trafficClass, annotationSetId: annotationSet?.id } });
}

export async function deleteDataset(userId: number, datasetId: number) {
  const db = await requiredDb();
  const dataset = await getDataset(userId, datasetId);
  if (!dataset) throw new Error("数据集不存在或无访问权限");
  await db.delete(flowFeatures).where(eq(flowFeatures.datasetId, datasetId));
  await db.delete(datasets).where(and(eq(datasets.id, datasetId), eq(datasets.userId, userId)));
  await logOperation({ userId, action: "dataset.deleted", entityType: "dataset", entityId: datasetId, summary: `已删除训练数据集：${dataset.name}`, metadata: { name: dataset.name } });
}

export async function listDatasetFeatures(userId: number, datasetId: number, limit = 50) {
  const dataset = await getDataset(userId, datasetId);
  if (!dataset) throw new Error("数据集不存在或无访问权限");
  const db = await requiredDb();
  const rows = await db.select().from(flowFeatures).where(eq(flowFeatures.datasetId, datasetId)).limit(limit);
  return rows.map(row => ({ ...row, nfstream: row.nfstreamJson ? { ...JSON.parse(row.nfstreamJson), source: "nfstream" } : null }));
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
    nfstream: row.nfstreamJson ? { ...JSON.parse(row.nfstreamJson), source: "nfstream" } : null,
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

export async function createTrainingJob(input: { userId: number; algorithm: ModelAlgorithm; datasetIds: number[]; featureSet: FeatureName[]; classSet: TrafficClass[]; annotationSet: AnnotationSetSnapshot }) {
  const db = await requiredDb();
  const result = await db.insert(trainingJobs).values({ userId: input.userId, algorithm: input.algorithm, datasetIdsJson: JSON.stringify(input.datasetIds), featureSetJson: JSON.stringify(input.featureSet), classSetJson: JSON.stringify(input.classSet), annotationSetId: input.annotationSet.id ?? null, annotationSnapshotJson: JSON.stringify(input.annotationSet), progress: 10 });
  const id = Number(result[0].insertId);
  await logOperation({ userId: input.userId, action: "training.created", entityType: "training_job", entityId: id, summary: `已创建多分类训练任务（${input.classSet.length} 类）`, metadata: { algorithm: input.algorithm, datasetIds: input.datasetIds, classSet: input.classSet, annotationSet: input.annotationSet, featureSet: input.featureSet } });
  return id;
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

export async function createModel(input: { userId: number; versionName: string; algorithm: ModelAlgorithm; featureSet: FeatureName[]; classSet: TrafficClass[]; annotationSet: AnnotationSetSnapshot; metrics: unknown; payload: unknown; datasetIds: number[]; isActive: boolean }) {
  const db = await requiredDb();
  const result = await db.insert(modelVersions).values({
    userId: input.userId,
    versionName: input.versionName,
    algorithm: input.algorithm,
    featureSetJson: JSON.stringify(input.featureSet),
    classSetJson: JSON.stringify(input.classSet),
    annotationSetId: input.annotationSet.id ?? null,
    annotationSnapshotJson: JSON.stringify(input.annotationSet),
    metricsJson: JSON.stringify(input.metrics),
    modelJson: JSON.stringify(input.payload),
    trainedDatasetIdsJson: JSON.stringify(input.datasetIds),
    isActive: input.isActive,
  });
  const id = Number(result[0].insertId);
  await logOperation({ userId: input.userId, action: "model.created", entityType: "model_version", entityId: id, summary: `已保存模型版本：${input.versionName}`, metadata: { algorithm: input.algorithm, classSet: input.classSet, annotationSet: input.annotationSet, datasetIds: input.datasetIds, isActive: input.isActive } });
  return id;
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
  await logOperation({ userId, action: "model.activated", entityType: "model_version", entityId: modelId, summary: `已激活模型版本：${model.versionName}`, metadata: { versionName: model.versionName } });
}

export async function createApiKey(userId: number, name: string) {
  const rawKey = `tg_${randomBytes(24).toString("base64url")}`;
  const db = await requiredDb();
  const result = await db.insert(apiKeys).values({ userId, name, keyPrefix: rawKey.slice(0, 12), keyHash: createHash("sha256").update(rawKey).digest("hex") });
  const id = Number(result[0].insertId);
  await logOperation({ userId, action: "api_key.created", entityType: "api_key", entityId: id, summary: `已生成接口密钥：${name}`, metadata: { name, keyPrefix: rawKey.slice(0, 12) } });
  return { id, rawKey, keyPrefix: rawKey.slice(0, 12), name };
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
  await logOperation({ userId, action: "api_key.revoked", entityType: "api_key", entityId: apiKeyId, summary: "已撤销接口密钥", metadata: {} });
}

export async function createDetectionTask(input: { userId: number; modelVersionId: number; annotationSet?: AnnotationSetSnapshot; fileName: string; storageKey: string; totalFlows: number; highRiskFlows: number; averageRisk: number; summary: unknown }) {
  const db = await requiredDb();
  const result = await db.insert(detectionTasks).values({ ...input, annotationSetId: input.annotationSet?.id ?? null, annotationSnapshotJson: input.annotationSet ? JSON.stringify(input.annotationSet) : null, summaryJson: JSON.stringify(input.summary) });
  const id = Number(result[0].insertId);
  await logOperation({ userId: input.userId, action: "detection.completed", entityType: "detection_task", entityId: id, summary: `已完成检测任务：${input.fileName}`, metadata: { modelVersionId: input.modelVersionId, totalFlows: input.totalFlows, highRiskFlows: input.highRiskFlows, averageRisk: input.averageRisk } });
  return id;
}

export async function insertDetectionFlows(taskId: number, flows: Array<{ flow: FlowFeature; score: number; predictedClass: TrafficClass; classScores: Record<string, number>; reasons: string[]; featureValues: Record<string, number>; detail?: unknown }>) {
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
      featureJson: JSON.stringify({ featureValues: entry.featureValues, detail: entry.detail ?? null }),
      nfstreamJson: entry.flow.nfstream ? JSON.stringify(entry.flow.nfstream) : null,
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
  return { task: tasks[0], flows: flows.map(flow => ({ ...flow, featureDetail: JSON.parse(flow.featureJson), nfstream: flow.nfstreamJson ? { ...JSON.parse(flow.nfstreamJson), source: "nfstream" } : null, classScores: JSON.parse(flow.classScoresJson), reasons: JSON.parse(flow.reasonsJson) })) };
}

export async function dashboard(userId: number) {
  const [datasetRows, modelRows, taskRows] = await Promise.all([listDatasets(userId), listModels(userId), listDetectionTasks(userId)]);
  return { datasetCount: datasetRows.length, modelCount: modelRows.length, detectionCount: taskRows.length, recentTasks: taskRows.slice(0, 5), activeModel: modelRows.find(model => model.isActive) ?? null };
}

export async function logOperation(input: { userId: number; action: string; entityType: string; entityId?: number; summary: string; metadata: Record<string, unknown> }) {
  const db = await requiredDb();
  await db.insert(operationLogs).values({ ...input, entityId: input.entityId ?? null, metadataJson: JSON.stringify(input.metadata) });
}

export async function listOperationLogs(userId: number, limit = 200) {
  const db = await requiredDb();
  const rows = await db.select().from(operationLogs).where(eq(operationLogs.userId, userId)).orderBy(desc(operationLogs.createdAt)).limit(limit);
  return rows.map(row => ({ ...row, metadata: JSON.parse(row.metadataJson) }));
}

type PageInput = { page: number; pageSize: number; keyword?: string };

export async function listDatasetHistory(userId: number, input: PageInput) {
  const db = await requiredDb(); const keyword = input.keyword?.trim();
  const filter = keyword ? and(eq(datasets.userId, userId), or(like(datasets.name, `%${keyword}%`), like(datasets.trafficClass, `%${keyword}%`))) : eq(datasets.userId, userId);
  const [totalRow] = await db.select({ total: count() }).from(datasets).where(filter);
  const items = await db.select().from(datasets).where(filter).orderBy(desc(datasets.createdAt)).limit(input.pageSize).offset((input.page - 1) * input.pageSize);
  return { items, total: Number(totalRow?.total ?? 0), page: input.page, pageSize: input.pageSize };
}

export async function listModelHistory(userId: number, input: PageInput) {
  const db = await requiredDb(); const keyword = input.keyword?.trim();
  const filter = keyword ? and(eq(modelVersions.userId, userId), or(like(modelVersions.versionName, `%${keyword}%`), like(modelVersions.algorithm, `%${keyword}%`), like(modelVersions.classSetJson, `%${keyword}%`))) : eq(modelVersions.userId, userId);
  const [totalRow] = await db.select({ total: count() }).from(modelVersions).where(filter);
  const items = await db.select().from(modelVersions).where(filter).orderBy(desc(modelVersions.createdAt)).limit(input.pageSize).offset((input.page - 1) * input.pageSize);
  return { items, total: Number(totalRow?.total ?? 0), page: input.page, pageSize: input.pageSize };
}

export async function listDetectionHistory(userId: number, input: PageInput) {
  const db = await requiredDb(); const keyword = input.keyword?.trim();
  const filter = keyword ? and(eq(detectionTasks.userId, userId), or(like(detectionTasks.fileName, `%${keyword}%`), like(detectionTasks.status, `%${keyword}%`))) : eq(detectionTasks.userId, userId);
  const [totalRow] = await db.select({ total: count() }).from(detectionTasks).where(filter);
  const items = await db.select().from(detectionTasks).where(filter).orderBy(desc(detectionTasks.createdAt)).limit(input.pageSize).offset((input.page - 1) * input.pageSize);
  return { items, total: Number(totalRow?.total ?? 0), page: input.page, pageSize: input.pageSize };
}

export async function listOperationLogHistory(userId: number, input: PageInput) {
  const db = await requiredDb(); const keyword = input.keyword?.trim();
  const filter = keyword ? and(eq(operationLogs.userId, userId), or(like(operationLogs.action, `%${keyword}%`), like(operationLogs.summary, `%${keyword}%`), like(operationLogs.entityType, `%${keyword}%`))) : eq(operationLogs.userId, userId);
  const [totalRow] = await db.select({ total: count() }).from(operationLogs).where(filter);
  const rows = await db.select().from(operationLogs).where(filter).orderBy(desc(operationLogs.createdAt)).limit(input.pageSize).offset((input.page - 1) * input.pageSize);
  return { items: rows.map(row => ({ ...row, metadata: JSON.parse(row.metadataJson) })), total: Number(totalRow?.total ?? 0), page: input.page, pageSize: input.pageSize };
}

export async function exportDataset(userId: number, datasetId: number) {
  const dataset = await getDataset(userId, datasetId);
  if (!dataset) throw new Error("数据集不存在或无访问权限");
  const db = await requiredDb();
  const features = await db.select().from(flowFeatures).where(eq(flowFeatures.datasetId, datasetId));
  return { dataset: { ...dataset, protocolDistribution: JSON.parse(dataset.protocolJson) }, flowFeatures: features.map(toFlowFeature) };
}

export async function exportModel(userId: number, modelId: number) {
  const model = await getModel(userId, modelId);
  if (!model) throw new Error("模型不存在或无访问权限");
  return { ...model, featureSet: JSON.parse(model.featureSetJson), classSet: JSON.parse(model.classSetJson), metrics: JSON.parse(model.metricsJson), trainedDatasetIds: JSON.parse(model.trainedDatasetIdsJson), payload: JSON.parse(model.modelJson) };
}
