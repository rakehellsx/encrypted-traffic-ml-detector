import { z } from "zod";
import { COOKIE_NAME } from "@shared/const";
import { getSessionCookieOptions } from "./_core/cookies";
import { systemRouter } from "./_core/systemRouter";
import { protectedProcedure, publicProcedure, router } from "./_core/trpc";
import {
  activateModel,
  createDataset,
  createUploadTask,
  createDetectionTask,
  createModel,
  createTrainingJob,
  dashboard,
  deleteDataset,
  getDataset,
  getDetectionTask,
  getModel,
  getTrainingJob,
  getUploadTask,
  getTrainingSamples,
  insertDetectionFlows,
  insertFlowFeatures,
  listDatasetFeatures,
  listDatasets,
  listDetectionTasks,
  listModels,
  updateDatasetLabel,
  updateTrainingJob,
  updateUploadTask,
} from "./db";
import { FEATURE_OPTIONS, scoreModel, trainModel, type FeatureName, type ModelAlgorithm, type StoredModelPayload } from "./modelEngine";
import { storageGetSignedUrl, storagePut } from "./storage";
import { analyzePcap } from "./trafficAnalysis";

const MAX_UPLOAD_BYTES = 20 * 1024 * 1024;
const labels = z.enum(["benign", "malicious", "unlabeled"]);
const algorithms = z.enum(["logistic_regression", "gaussian_nb"]);
const featureNames = z.enum(FEATURE_OPTIONS);

function decodePcap(base64: string) {
  const encoded = base64.includes(",") ? base64.split(",").at(-1)! : base64;
  const buffer = Buffer.from(encoded, "base64");
  if (!buffer.length) throw new Error("上传内容为空");
  if (buffer.length > MAX_UPLOAD_BYTES) throw new Error("单个 PCAP 文件不能超过 20 MB");
  return buffer;
}

function safeName(name: string) {
  return name.replace(/[^a-zA-Z0-9._-]/g, "_").slice(0, 160) || "capture.pcap";
}

export const appRouter = router({
  system: systemRouter,
  auth: router({
    me: publicProcedure.query(opts => opts.ctx.user),
    logout: publicProcedure.mutation(({ ctx }) => {
      const cookieOptions = getSessionCookieOptions(ctx.req);
      ctx.res.clearCookie(COOKIE_NAME, { ...cookieOptions, maxAge: -1 });
      return { success: true } as const;
    }),
  }),
  dashboard: router({ overview: protectedProcedure.query(({ ctx }) => dashboard(ctx.user.id)) }),
  datasets: router({
    list: protectedProcedure.query(({ ctx }) => listDatasets(ctx.user.id)),
    uploadJob: protectedProcedure.input(z.object({ jobId: z.number().int().positive() })).query(({ ctx, input }) => getUploadTask(ctx.user.id, input.jobId)),
    createUploadJob: protectedProcedure.input(z.object({ name: z.string().min(1).max(255), fileBase64: z.string().min(20), label: labels.default("unlabeled") })).mutation(async ({ ctx, input }) => {
      const buffer = decodePcap(input.fileBase64);
      const stored = await storagePut(`pcaps/user-${ctx.user.id}/${safeName(input.name)}`, buffer, "application/vnd.tcpdump.pcap");
      return createUploadTask({ userId: ctx.user.id, fileName: input.name, storageKey: stored.key, fileSize: buffer.length, label: input.label });
    }),
    processUploadJob: protectedProcedure.input(z.object({ jobId: z.number().int().positive() })).mutation(async ({ ctx, input }) => {
      const job = await getUploadTask(ctx.user.id, input.jobId);
      if (!job || job.status !== "queued") throw new Error("上传解析任务不存在、无访问权限或已被处理");
      try {
        await updateUploadTask(job.id, { status: "processing", progress: 15 });
        const signedUrl = await storageGetSignedUrl(job.storageKey);
        const response = await fetch(signedUrl);
        if (!response.ok) throw new Error("无法读取已上传的 PCAP 文件");
        const buffer = Buffer.from(await response.arrayBuffer());
        const analysis = analyzePcap(buffer);
        await updateUploadTask(job.id, { status: "processing", progress: 55 });
        const datasetId = await createDataset({ userId: ctx.user.id, name: job.fileName, storageKey: job.storageKey, fileSize: job.fileSize, packetCount: analysis.packetCount, flowCount: analysis.flowCount, protocolDistribution: analysis.protocolDistribution, label: job.label });
        await updateUploadTask(job.id, { status: "processing", progress: 75, datasetId });
        await insertFlowFeatures(datasetId, analysis.flows);
        await updateUploadTask(job.id, { status: "completed", progress: 100, datasetId });
        return { datasetId, packetCount: analysis.packetCount, flowCount: analysis.flowCount, protocolDistribution: analysis.protocolDistribution };
      } catch (error) {
        await updateUploadTask(job.id, { status: "failed", progress: 100, errorMessage: error instanceof Error ? error.message : "PCAP 解析失败" });
        throw error;
      }
    }),
    upload: protectedProcedure.input(z.object({ name: z.string().min(1).max(255), fileBase64: z.string().min(20), label: labels.default("unlabeled") })).mutation(async ({ ctx, input }) => {
      const buffer = decodePcap(input.fileBase64);
      const analysis = analyzePcap(buffer);
      const stored = await storagePut(`pcaps/user-${ctx.user.id}/${safeName(input.name)}`, buffer, "application/vnd.tcpdump.pcap");
      const datasetId = await createDataset({ userId: ctx.user.id, name: input.name, storageKey: stored.key, fileSize: buffer.length, packetCount: analysis.packetCount, flowCount: analysis.flowCount, protocolDistribution: analysis.protocolDistribution, label: input.label });
      await insertFlowFeatures(datasetId, analysis.flows);
      return { datasetId, packetCount: analysis.packetCount, flowCount: analysis.flowCount, protocolDistribution: analysis.protocolDistribution };
    }),
    updateLabel: protectedProcedure.input(z.object({ datasetId: z.number().int().positive(), label: labels })).mutation(async ({ ctx, input }) => { await updateDatasetLabel(ctx.user.id, input.datasetId, input.label); return { success: true }; }),
    remove: protectedProcedure.input(z.object({ datasetId: z.number().int().positive() })).mutation(async ({ ctx, input }) => { await deleteDataset(ctx.user.id, input.datasetId); return { success: true }; }),
    features: protectedProcedure.input(z.object({ datasetId: z.number().int().positive() })).query(({ ctx, input }) => listDatasetFeatures(ctx.user.id, input.datasetId)),
    detail: protectedProcedure.input(z.object({ datasetId: z.number().int().positive() })).query(({ ctx, input }) => getDataset(ctx.user.id, input.datasetId)),
  }),
  models: router({
    list: protectedProcedure.query(({ ctx }) => listModels(ctx.user.id)),
    trainingJob: protectedProcedure.input(z.object({ jobId: z.number().int().positive() })).query(({ ctx, input }) => getTrainingJob(ctx.user.id, input.jobId)),
    activate: protectedProcedure.input(z.object({ modelId: z.number().int().positive() })).mutation(async ({ ctx, input }) => { await activateModel(ctx.user.id, input.modelId); return { success: true }; }),
    createTrainingJob: protectedProcedure.input(z.object({ datasetIds: z.array(z.number().int().positive()).min(2), features: z.array(featureNames).min(3), algorithm: algorithms })).mutation(({ ctx, input }) => createTrainingJob({ userId: ctx.user.id, algorithm: input.algorithm as ModelAlgorithm, datasetIds: input.datasetIds, featureSet: input.features as FeatureName[] })),
    train: protectedProcedure.input(z.object({ jobId: z.number().int().positive(), datasetIds: z.array(z.number().int().positive()).min(2), features: z.array(featureNames).min(3), algorithm: algorithms })).mutation(async ({ ctx, input }) => {
      const job = await getTrainingJob(ctx.user.id, input.jobId);
      if (!job || job.status !== "running") throw new Error("训练任务不存在、无访问权限或已结束");
      const jobId = job.id;
      try {
        await updateTrainingJob(jobId, { status: "running", progress: 30 });
        const samples = await getTrainingSamples(ctx.user.id, input.datasetIds);
        await updateTrainingJob(jobId, { status: "running", progress: 60 });
        const trained = trainModel(samples, input.features as FeatureName[], input.algorithm as ModelAlgorithm);
        const models = await listModels(ctx.user.id);
        const versionName = `v${models.length + 1}.${new Date().toISOString().slice(0, 10).replace(/-/g, "")}`;
        const modelId = await createModel({ userId: ctx.user.id, versionName, algorithm: input.algorithm as ModelAlgorithm, featureSet: input.features as FeatureName[], metrics: trained.metrics, payload: trained.payload, datasetIds: input.datasetIds, isActive: models.length === 0 });
        await updateTrainingJob(jobId, { status: "completed", progress: 100, modelVersionId: modelId });
        return { jobId, modelId, versionName, metrics: trained.metrics, trainingCount: trained.trainingCount, validationCount: trained.validationCount };
      } catch (error) {
        await updateTrainingJob(jobId, { status: "failed", progress: 100, errorMessage: error instanceof Error ? error.message : "训练失败" });
        throw error;
      }
    }),
  }),
  detections: router({
    list: protectedProcedure.query(({ ctx }) => listDetectionTasks(ctx.user.id)),
    detail: protectedProcedure.input(z.object({ taskId: z.number().int().positive() })).query(({ ctx, input }) => getDetectionTask(ctx.user.id, input.taskId)),
    analyze: protectedProcedure.input(z.object({ name: z.string().min(1).max(255), fileBase64: z.string().min(20), modelId: z.number().int().positive() })).mutation(async ({ ctx, input }) => {
      const model = await getModel(ctx.user.id, input.modelId);
      if (!model) throw new Error("选择的模型不存在或无访问权限");
      const buffer = decodePcap(input.fileBase64);
      const analysis = analyzePcap(buffer);
      const payload = JSON.parse(model.modelJson) as StoredModelPayload;
      const features = JSON.parse(model.featureSetJson) as FeatureName[];
      const scored = analysis.flows.map(flow => ({ flow, ...scoreModel(flow, features, payload) }));
      const stored = await storagePut(`detections/user-${ctx.user.id}/${safeName(input.name)}`, buffer, "application/vnd.tcpdump.pcap");
      const highRiskFlows = scored.filter(item => item.score >= 0.7).length;
      const averageRisk = scored.reduce((sum, item) => sum + item.score, 0) / Math.max(1, scored.length);
      const summary = { packetCount: analysis.packetCount, flowCount: analysis.flowCount, protocolDistribution: analysis.protocolDistribution, highRiskFlows, averageRisk, modelVersion: model.versionName };
      const taskId = await createDetectionTask({ userId: ctx.user.id, modelVersionId: model.id, fileName: input.name, storageKey: stored.key, totalFlows: scored.length, highRiskFlows, averageRisk, summary });
      await insertDetectionFlows(taskId, scored.slice(0, 1000));
      return { taskId, summary, topFlows: scored.sort((a, b) => b.score - a.score).slice(0, 10) };
    }),
  }),
});

export type AppRouter = typeof appRouter;
