import { and, eq, inArray } from "drizzle-orm";
import { appRouter } from "../server/routers";
import { getDb } from "../server/db";
import { datasets, detectionFlows, detectionTasks, flowFeatures, modelVersions, trainingJobs, uploadTasks, users } from "../drizzle/schema";

function tcpFrame(index: number, payloadLength: number) {
  const frame = Buffer.alloc(14 + 20 + 20 + payloadLength);
  frame.writeUInt16BE(0x0800, 12);
  frame[14] = 0x45;
  frame.writeUInt16BE(20 + 20 + payloadLength, 16);
  frame[23] = 6;
  [10, 20, 0, index + 1].forEach((value, offset) => { frame[26 + offset] = value; });
  [198, 51, 100, 25].forEach((value, offset) => { frame[30 + offset] = value; });
  frame.writeUInt16BE(43000 + index, 34);
  frame.writeUInt16BE(443, 36);
  frame[46] = 0x50;
  for (let offset = 0; offset < payloadLength; offset += 1) frame[54 + offset] = (index * 13 + offset) % 255;
  return frame;
}

function pcap(payloadLength: number) {
  const header = Buffer.alloc(24);
  header.writeUInt32LE(0xa1b2c3d4, 0);
  header.writeUInt16LE(2, 4);
  header.writeUInt16LE(4, 6);
  header.writeUInt32LE(65535, 16);
  header.writeUInt32LE(1, 20);
  const records: Buffer[] = [];
  for (let index = 0; index < 5; index += 1) {
    const frame = tcpFrame(index, payloadLength + index * 4);
    const packetHeader = Buffer.alloc(16);
    packetHeader.writeUInt32LE(1710000100 + index, 0);
    packetHeader.writeUInt32LE(index * 200000, 4);
    packetHeader.writeUInt32LE(frame.length, 8);
    packetHeader.writeUInt32LE(frame.length, 12);
    records.push(packetHeader, frame);
  }
  return Buffer.concat([header, ...records]);
}

function asDataUrl(buffer: Buffer) {
  return `data:application/vnd.tcpdump.pcap;base64,${buffer.toString("base64")}`;
}

async function main() {
  const db = await getDb();
  if (!db) throw new Error("E2E 验证需要数据库连接");
  const existingUsers = await db.select().from(users).limit(1);
  if (!existingUsers[0]) throw new Error("E2E 验证需要已登录的应用用户");
  const user = existingUsers[0];
  const caller = appRouter.createCaller({ user, req: {} as any, res: {} as any });
  const suffix = Date.now();
  const createdDatasetIds: number[] = [];
  const createdJobIds: number[] = [];
  let modelId: number | null = null;
  let taskId: number | null = null;
  try {
    const uploadAndProcess = async (label: "benign" | "malicious", payloadLength: number) => {
      const jobId = await caller.datasets.createUploadJob({ name: `e2e-${label}-${suffix}.pcap`, fileBase64: asDataUrl(pcap(payloadLength)), label });
      createdJobIds.push(jobId);
      const queued = await caller.datasets.uploadJob({ jobId });
      if (queued?.status !== "queued") throw new Error(`上传任务未进入 queued 状态：${queued?.status}`);
      const processed = await caller.datasets.processUploadJob({ jobId });
      createdDatasetIds.push(processed.datasetId);
      const completed = await caller.datasets.uploadJob({ jobId });
      if (completed?.status !== "completed" || completed.progress !== 100) throw new Error("PCAP 解析任务没有完成");
      return processed.datasetId;
    };

    const benignDatasetId = await uploadAndProcess("benign", 24);
    const maliciousDatasetId = await uploadAndProcess("malicious", 1100);
    const trainingJobId = await caller.models.createTrainingJob({ datasetIds: [benignDatasetId, maliciousDatasetId], features: ["packetCount", "byteCount", "avgPacketLength", "uplinkRatio"], algorithm: "logistic_regression" });
    createdJobIds.push(trainingJobId);
    const trained = await caller.models.train({ jobId: trainingJobId, datasetIds: [benignDatasetId, maliciousDatasetId], features: ["packetCount", "byteCount", "avgPacketLength", "uplinkRatio"], algorithm: "logistic_regression" });
    modelId = trained.modelId;
    await caller.models.activate({ modelId });
    const analyzed = await caller.detections.analyze({ name: `e2e-detection-${suffix}.pcap`, fileBase64: asDataUrl(pcap(1400)), modelId });
    taskId = analyzed.taskId;
    const detail = await caller.detections.detail({ taskId });
    if (!detail || detail.task.totalFlows < 5 || !detail.flows.length) throw new Error("检测任务没有保存逐流结果");
    console.log(JSON.stringify({ uploadStatus: "completed", datasets: createdDatasetIds.length, modelVersion: trained.versionName, trainingF1: trained.metrics.f1, detectionTaskId: taskId, scoredFlows: detail.flows.length, highRiskFlows: analyzed.summary.highRiskFlows }, null, 2));
  } finally {
    if (taskId) {
      await db.delete(detectionFlows).where(eq(detectionFlows.taskId, taskId));
      await db.delete(detectionTasks).where(eq(detectionTasks.id, taskId));
    }
    if (modelId) await db.delete(modelVersions).where(and(eq(modelVersions.id, modelId), eq(modelVersions.userId, user.id)));
    if (createdJobIds.length) await db.delete(trainingJobs).where(inArray(trainingJobs.id, createdJobIds));
    if (createdDatasetIds.length) {
      await db.delete(flowFeatures).where(inArray(flowFeatures.datasetId, createdDatasetIds));
      await db.delete(datasets).where(and(eq(datasets.userId, user.id), inArray(datasets.id, createdDatasetIds)));
    }
    if (createdJobIds.length) await db.delete(uploadTasks).where(and(eq(uploadTasks.userId, user.id), inArray(uploadTasks.id, createdJobIds)));
  }
}

main().then(() => process.exit(0)).catch(error => { console.error(error); process.exit(1); });
