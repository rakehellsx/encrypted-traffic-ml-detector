import type { Express, Request, Response } from "express";
import multer from "multer";
import { inspectPcap } from "./detectionService";
import { createDetectionTask, getModel, insertDetectionFlows, resolveApiKey } from "./db";
import { storagePut } from "./storage";

const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 20 * 1024 * 1024, files: 1 } });

function respondError(response: Response, status: number, code: string, message: string) {
  response.status(status).json({ error: { code, message } });
}

function bearerToken(request: Request) {
  const header = request.header("authorization")?.trim();
  if (!header) return null;
  const match = /^Bearer\s+(.+)$/i.exec(header);
  return match?.[1]?.trim() || null;
}

/** Public HTTP contract: POST /api/v1/detect, Authorization: Bearer <API_KEY>. */
export function registerDetectionHttp(app: Express) {
  app.get("/api/v1/detect/health", (_request, response) => response.json({ status: "ok", service: "encrypted-traffic-ml-detector", version: "v1", engine: "Abonnen/Malicious_TLS_Detection" }));
  app.post("/api/v1/detect", upload.single("file"), async (request: Request, response: Response) => {
    try {
      const apiKey = bearerToken(request);
      if (!apiKey) return respondError(response, 401, "API_KEY_REQUIRED", "请在 Authorization 请求头中提供 Bearer API Key");
      const credential = await resolveApiKey(apiKey);
      if (!credential) return respondError(response, 401, "API_KEY_INVALID", "API Key 无效或已失效");
      if (!request.file) return respondError(response, 400, "PCAP_REQUIRED", "请使用 multipart/form-data 的 file 字段上传 PCAP 文件");
      const modelVersionId = request.body.modelVersionId ? Number(request.body.modelVersionId) : undefined;
      if (request.body.modelVersionId && (!Number.isInteger(modelVersionId) || !modelVersionId || modelVersionId < 1)) return respondError(response, 400, "MODEL_VERSION_ID_INVALID", "modelVersionId 必须为正整数");
      const fileName = request.file.originalname || "upload.pcap";
      const result = await inspectPcap(credential.userId, fileName, request.file.buffer, modelVersionId);
      const model = await getModel(credential.userId, result.model.id);
      if (!model) return respondError(response, 422, "MODEL_UNAVAILABLE", "选择的模型不可用");
      const safeName = fileName.replace(/[^a-zA-Z0-9._-]/g, "_");
      const stored = await storagePut(`api-detections/public/${safeName}`, request.file.buffer, "application/vnd.tcpdump.pcap");
      const summary = { ...result.summary, modelVersion: model.versionName, modelVersionId: model.id, source: "http_api" };
      const taskId = await createDetectionTask({ userId: credential.userId, modelVersionId: model.id, fileName, storageKey: stored.key, totalFlows: result.scored.length, highRiskFlows: result.summary.highRiskFlows, averageRisk: result.summary.averageRisk, summary });
      await insertDetectionFlows(taskId, result.scored.slice(0, 1000).map((entry, index) => ({ ...entry, detail: result.flows[index] })));
      return response.status(200).json({
        requestId: crypto.randomUUID(),
        task: { id: taskId, fileName, modelVersionId: model.id, totalFlows: result.scored.length, highRiskFlows: result.summary.highRiskFlows, averageRisk: result.summary.averageRisk },
        summary,
        model: result.model,
        flows: result.flows.slice(0, 1000),
      });
    } catch (error) {
      const message = error instanceof Error ? error.message : "检测服务发生未知错误";
      const status = message.includes("模型") || message.includes("Abonnen") ? 422 : 500;
      return respondError(response, status, status === 422 ? "MODEL_UNAVAILABLE" : "DETECTION_FAILED", message);
    }
  });
}
