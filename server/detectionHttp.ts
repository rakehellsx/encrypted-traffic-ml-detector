import type { Express, Request, Response } from "express";
import multer from "multer";
import { inspectPcap } from "./detectionService";
import { resolveApiKey } from "./db";

const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 20 * 1024 * 1024, files: 1 } });

function respondError(response: Response, status: number, code: string, message: string) {
  response.status(status).json({ error: { code, message } });
}

export function registerDetectionHttp(app: Express) {
  app.get("/api/v1/detect/health", (_request, response) => response.json({ status: "ok", service: "trafficguard-pcap-detect", version: "v1" }));
  app.post("/api/v1/detect", upload.single("pcap"), async (request: Request, response: Response) => {
    try {
      const apiKey = request.header("x-api-key");
      if (!apiKey) return respondError(response, 401, "API_KEY_REQUIRED", "请在 x-api-key 请求头中提供接口密钥");
      const credential = await resolveApiKey(apiKey);
      if (!credential) return respondError(response, 401, "API_KEY_INVALID", "接口密钥无效或已失效");
      if (!request.file) return respondError(response, 400, "PCAP_REQUIRED", "请使用 multipart/form-data 的 pcap 字段上传 PCAP 文件");
      const modelId = request.body.modelId ? Number(request.body.modelId) : undefined;
      if (request.body.modelId && (!Number.isInteger(modelId) || !modelId || modelId < 1)) return respondError(response, 400, "MODEL_ID_INVALID", "modelId 必须为正整数");
      const result = await inspectPcap(credential.userId, request.file.originalname || "upload.pcap", request.file.buffer, modelId);
      return response.status(200).json({ requestId: crypto.randomUUID(), ...result, flows: result.flows.slice(0, 1000) });
    } catch (error) {
      const message = error instanceof Error ? error.message : "检测服务发生未知错误";
      const status = message.includes("模型") ? 422 : 500;
      return respondError(response, status, status === 422 ? "MODEL_UNAVAILABLE" : "DETECTION_FAILED", message);
    }
  });
}
