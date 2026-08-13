import type { FlowFeature } from "./trafficAnalysis";
import { runOpenSourceMl } from "./openSourceMl";

export const FEATURE_OPTIONS = ["packetCount", "byteCount", "durationMs", "avgPacketLength", "stdPacketLength", "avgIatMs", "stdIatMs", "uplinkRatio", "upPackets", "downPackets"] as const;
export const TRAFFIC_CLASSES = ["benign", "c2_channel", "data_exfiltration", "lateral_movement", "malware_transfer"] as const;
export type FeatureName = (typeof FEATURE_OPTIONS)[number]; export type TrafficClass = (typeof TRAFFIC_CLASSES)[number]; export type ModelAlgorithm = "lightgbm_kitnet"; export type LabeledFlow = { flow: FlowFeature; label: TrafficClass };
export type StoredModelPayload = { kind: "opensource_ml"; frameworks: string[]; classes: TrafficClass[]; features: FeatureName[]; lightgbm: string; kitnet: string; kitnetGrace: { featureMapping: number; anomalyDetector: number } } | { kind: "logistic_regression" | "gaussian_nb"; classes: TrafficClass[]; [key: string]: unknown };
export type ModelScore = { score: number; anomalyScore: number; predictedClass: TrafficClass; classScores: Record<string, number>; reasons: string[]; featureValues: Record<string, number> };
const labels: Record<FeatureName, string> = { packetCount: "包数量", byteCount: "总字节数", durationMs: "会话持续时间", avgPacketLength: "平均包长", stdPacketLength: "包长波动", avgIatMs: "平均包间隔", stdIatMs: "包间隔波动", uplinkRatio: "上行字节占比", upPackets: "上行包数量", downPackets: "下行包数量" };
export const trafficClassLabels: Record<TrafficClass, string> = { benign: "正常流量", c2_channel: "命令控制", data_exfiltration: "数据外传", lateral_movement: "横向移动", malware_transfer: "恶意传输" };
const values = (flow: FlowFeature, features: FeatureName[]) => features.map(feature => Number(flow[feature]) || 0);

export async function trainModel(samples: LabeledFlow[], features: FeatureName[], _algorithm: ModelAlgorithm) {
  if (samples.length < 12) throw new Error("至少需要 12 条已标注流特征才能训练 LightGBM 多分类模型"); const classes = Array.from(new Set(samples.map(sample => sample.label))) as TrafficClass[]; if (classes.length < 3 || !classes.includes("benign")) throw new Error("训练至少需要正常流量和两种恶意流量类别");
  return runOpenSourceMl<{ payload: StoredModelPayload; metrics: Record<string, unknown>; trainingCount: number; validationCount: number; classes: TrafficClass[] }>({ operation: "train", features, samples: samples.map(sample => ({ values: values(sample.flow, features), label: sample.label })) });
}

export async function scoreModelBatch(flows: FlowFeature[], features: FeatureName[], payload: StoredModelPayload): Promise<ModelScore[]> {
  if (payload.kind !== "opensource_ml") throw new Error("历史自研模型仅可查看；请使用 LightGBM + KitNET 新模型执行检测"); const result = await runOpenSourceMl<{ scores: Array<{ probabilities: number[]; anomalyScore: number }> }>({ operation: "score", payload, values: flows.map(flow => values(flow, features)) });
  return result.scores.map((resultItem, index) => { const classScores = Object.fromEntries(payload.classes.map((key, classIndex) => [key, resultItem.probabilities[classIndex] ?? 0])); const predictedClass = payload.classes[resultItem.probabilities.indexOf(Math.max(...resultItem.probabilities))]; const supervisedRisk = 1 - (classScores.benign ?? 0); const score = Math.min(1, supervisedRisk * 0.7 + resultItem.anomalyScore * 0.3); const raw = values(flows[index], features); const top = features.map((feature, featureIndex) => ({ feature, value: raw[featureIndex] })).sort((a, b) => Math.abs(b.value) - Math.abs(a.value)).slice(0, 3); return { score, anomalyScore: resultItem.anomalyScore, predictedClass, classScores, reasons: [`LightGBM 预测为${trafficClassLabels[predictedClass]}（置信度 ${(classScores[predictedClass] * 100).toFixed(1)}%）`, `Kitsune KitNET 异常分 ${(resultItem.anomalyScore * 100).toFixed(1)}%`, ...top.map(item => `${labels[item.feature]}参与行为分类（值 ${item.value.toFixed(2)}）`)], featureValues: Object.fromEntries(features.map((feature, featureIndex) => [feature, raw[featureIndex]])) }; });
}

export async function scoreModel(flow: FlowFeature, features: FeatureName[], payload: StoredModelPayload) { return (await scoreModelBatch([flow], features, payload))[0]; }
