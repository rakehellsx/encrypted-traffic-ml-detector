import type { FlowFeature } from "./trafficAnalysis";

export const FEATURE_OPTIONS = [
  "packetCount",
  "byteCount",
  "durationMs",
  "avgPacketLength",
  "stdPacketLength",
  "avgIatMs",
  "stdIatMs",
  "uplinkRatio",
  "upPackets",
  "downPackets",
] as const;

export type FeatureName = (typeof FEATURE_OPTIONS)[number];
export type ModelAlgorithm = "logistic_regression" | "gaussian_nb";
export type LabeledFlow = { flow: FlowFeature; label: 0 | 1 };

type LogisticPayload = { kind: "logistic_regression"; means: number[]; stds: number[]; weights: number[]; bias: number };
type GaussianPayload = { kind: "gaussian_nb"; means: number[][]; variances: number[][]; priors: [number, number] };
export type StoredModelPayload = LogisticPayload | GaussianPayload;

const featureLabels: Record<FeatureName, string> = {
  packetCount: "包数量",
  byteCount: "总字节数",
  durationMs: "会话持续时间",
  avgPacketLength: "平均包长",
  stdPacketLength: "包长波动",
  avgIatMs: "平均包间隔",
  stdIatMs: "包间隔波动",
  uplinkRatio: "上行字节占比",
  upPackets: "上行包数量",
  downPackets: "下行包数量",
};

function sigmoid(value: number) {
  return value >= 0 ? 1 / (1 + Math.exp(-value)) : Math.exp(value) / (1 + Math.exp(value));
}

function featureVector(flow: FlowFeature, features: FeatureName[]) {
  return features.map(feature => Number(flow[feature]) || 0);
}

function calculateMetrics(scores: number[], labels: number[]) {
  let tp = 0;
  let fp = 0;
  let tn = 0;
  let fn = 0;
  scores.forEach((score, index) => {
    const predicted = score >= 0.5 ? 1 : 0;
    const actual = labels[index];
    if (predicted && actual) tp += 1;
    else if (predicted && !actual) fp += 1;
    else if (!predicted && !actual) tn += 1;
    else fn += 1;
  });
  const accuracy = (tp + tn) / Math.max(1, labels.length);
  const precision = tp / Math.max(1, tp + fp);
  const recall = tp / Math.max(1, tp + fn);
  const f1 = (2 * precision * recall) / Math.max(1e-9, precision + recall);
  return { accuracy, precision, recall, f1, support: labels.length, confusionMatrix: { tp, fp, tn, fn } };
}

function scaledRows(rows: number[][], means: number[], stds: number[]) {
  return rows.map(row => row.map((value, index) => (value - means[index]) / stds[index]));
}

export function trainModel(samples: LabeledFlow[], features: FeatureName[], algorithm: ModelAlgorithm) {
  if (samples.length < 8) throw new Error("至少需要 8 条已标注流特征才能训练模型");
  const positives = samples.filter(sample => sample.label === 1).length;
  if (!positives || positives === samples.length) throw new Error("训练数据必须同时包含良性和恶意标签");
  const train = samples.filter((_, index) => index % 5 !== 0);
  const validation = samples.filter((_, index) => index % 5 === 0);
  const trainingSamples = train.length >= 4 ? train : samples;
  const evaluationSamples = validation.length >= 2 ? validation : samples;
  const trainRows = trainingSamples.map(sample => featureVector(sample.flow, features));
  const trainLabels = trainingSamples.map(sample => sample.label);
  const means = features.map((_, index) => trainRows.reduce((sum, row) => sum + row[index], 0) / trainRows.length);
  const stds = features.map((_, index) => Math.max(1e-6, Math.sqrt(trainRows.reduce((sum, row) => sum + (row[index] - means[index]) ** 2, 0) / trainRows.length)));
  const scaledTrain = scaledRows(trainRows, means, stds);
  let payload: StoredModelPayload;

  if (algorithm === "logistic_regression") {
    const weights = new Array(features.length).fill(0);
    let bias = 0;
    const positivesInTrain = trainLabels.filter(label => label === 1).length;
    const positiveWeight = (trainLabels.length - positivesInTrain) / Math.max(1, positivesInTrain);
    for (let epoch = 0; epoch < 260; epoch += 1) {
      const gradients = new Array(features.length).fill(0);
      let biasGradient = 0;
      scaledTrain.forEach((row, index) => {
        const prediction = sigmoid(row.reduce((sum, value, featureIndex) => sum + value * weights[featureIndex], bias));
        const weight = trainLabels[index] === 1 ? positiveWeight : 1;
        const error = (prediction - trainLabels[index]) * weight;
        row.forEach((value, featureIndex) => { gradients[featureIndex] += error * value; });
        biasGradient += error;
      });
      const rate = 0.09 / (1 + epoch / 150);
      weights.forEach((weight, index) => { weights[index] = weight - rate * (gradients[index] / scaledTrain.length + 0.001 * weight); });
      bias -= rate * biasGradient / scaledTrain.length;
    }
    payload = { kind: "logistic_regression", means, stds, weights, bias };
  } else {
    const classRows = [0, 1].map(label => scaledTrain.filter((_, index) => trainLabels[index] === label));
    const classMeans = classRows.map(rows => features.map((_, index) => rows.reduce((sum, row) => sum + row[index], 0) / Math.max(1, rows.length)));
    const variances = classRows.map((rows, classIndex) => features.map((_, index) => Math.max(1e-5, rows.reduce((sum, row) => sum + (row[index] - classMeans[classIndex][index]) ** 2, 0) / Math.max(1, rows.length))));
    payload = { kind: "gaussian_nb", means: classMeans, variances, priors: [classRows[0].length / trainLabels.length, classRows[1].length / trainLabels.length] };
  }
  const scores = evaluationSamples.map(sample => scoreModel(sample.flow, features, payload).score);
  const metrics = calculateMetrics(scores, evaluationSamples.map(sample => sample.label));
  return { payload, metrics, trainingCount: trainingSamples.length, validationCount: evaluationSamples.length };
}

export function scoreModel(flow: FlowFeature, features: FeatureName[], payload: StoredModelPayload) {
  const raw = featureVector(flow, features);
  let score = 0;
  let contributions: number[] = [];
  let normalizedForReasons: number[] = [];
  if (payload.kind === "logistic_regression") {
    const scaled = raw.map((value, index) => (value - payload.means[index]) / payload.stds[index]);
    normalizedForReasons = scaled;
    contributions = scaled.map((value, index) => value * payload.weights[index]);
    score = sigmoid(contributions.reduce((sum, value) => sum + value, payload.bias));
  } else {
    const scaled = raw.map((value, index) => (value - payload.means[0][index]) / Math.sqrt(payload.variances[0][index]));
    normalizedForReasons = scaled;
    const logProbabilities = [0, 1].map(label => {
      const prior = Math.log(Math.max(1e-8, payload.priors[label]));
      return prior + scaled.reduce((sum, value, index) => sum - 0.5 * Math.log(2 * Math.PI * payload.variances[label][index]) - ((value - payload.means[label][index]) ** 2) / (2 * payload.variances[label][index]), 0);
    });
    score = sigmoid(logProbabilities[1] - logProbabilities[0]);
    contributions = normalizedForReasons.map((value, index) => Math.abs(value - payload.means[1][index]) - Math.abs(value - payload.means[0][index]));
  }
  const reasons = features
    .map((feature, index) => ({ feature, magnitude: Math.abs(contributions[index]), value: raw[index], z: normalizedForReasons[index] }))
    .sort((a, b) => b.magnitude - a.magnitude)
    .slice(0, 3)
    .filter(reason => reason.magnitude > 0.05)
    .map(reason => `${featureLabels[reason.feature]}偏离训练基线（值 ${reason.value.toFixed(2)}，标准化偏离 ${reason.z.toFixed(2)}）`);
  if (flow.applicationProtocol === "QUIC") reasons.push("检测到 UDP/443 QUIC 会话；风险判断基于流量行为，不依赖 SNI 明文");
  if (flow.sniVisibility === "not_observed" && flow.applicationProtocol === "TLS") reasons.push("TLS 会话未观察到 SNI；模型以流量统计与时序特征继续评分");
  return { score, reasons: reasons.length ? reasons : ["综合流统计与时序特征得到当前风险评分"], featureValues: Object.fromEntries(features.map((feature, index) => [feature, raw[index]])) };
}
