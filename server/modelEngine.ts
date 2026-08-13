import type { FlowFeature } from "./trafficAnalysis";

export const FEATURE_OPTIONS = ["packetCount", "byteCount", "durationMs", "avgPacketLength", "stdPacketLength", "avgIatMs", "stdIatMs", "uplinkRatio", "upPackets", "downPackets"] as const;
export const TRAFFIC_CLASSES = ["benign", "c2_channel", "data_exfiltration", "lateral_movement", "malware_transfer"] as const;
export type FeatureName = (typeof FEATURE_OPTIONS)[number];
export type TrafficClass = (typeof TRAFFIC_CLASSES)[number];
export type ModelAlgorithm = "logistic_regression" | "gaussian_nb";
export type LabeledFlow = { flow: FlowFeature; label: TrafficClass };

type LogisticPayload = { kind: "logistic_regression"; classes: TrafficClass[]; means: number[]; stds: number[]; weights: number[][]; biases: number[] };
type GaussianPayload = { kind: "gaussian_nb"; classes: TrafficClass[]; means: number[][]; variances: number[][]; priors: number[]; standardMeans: number[]; standardStds: number[] };
export type StoredModelPayload = LogisticPayload | GaussianPayload;

const featureLabels: Record<FeatureName, string> = { packetCount: "包数量", byteCount: "总字节数", durationMs: "会话持续时间", avgPacketLength: "平均包长", stdPacketLength: "包长波动", avgIatMs: "平均包间隔", stdIatMs: "包间隔波动", uplinkRatio: "上行字节占比", upPackets: "上行包数量", downPackets: "下行包数量" };
export const trafficClassLabels: Record<TrafficClass, string> = { benign: "正常流量", c2_channel: "命令控制", data_exfiltration: "数据外传", lateral_movement: "横向移动", malware_transfer: "恶意传输" };

function softmax(values: number[]) { const maximum = Math.max(...values); const exp = values.map(value => Math.exp(value - maximum)); const total = exp.reduce((sum, value) => sum + value, 0); return exp.map(value => value / total); }
function vector(flow: FlowFeature, features: FeatureName[]) { return features.map(feature => Number(flow[feature]) || 0); }
function mean(values: number[]) { return values.reduce((sum, value) => sum + value, 0) / Math.max(1, values.length); }
function standardDeviation(values: number[], average: number) { return Math.max(1e-6, Math.sqrt(values.reduce((sum, value) => sum + (value - average) ** 2, 0) / Math.max(1, values.length))); }
function standardized(row: number[], means: number[], stds: number[]) { return row.map((value, index) => (value - means[index]) / stds[index]); }

function metrics(predicted: TrafficClass[], actual: TrafficClass[], classes: TrafficClass[]) {
  const classMetrics = Object.fromEntries(classes.map(label => {
    const tp = actual.filter((value, index) => value === label && predicted[index] === label).length;
    const fp = actual.filter((value, index) => value !== label && predicted[index] === label).length;
    const fn = actual.filter((value, index) => value === label && predicted[index] !== label).length;
    const precision = tp / Math.max(1, tp + fp); const recall = tp / Math.max(1, tp + fn); const f1 = 2 * precision * recall / Math.max(1e-9, precision + recall);
    return [label, { precision, recall, f1, support: actual.filter(value => value === label).length }];
  }));
  const accuracy = predicted.filter((value, index) => value === actual[index]).length / Math.max(1, actual.length);
  const values = Object.values(classMetrics) as Array<{ precision: number; recall: number; f1: number }>;
  const precision = mean(values.map(value => value.precision)); const recall = mean(values.map(value => value.recall)); const f1 = mean(values.map(value => value.f1));
  return { accuracy, precision, recall, f1, macroPrecision: precision, macroRecall: recall, macroF1: f1, support: actual.length, classMetrics };
}

export function trainModel(samples: LabeledFlow[], features: FeatureName[], algorithm: ModelAlgorithm) {
  if (samples.length < 12) throw new Error("至少需要 12 条已标注流特征才能训练多分类模型");
  const classes = Array.from(new Set(samples.map(sample => sample.label))) as TrafficClass[];
  if (classes.length < 3 || !classes.includes("benign")) throw new Error("多分类训练至少需要正常流量和两种恶意流量类别");
  const train = samples.filter((_, index) => index % 5 !== 0); const validation = samples.filter((_, index) => index % 5 === 0);
  const trainingSamples = train.length >= 8 ? train : samples; const evaluationSamples = validation.length >= 3 ? validation : samples;
  const trainRows = trainingSamples.map(sample => vector(sample.flow, features)); const means = features.map((_, index) => mean(trainRows.map(row => row[index]))); const stds = features.map((_, index) => standardDeviation(trainRows.map(row => row[index]), means[index])); const scaled = trainRows.map(row => standardized(row, means, stds));
  let payload: StoredModelPayload;
  if (algorithm === "logistic_regression") {
    const weights = classes.map(() => new Array(features.length).fill(0)); const biases = classes.map(() => 0); const classCounts = classes.map(label => trainingSamples.filter(sample => sample.label === label).length); const classWeights = classCounts.map(count => trainingSamples.length / Math.max(1, classes.length * count));
    for (let epoch = 0; epoch < 320; epoch += 1) {
      const gradients = classes.map(() => new Array(features.length).fill(0)); const biasGradients = classes.map(() => 0);
      scaled.forEach((row, rowIndex) => { const probabilities = softmax(classes.map((_, classIndex) => row.reduce((sum, value, featureIndex) => sum + value * weights[classIndex][featureIndex], biases[classIndex]))); classes.forEach((label, classIndex) => { const target = trainingSamples[rowIndex].label === label ? 1 : 0; const error = (probabilities[classIndex] - target) * classWeights[classIndex]; row.forEach((value, featureIndex) => { gradients[classIndex][featureIndex] += error * value; }); biasGradients[classIndex] += error; }); });
      const rate = 0.1 / (1 + epoch / 180); classes.forEach((_, classIndex) => { weights[classIndex].forEach((weight, featureIndex) => { weights[classIndex][featureIndex] = weight - rate * (gradients[classIndex][featureIndex] / scaled.length + 0.001 * weight); }); biases[classIndex] -= rate * biasGradients[classIndex] / scaled.length; });
    }
    payload = { kind: "logistic_regression", classes, means, stds, weights, biases };
  } else {
    const grouped = classes.map(label => scaled.filter((_, index) => trainingSamples[index].label === label)); const classMeans = grouped.map(rows => features.map((_, index) => mean(rows.map(row => row[index])))); const variances = grouped.map((rows, classIndex) => features.map((_, index) => Math.max(1e-5, mean(rows.map(row => (row[index] - classMeans[classIndex][index]) ** 2)))));
    payload = { kind: "gaussian_nb", classes, means: classMeans, variances, priors: grouped.map(rows => rows.length / trainingSamples.length), standardMeans: means, standardStds: stds };
  }
  const validationResults = evaluationSamples.map(sample => scoreModel(sample.flow, features, payload));
  return { payload, metrics: metrics(validationResults.map(item => item.predictedClass), evaluationSamples.map(sample => sample.label), classes), trainingCount: trainingSamples.length, validationCount: evaluationSamples.length, classes };
}

export function scoreModel(flow: FlowFeature, features: FeatureName[], payload: StoredModelPayload) {
  const raw = vector(flow, features); let probabilities: number[]; let contributions: number[]; let normalized: number[];
  if (payload.kind === "logistic_regression") { normalized = standardized(raw, payload.means, payload.stds); probabilities = softmax(payload.classes.map((_, classIndex) => normalized.reduce((sum, value, featureIndex) => sum + value * payload.weights[classIndex][featureIndex], payload.biases[classIndex]))); const bestIndex = probabilities.indexOf(Math.max(...probabilities)); contributions = normalized.map((value, index) => value * payload.weights[bestIndex][index]); }
  else { normalized = standardized(raw, payload.standardMeans, payload.standardStds); const logLikelihoods = payload.classes.map((_, classIndex) => Math.log(Math.max(1e-8, payload.priors[classIndex])) + normalized.reduce((sum, value, index) => sum - 0.5 * Math.log(2 * Math.PI * payload.variances[classIndex][index]) - ((value - payload.means[classIndex][index]) ** 2) / (2 * payload.variances[classIndex][index]), 0)); probabilities = softmax(logLikelihoods); const bestIndex = probabilities.indexOf(Math.max(...probabilities)); contributions = normalized.map((value, index) => Math.abs(value - payload.means[bestIndex][index])); }
  const bestIndex = probabilities.indexOf(Math.max(...probabilities)); const predictedClass = payload.classes[bestIndex]; const classScores = Object.fromEntries(payload.classes.map((label, index) => [label, probabilities[index]])); const riskScore = 1 - (classScores.benign ?? 0);
  const reasons = features.map((feature, index) => ({ feature, magnitude: Math.abs(contributions[index]), value: raw[index], z: normalized[index] })).sort((a, b) => b.magnitude - a.magnitude).slice(0, 3).filter(item => item.magnitude > 0.05).map(item => `${featureLabels[item.feature]}偏离${trafficClassLabels[predictedClass]}训练基线（值 ${item.value.toFixed(2)}，标准化偏离 ${item.z.toFixed(2)}）`);
  if (flow.applicationProtocol === "QUIC") reasons.push("检测到 QUIC 长包头会话；分类基于流量行为，不依赖 SNI 明文");
  if (flow.sniVisibility === "not_observed" && flow.applicationProtocol === "TLS") reasons.push("TLS 会话未观察到 SNI；模型继续使用流统计与时序特征分类");
  return { score: riskScore, predictedClass, classScores, reasons: reasons.length ? reasons : [`综合流特征判定为${trafficClassLabels[predictedClass]}`], featureValues: Object.fromEntries(features.map((feature, index) => [feature, raw[index]])) };
}
