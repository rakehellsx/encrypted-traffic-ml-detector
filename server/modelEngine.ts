import { ABONNEN_FEATURE_OPTIONS, type AbonnenFeatureName, type AbonnenFeatureValues } from "./abonnen";
import { runAbonnenTlsEngine } from "./openSourceMl";
import type { FlowFeature } from "./trafficAnalysis";

export const FEATURE_OPTIONS = ABONNEN_FEATURE_OPTIONS;
export const TRAFFIC_CLASSES = ["benign", "c2_channel", "data_exfiltration", "lateral_movement", "malware_transfer"] as const;
export type FeatureName = AbonnenFeatureName;
export type TrafficClass = (typeof TRAFFIC_CLASSES)[number];
export type ModelAlgorithm = "abonnen_random_forest" | "abonnen_gbdt";
export type LabeledFlow = { flow: FlowFeature; label: TrafficClass };
export type StoredModelPayload = {
  kind: "abonnen_tls";
  source: "Abonnen/Malicious_TLS_Detection";
  frameworks: string[];
  algorithm: ModelAlgorithm;
  classes: TrafficClass[];
  trainedClasses: TrafficClass[];
  features: FeatureName[];
  artifact: string;
  categoricalEncoders: Record<string, Record<string, number>>;
};
export type ModelScore = {
  score: number;
  /** Kept for backward-compatible archive consumers; no KitNET anomaly score is used. */
  anomalyScore: number;
  predictedClass: TrafficClass;
  classScores: Record<TrafficClass, number>;
  reasons: string[];
  featureValues: Record<string, number | string>;
};

const labels: Record<FeatureName, string> = {
  avg_cert_path: "证书链平均长度", avg_cert_valid_day: "证书平均有效天数", avg_domain_name_length: "域名平均长度", avg_duration: "连接平均持续时间",
  avg_IPs_in_DNS: "DNS 平均 IP 数", avg_pkts: "连接平均包数", avg_size: "连接平均字节数", avg_time_diff: "连接平均间隔", avg_TTL: "DNS 平均 TTL",
  avg_valid_cert_percent: "证书有效期位置", cert_key_type: "证书密钥类型", cert_sig_alg: "证书签名算法", cipher_suite_server: "服务端密码套件",
  is_CNs_in_SNA_dns: "CN 与 SAN 一致性", is_O_in_issuer: "签发者组织字段", is_O_in_subject: "主题组织字段", is_ST_in_subject: "主题省份字段",
  max_duration: "最大连接持续时间", max_time_diff: "最大连接间隔", number_of_domains_in_cert: "证书域名数量", number_of_flows: "元组连接数量",
  packet_loss: "丢失字节数", recv_sent_pkts_ratio: "收发包比", recv_sent_size_ratio: "收发字节比", ssl_version: "TLS 版本",
  std_domain_name_length: "域名长度波动", std_time_diff: "连接间隔波动", subject_only_CN: "主题仅含 CN", resumed: "TLS 恢复次数", SNI_ssl_ratio: "可见 SNI 比例",
};

export const trafficClassLabels: Record<TrafficClass, string> = {
  benign: "正常流量", c2_channel: "命令控制", data_exfiltration: "数据外传", lateral_movement: "横向移动", malware_transfer: "恶意传输",
};

function values(flow: FlowFeature): AbonnenFeatureValues {
  if (!flow.abonnen) throw new Error("该流缺少 Abonnen TLS 特征；请重新上传并解析 PCAP 后训练或检测");
  return flow.abonnen;
}

export async function trainModel(samples: LabeledFlow[], features: FeatureName[], algorithm: ModelAlgorithm) {
  if (features.length !== FEATURE_OPTIONS.length || features.some((feature, index) => feature !== FEATURE_OPTIONS[index])) {
    throw new Error("Abonnen TLS 模型必须使用固定的 30 项上游筛选特征，不能删减或重排");
  }
  if (samples.length < 10) throw new Error("至少需要 10 条已标注的上游 TLS 特征流才能训练模型");
  const classes = Array.from(new Set(samples.map(sample => sample.label))) as TrafficClass[];
  if (!classes.includes("benign") || classes.length < 2) throw new Error("训练至少需要正常流量和一种恶意流量类别");
  return runAbonnenTlsEngine<{ payload: StoredModelPayload; metrics: Record<string, unknown>; trainingCount: number; validationCount: number; classes: TrafficClass[] }>({
    operation: "train",
    algorithm,
    samples: samples.map(sample => ({ values: values(sample.flow), label: sample.label })),
  });
}

export async function scoreModelBatch(flows: FlowFeature[], features: FeatureName[], payload: StoredModelPayload): Promise<ModelScore[]> {
  if (payload.kind !== "abonnen_tls") throw new Error("历史模型无法用于检测；请使用 Abonnen TLS 新模型训练并激活版本");
  if (features.length !== FEATURE_OPTIONS.length || features.some((feature, index) => feature !== FEATURE_OPTIONS[index])) throw new Error("模型特征集与 Abonnen TLS 上游特征顺序不一致");
  const result = await runAbonnenTlsEngine<{ scores: Array<{ probabilities: Record<TrafficClass, number>; predictedClass: TrafficClass; riskScore: number; explanation: Array<{ feature: FeatureName; value: number | string; importance: number }> }> }>({
    operation: "score",
    payload,
    values: flows.map(values),
  });
  return result.scores.map((item, index) => {
    const featureValues = values(flows[index]);
    const details = item.explanation.map(entry => `${labels[entry.feature]}参与上游模型判定（值 ${String(entry.value)}）`);
    return {
      score: Math.min(1, Math.max(0, item.riskScore)),
      anomalyScore: 0,
      predictedClass: item.predictedClass,
      classScores: item.probabilities,
      reasons: [
        `${payload.algorithm === "abonnen_random_forest" ? "Abonnen 随机森林" : "Abonnen GBDT"} 预测为${trafficClassLabels[item.predictedClass]}（置信度 ${(item.probabilities[item.predictedClass] * 100).toFixed(1)}%）`,
        `风险评分为 1 − 正常流量概率（${((1 - item.probabilities.benign) * 100).toFixed(1)}%）`,
        ...details,
      ],
      featureValues,
    };
  });
}

export async function scoreModel(flow: FlowFeature, features: FeatureName[], payload: StoredModelPayload) {
  return (await scoreModelBatch([flow], features, payload))[0];
}
