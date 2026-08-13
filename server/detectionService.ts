import { getActiveModel, getModel } from "./db";
import { scoreModelBatch, type FeatureName, type ModelScore, type StoredModelPayload } from "./modelEngine";
import { analyzePcap, type FlowFeature } from "./trafficAnalysis";
import { labelName, type AnnotationSetSnapshot } from "@shared/annotationSets";

function riskLevel(score: number) {
  if (score >= 0.8) return "critical";
  if (score >= 0.6) return "high";
  if (score >= 0.35) return "medium";
  return "low";
}

function detailFlow(entry: ModelScore & { flow: FlowFeature }, annotationSet: AnnotationSetSnapshot) {
  const { flow, score, predictedClass, classScores, reasons, featureValues } = entry;
  return {
    flowId: flow.flowKey,
    network: {
      fiveTuple: { sourceIp: flow.sourceIp, sourcePort: flow.sourcePort, destinationIp: flow.destinationIp, destinationPort: flow.destinationPort, transportProtocol: flow.transportProtocol },
      applicationProtocol: flow.applicationProtocol,
    },
    trafficStatistics: {
      packetCount: flow.packetCount, byteCount: flow.byteCount, durationMs: flow.durationMs,
      packets: { upstream: flow.upPackets, downstream: flow.downPackets }, bytes: { upstream: flow.upBytes, downstream: flow.downBytes, uplinkRatio: flow.uplinkRatio },
      packetLength: { average: flow.avgPacketLength, standardDeviation: flow.stdPacketLength }, interArrivalTimeMs: { average: flow.avgIatMs, standardDeviation: flow.stdIatMs },
    },
    splt: { observedPackets: flow.splt.length, maxPackets: 24, sequence: flow.splt },
    encryptedMetadata: {
      protocol: flow.applicationProtocol,
      tls: { version: flow.tlsVersion, ja3: flow.ja3, sni: { visibility: flow.sniVisibility, value: flow.sni } },
      quic: { detected: flow.applicationProtocol === "QUIC", version: flow.applicationProtocol === "QUIC" ? flow.tlsVersion : null },
    },
    classification: { predictedClass, predictedLabel: labelName(annotationSet, predictedClass), confidence: classScores[predictedClass], probabilities: classScores },
    risk: { score, level: riskLevel(score), reasons, featureValues },
  };
}

export async function inspectPcap(userId: number, fileName: string, buffer: Buffer, requestedModelId?: number) {
  const model = requestedModelId ? await getModel(userId, requestedModelId) : await getActiveModel(userId);
  if (!model) throw new Error(requestedModelId ? "指定模型不存在或无访问权限" : "当前用户没有已激活的检测模型");
  const analysis = analyzePcap(buffer); const payload = JSON.parse(model.modelJson) as StoredModelPayload; const features = JSON.parse(model.featureSetJson) as FeatureName[];
  const annotationSet = model.annotationSnapshotJson ? JSON.parse(model.annotationSnapshotJson) as AnnotationSetSnapshot : { name: "历史标注集", labels: [] };
  const scores = await scoreModelBatch(analysis.flows, features, payload); const scored = analysis.flows.map((flow, index) => ({ flow, ...scores[index] })).sort((left, right) => right.score - left.score);
  const flows = scored.map(entry => detailFlow(entry, annotationSet)); const classDistribution = flows.reduce<Record<string, number>>((distribution, entry) => { distribution[entry.classification.predictedClass] = (distribution[entry.classification.predictedClass] ?? 0) + 1; return distribution; }, {});
  const riskDistribution = flows.reduce<Record<string, number>>((distribution, entry) => { distribution[entry.risk.level] = (distribution[entry.risk.level] ?? 0) + 1; return distribution; }, { critical: 0, high: 0, medium: 0, low: 0 });
  const encryptionMetadata = { tlsFlows: flows.filter(entry => entry.encryptedMetadata.protocol === "TLS").length, quicFlows: flows.filter(entry => entry.encryptedMetadata.protocol === "QUIC").length, sniVisible: flows.filter(entry => entry.encryptedMetadata.tls.sni.visibility === "visible").length, sniNotObserved: flows.filter(entry => entry.encryptedMetadata.tls.sni.visibility === "not_observed").length, ja3Observed: flows.filter(entry => Boolean(entry.encryptedMetadata.tls.ja3)).length };
  const highRiskFlows = scored.filter(entry => entry.score >= 0.7).length; const averageRisk = scored.reduce((sum, entry) => sum + entry.score, 0) / Math.max(1, scored.length);
  return { model: { id: model.id, version: model.versionName, algorithm: model.algorithm, classes: JSON.parse(model.classSetJson), annotationSet }, summary: { fileName, packetCount: analysis.packetCount, flowCount: analysis.flowCount, protocolDistribution: analysis.protocolDistribution, classDistribution, riskDistribution, encryptionMetadata, highRiskFlows, averageRisk, annotationSet }, flows, scored };
}
