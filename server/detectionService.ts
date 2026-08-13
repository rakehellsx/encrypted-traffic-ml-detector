import { getActiveModel, getModel } from "./db";
import { scoreModel, type FeatureName, type StoredModelPayload } from "./modelEngine";
import { analyzePcap } from "./trafficAnalysis";

export async function inspectPcap(userId: number, fileName: string, buffer: Buffer, requestedModelId?: number) {
  const model = requestedModelId ? await getModel(userId, requestedModelId) : await getActiveModel(userId);
  if (!model) throw new Error(requestedModelId ? "指定模型不存在或无访问权限" : "当前用户没有已激活的检测模型");
  const analysis = analyzePcap(buffer);
  const payload = JSON.parse(model.modelJson) as StoredModelPayload;
  const features = JSON.parse(model.featureSetJson) as FeatureName[];
  const flows = analysis.flows.map(flow => ({ flow, ...scoreModel(flow, features, payload) })).sort((left, right) => right.score - left.score);
  const classDistribution = flows.reduce<Record<string, number>>((distribution, entry) => { distribution[entry.predictedClass] = (distribution[entry.predictedClass] ?? 0) + 1; return distribution; }, {});
  const highRiskFlows = flows.filter(entry => entry.score >= 0.7).length;
  const averageRisk = flows.reduce((sum, entry) => sum + entry.score, 0) / Math.max(1, flows.length);
  return {
    model: { id: model.id, version: model.versionName, algorithm: model.algorithm, classes: JSON.parse(model.classSetJson) },
    summary: { fileName, packetCount: analysis.packetCount, flowCount: analysis.flowCount, protocolDistribution: analysis.protocolDistribution, classDistribution, highRiskFlows, averageRisk },
    flows,
  };
}
