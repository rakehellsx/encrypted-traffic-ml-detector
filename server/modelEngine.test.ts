import { describe, expect, it } from "vitest";
import { scoreModel, trainModel, type TrafficClass } from "./modelEngine";
import type { FlowFeature } from "./trafficAnalysis";

function makeFlow(index: number, trafficClass: TrafficClass): FlowFeature {
  const profile = trafficClass === "benign" ? { packets: 6, bytes: 500, ratio: 0.35, duration: 600, size: 100 } : trafficClass === "c2_channel" ? { packets: 30, bytes: 1800, ratio: 0.52, duration: 20000, size: 80 } : { packets: 70, bytes: 12000, ratio: 0.92, duration: 8000, size: 430 };
  const byteCount = profile.bytes + index * 7;
  return { flowKey: `TCP|10.0.0.${index}:443|10.0.1.1:5000`, sourceIp: `10.0.0.${index}`, sourcePort: 443, destinationIp: "10.0.1.1", destinationPort: 5000, transportProtocol: "TCP", applicationProtocol: "TLS", packetCount: profile.packets + (index % 3), byteCount, upPackets: Math.round(profile.packets * profile.ratio), downPackets: profile.packets - Math.round(profile.packets * profile.ratio), upBytes: Math.round(byteCount * profile.ratio), downBytes: Math.round(byteCount * (1 - profile.ratio)), durationMs: profile.duration + index * 5, avgPacketLength: profile.size, stdPacketLength: profile.size / 4, avgIatMs: profile.duration / profile.packets, stdIatMs: 15, uplinkRatio: profile.ratio, splt: [], tlsVersion: "TLS 1.3", ja3: null, sniVisibility: "not_observed", sni: null };
}

describe("model engine", () => {
  it("trains and predicts separable multi-class encrypted traffic", async () => {
    const classes: TrafficClass[] = ["benign", "c2_channel", "data_exfiltration"];
    const samples = classes.flatMap((trafficClass, classIndex) => Array.from({ length: 10 }, (_, index) => ({ flow: makeFlow(classIndex * 20 + index + 1, trafficClass), label: trafficClass })));
    const features = ["byteCount", "packetCount", "uplinkRatio", "durationMs"] as const;
    const trained = await trainModel(samples, [...features], "lightgbm_kitnet");
    const prediction = await scoreModel(makeFlow(99, "c2_channel"), [...features], trained.payload);
    expect(prediction.predictedClass).toBe("c2_channel");
    expect(prediction.classScores.c2_channel).toBeGreaterThan(prediction.classScores.benign);
    expect(trained.metrics.macroF1).toBeGreaterThan(0.7);
  }, 20_000);
});
