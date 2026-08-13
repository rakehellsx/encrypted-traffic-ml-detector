import { describe, expect, it } from "vitest";
import { scoreModel, trainModel } from "./modelEngine";
import type { FlowFeature } from "./trafficAnalysis";

function makeFlow(index: number, malicious: boolean): FlowFeature {
  const byteCount = malicious ? 9000 + index * 120 : 500 + index * 8;
  return {
    flowKey: `TCP|10.0.0.${index}:443|10.0.1.1:5000`, sourceIp: `10.0.0.${index}`, sourcePort: 443, destinationIp: "10.0.1.1", destinationPort: 5000,
    transportProtocol: "TCP", applicationProtocol: "TLS", packetCount: malicious ? 60 : 6, byteCount, upPackets: malicious ? 54 : 2, downPackets: malicious ? 6 : 4,
    upBytes: malicious ? Math.round(byteCount * 0.9) : Math.round(byteCount * 0.35), downBytes: malicious ? Math.round(byteCount * 0.1) : Math.round(byteCount * 0.65),
    durationMs: malicious ? 8000 : 600, avgPacketLength: malicious ? 420 : 100, stdPacketLength: malicious ? 190 : 20, avgIatMs: malicious ? 140 : 80, stdIatMs: malicious ? 70 : 12,
    uplinkRatio: malicious ? 0.9 : 0.35, splt: [], tlsVersion: "TLS 1.3", ja3: null, sniVisibility: "not_observed", sni: null,
  };
}

describe("model engine", () => {
  it("trains and scores a separable malicious-flow sample", () => {
    const samples = Array.from({ length: 20 }, (_, index) => ({ flow: makeFlow(index + 1, index >= 10), label: index >= 10 ? (1 as const) : (0 as const) }));
    const features = ["byteCount", "packetCount", "uplinkRatio", "durationMs"] as const;
    const trained = trainModel(samples, [...features], "logistic_regression");
    const maliciousScore = scoreModel(makeFlow(32, true), [...features], trained.payload).score;
    const benignScore = scoreModel(makeFlow(33, false), [...features], trained.payload).score;
    expect(maliciousScore).toBeGreaterThan(benignScore);
    expect(trained.metrics.f1).toBeGreaterThan(0.7);
  });
});
