import { describe, expect, it } from "vitest";
import { FEATURE_OPTIONS, scoreModel, trainModel, type TrafficClass } from "./modelEngine";
import type { AbonnenFeatureValues } from "./abonnen";
import type { FlowFeature } from "./trafficAnalysis";

function values(trafficClass: TrafficClass, index: number): AbonnenFeatureValues {
  const baseline: AbonnenFeatureValues = {
    avg_cert_path: 2, avg_cert_valid_day: 365, avg_domain_name_length: 14, avg_duration: 0.2, avg_IPs_in_DNS: 2, avg_pkts: 5, avg_size: 500, avg_time_diff: 0.04, avg_TTL: 300, avg_valid_cert_percent: 0.4,
    cert_key_type: "rsa", cert_sig_alg: "sha256", cipher_suite_server: "TLS_AES_128_GCM_SHA256", is_CNs_in_SNA_dns: 1, is_O_in_issuer: 1, is_O_in_subject: 1, is_ST_in_subject: 0, max_duration: 0.3, max_time_diff: 0.05,
    number_of_domains_in_cert: 3, number_of_flows: 1, packet_loss: 0, recv_sent_pkts_ratio: 1, recv_sent_size_ratio: 1, ssl_version: "TLSv13", std_domain_name_length: 2, std_time_diff: 0.01, subject_only_CN: 0, resumed: 0, SNI_ssl_ratio: 1,
  };
  const profiles: Record<TrafficClass, Partial<AbonnenFeatureValues>> = {
    benign: { avg_duration: 0.15 + index / 1000, avg_size: 500 + index, avg_pkts: 5 + index / 20 },
    c2_channel: { avg_duration: 9 + index / 10, avg_size: 80 + index, avg_time_diff: 3.5 + index / 100, recv_sent_size_ratio: 0.2, cipher_suite_server: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256" },
    data_exfiltration: { avg_duration: 4 + index / 10, avg_size: 30_000 + index * 100, avg_pkts: 50 + index, recv_sent_size_ratio: 0.04, cert_key_type: "ec", cipher_suite_server: "TLS_CHACHA20_POLY1305_SHA256" },
    lateral_movement: { avg_duration: 0.5 + index / 100, avg_size: 10_000 + index * 20, avg_pkts: 120 + index, number_of_flows: 10 + index / 10, ssl_version: "TLSv10" },
    malware_transfer: { avg_duration: 1.5 + index / 100, avg_size: 80_000 + index * 100, avg_pkts: 250 + index, number_of_domains_in_cert: 0, SNI_ssl_ratio: 0, cert_sig_alg: "md5" },
  };
  return { ...baseline, ...profiles[trafficClass] };
}

function makeFlow(index: number, trafficClass: TrafficClass): FlowFeature {
  const abonnen = values(trafficClass, index);
  const byteCount = Number(abonnen.avg_size);
  return {
    flowKey: `TCP|10.0.0.${index}:443|10.0.1.1:5000`, sourceIp: `10.0.0.${index}`, sourcePort: 443, destinationIp: "10.0.1.1", destinationPort: 5000,
    transportProtocol: "TCP", applicationProtocol: "TLS", packetCount: Number(abonnen.avg_pkts), byteCount, upPackets: 3, downPackets: 2, upBytes: byteCount / 2, downBytes: byteCount / 2,
    durationMs: Number(abonnen.avg_duration) * 1000, avgPacketLength: byteCount / Math.max(1, Number(abonnen.avg_pkts)), stdPacketLength: 3, avgIatMs: Number(abonnen.avg_time_diff) * 1000, stdIatMs: Number(abonnen.std_time_diff) * 1000,
    uplinkRatio: 0.5, splt: [], tlsVersion: String(abonnen.ssl_version), ja3: null, sniVisibility: "visible", sni: "example.test", abonnen, abonnenSource: "upstream_zeek",
  };
}

describe("Abonnen TLS model engine", () => {
  it("trains the upstream random forest and returns normalized five-class probabilities", async () => {
    const classes: TrafficClass[] = ["benign", "c2_channel", "data_exfiltration", "lateral_movement", "malware_transfer"];
    const samples = classes.flatMap((trafficClass, classIndex) => Array.from({ length: 10 }, (_, index) => ({ flow: makeFlow(classIndex * 30 + index + 1, trafficClass), label: trafficClass })));
    const trained = await trainModel(samples, [...FEATURE_OPTIONS], "abonnen_random_forest");
    const prediction = await scoreModel(makeFlow(99, "c2_channel"), [...FEATURE_OPTIONS], trained.payload);
    const metrics = trained.metrics as { macroF1: number };
    expect(trained.payload.kind).toBe("abonnen_tls");
    expect(trained.payload.features).toEqual(FEATURE_OPTIONS);
    expect(prediction.predictedClass).toBe("c2_channel");
    expect(prediction.classScores.c2_channel).toBeGreaterThan(prediction.classScores.benign);
    expect(Object.keys(prediction.classScores)).toEqual(classes);
    expect(Object.values(prediction.classScores).reduce((sum, value) => sum + value, 0)).toBeCloseTo(1, 6);
    expect(metrics.macroF1).toBeGreaterThan(0.7);
  }, 30_000);
});
