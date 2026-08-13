import { describe, expect, it } from "vitest";
import { ABONNEN_FEATURE_OPTIONS, enrichWithAbonnenFeatures } from "./abonnen";
import { analyzePcap } from "./trafficAnalysis";

function tcpFrame(payloadLength: number) {
  const frame = Buffer.alloc(14 + 20 + 20 + payloadLength);
  frame.writeUInt16BE(0x0800, 12); frame[14] = 0x45; frame.writeUInt16BE(20 + 20 + payloadLength, 16); frame[23] = 6;
  [10, 20, 0, 1].forEach((value, offset) => { frame[26 + offset] = value; }); [198, 51, 100, 25].forEach((value, offset) => { frame[30 + offset] = value; });
  frame.writeUInt16BE(43000, 34); frame.writeUInt16BE(443, 36); frame[46] = 0x50;
  return frame;
}
function pcap() {
  const global = Buffer.alloc(24); global.writeUInt32LE(0xa1b2c3d4, 0); global.writeUInt16LE(2, 4); global.writeUInt16LE(4, 6); global.writeUInt32LE(65535, 16); global.writeUInt32LE(1, 20);
  const frame = tcpFrame(24); const record = Buffer.alloc(16); record.writeUInt32LE(1710000100, 0); record.writeUInt32LE(frame.length, 8); record.writeUInt32LE(frame.length, 12);
  return Buffer.concat([global, record, frame]);
}

describe("Abonnen feature enrichment", () => {
  it("adds the full upstream vector to every parsed flow", async () => {
    const capture = pcap();
    const analysis = analyzePcap(capture);
    const enriched = await enrichWithAbonnenFeatures(capture, analysis.flows);
    expect(enriched.flows).toHaveLength(1);
    expect(enriched.flows[0].abonnen).toBeDefined();
    expect(Object.keys(enriched.flows[0].abonnen ?? {}).sort()).toEqual([...ABONNEN_FEATURE_OPTIONS].sort());
    expect(["upstream_zeek", "native_compatibility"]).toContain(enriched.flows[0].abonnenSource);
  }, 30_000);
});
