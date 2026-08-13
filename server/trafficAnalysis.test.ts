import { describe, expect, it } from "vitest";
import { analyzePcap } from "./trafficAnalysis";

function ethernetIpv4UdpFrame(sourcePort: number, destinationPort: number, payload: number[], reverse = false) {
  const frame = Buffer.alloc(14 + 20 + 8 + payload.length);
  frame.writeUInt16BE(0x0800, 12);
  frame[14] = 0x45;
  frame.writeUInt16BE(20 + 8 + payload.length, 16);
  frame[23] = 17;
  const source = reverse ? [8, 8, 8, 8] : [10, 0, 0, 1];
  const destination = reverse ? [10, 0, 0, 1] : [8, 8, 8, 8];
  source.forEach((value, index) => { frame[26 + index] = value; });
  destination.forEach((value, index) => { frame[30 + index] = value; });
  frame.writeUInt16BE(sourcePort, 34);
  frame.writeUInt16BE(destinationPort, 36);
  frame.writeUInt16BE(8 + payload.length, 38);
  Buffer.from(payload).copy(frame, 42);
  return frame;
}

function createPcap(frames: Buffer[]) {
  const header = Buffer.alloc(24);
  header.writeUInt32LE(0xa1b2c3d4, 0);
  header.writeUInt16LE(2, 4);
  header.writeUInt16LE(4, 6);
  header.writeUInt32LE(65535, 16);
  header.writeUInt32LE(1, 20);
  const packets = frames.flatMap((frame, index) => {
    const packetHeader = Buffer.alloc(16);
    packetHeader.writeUInt32LE(1710000000, 0);
    packetHeader.writeUInt32LE(index * 100000, 4);
    packetHeader.writeUInt32LE(frame.length, 8);
    packetHeader.writeUInt32LE(frame.length, 12);
    return [packetHeader, frame];
  });
  return Buffer.concat([header, ...packets]);
}

describe("PCAP traffic analysis", () => {
  it("extracts a bidirectional UDP flow and statistical features", () => {
    const pcap = createPcap([ethernetIpv4UdpFrame(53000, 443, [0xc0, 0x00, 0x00, 0x00, 0x01, 0x08]), ethernetIpv4UdpFrame(443, 53000, [4, 5], true)]);
    const analysis = analyzePcap(pcap);
    expect(analysis.packetCount).toBe(2);
    expect(analysis.flowCount).toBe(1);
    expect(analysis.flows[0].transportProtocol).toBe("UDP");
    expect(analysis.flows[0].applicationProtocol).toBe("QUIC");
    expect(analysis.flows[0].packetCount).toBe(2);
    expect(analysis.flows[0].splt).toHaveLength(2);
  });
});
