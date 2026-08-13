import { createHash } from "node:crypto";

export type SpltPoint = { length: number; iatMs: number; direction: "up" | "down" };

export type FlowFeature = {
  flowKey: string;
  sourceIp: string;
  sourcePort: number;
  destinationIp: string;
  destinationPort: number;
  transportProtocol: "TCP" | "UDP";
  applicationProtocol: "TLS" | "QUIC" | "UNKNOWN";
  packetCount: number;
  byteCount: number;
  upPackets: number;
  downPackets: number;
  upBytes: number;
  downBytes: number;
  durationMs: number;
  avgPacketLength: number;
  stdPacketLength: number;
  avgIatMs: number;
  stdIatMs: number;
  uplinkRatio: number;
  splt: SpltPoint[];
  tlsVersion: string;
  ja3: string | null;
  sniVisibility: "visible" | "not_observed";
  sni: string | null;
};

export type PcapAnalysis = {
  packetCount: number;
  flowCount: number;
  protocolDistribution: Record<string, number>;
  flows: FlowFeature[];
};

type MutableFlow = {
  firstTimestamp: number;
  lastTimestamp: number;
  sourceIp: string;
  sourcePort: number;
  destinationIp: string;
  destinationPort: number;
  transportProtocol: "TCP" | "UDP";
  applicationProtocol: "TLS" | "QUIC" | "UNKNOWN";
  packetLengths: number[];
  iats: number[];
  upPackets: number;
  downPackets: number;
  upBytes: number;
  downBytes: number;
  splt: SpltPoint[];
  tlsVersion: string;
  ja3: string | null;
  sni: string | null;
};

const MAX_PACKETS = 50000;
const MAX_FLOWS = 12000;
const MAX_SPLT = 24;

function mean(values: number[]) {
  return values.length ? values.reduce((sum, value) => sum + value, 0) / values.length : 0;
}

function standardDeviation(values: number[], average: number) {
  if (values.length < 2) return 0;
  return Math.sqrt(values.reduce((sum, value) => sum + (value - average) ** 2, 0) / values.length);
}

function ipv4(buffer: Buffer, offset: number) {
  return `${buffer[offset]}.${buffer[offset + 1]}.${buffer[offset + 2]}.${buffer[offset + 3]}`;
}

function ipv6(buffer: Buffer, offset: number) {
  const parts: string[] = [];
  for (let index = 0; index < 16; index += 2) parts.push(buffer.readUInt16BE(offset + index).toString(16));
  return parts.join(":");
}

function tlsVersionName(version: number) {
  const versions: Record<number, string> = { 0x0301: "TLS 1.0", 0x0302: "TLS 1.1", 0x0303: "TLS 1.2", 0x0304: "TLS 1.3" };
  return versions[version] ?? "TLS";
}

function isGrease(value: number) {
  return (value & 0x0f0f) === 0x0a0a && (value >> 8) === (value & 0xff);
}

function parseTlsClientHello(payload: Buffer) {
  if (payload.length < 14 || payload[0] !== 22 || payload[5] !== 1) return null;
  let offset = 9;
  if (offset + 34 > payload.length) return null;
  const clientVersion = payload.readUInt16BE(offset);
  offset += 34;
  const sessionLength = payload[offset] ?? 0;
  offset += 1 + sessionLength;
  if (offset + 2 > payload.length) return null;
  const cipherLength = payload.readUInt16BE(offset);
  offset += 2;
  if (offset + cipherLength > payload.length) return null;
  const ciphers: number[] = [];
  for (let index = 0; index < cipherLength; index += 2) {
    const value = payload.readUInt16BE(offset + index);
    if (!isGrease(value)) ciphers.push(value);
  }
  offset += cipherLength;
  const compressionLength = payload[offset] ?? 0;
  offset += 1 + compressionLength;
  if (offset + 2 > payload.length) return { tlsVersion: tlsVersionName(clientVersion), ja3: null, sni: null };
  const extensionLength = payload.readUInt16BE(offset);
  offset += 2;
  const end = Math.min(payload.length, offset + extensionLength);
  const extensions: number[] = [];
  const groups: number[] = [];
  const points: number[] = [];
  let sni: string | null = null;
  while (offset + 4 <= end) {
    const type = payload.readUInt16BE(offset);
    const length = payload.readUInt16BE(offset + 2);
    const dataStart = offset + 4;
    const dataEnd = dataStart + length;
    if (dataEnd > end) break;
    if (!isGrease(type)) extensions.push(type);
    if (type === 0 && dataStart + 5 <= dataEnd) {
      const nameLength = payload.readUInt16BE(dataStart + 3);
      if (dataStart + 5 + nameLength <= dataEnd) sni = payload.subarray(dataStart + 5, dataStart + 5 + nameLength).toString("utf8");
    }
    if (type === 10 && dataStart + 2 <= dataEnd) {
      const listLength = payload.readUInt16BE(dataStart);
      for (let index = dataStart + 2; index + 1 < Math.min(dataEnd, dataStart + 2 + listLength); index += 2) {
        const group = payload.readUInt16BE(index);
        if (!isGrease(group)) groups.push(group);
      }
    }
    if (type === 11 && dataStart + 1 <= dataEnd) {
      const listLength = payload[dataStart];
      for (let index = dataStart + 1; index < Math.min(dataEnd, dataStart + 1 + listLength); index += 1) points.push(payload[index]);
    }
    offset = dataEnd;
  }
  const ja3Raw = `${clientVersion},${ciphers.join("-")},${extensions.join("-")},${groups.join("-")},${points.join("-")}`;
  return { tlsVersion: tlsVersionName(clientVersion), ja3: createHash("md5").update(ja3Raw).digest("hex"), sni };
}

function parseQuicLongHeader(payload: Buffer) {
  if (payload.length < 6 || (payload[0] & 0x80) === 0) return null;
  const version = payload.readUInt32BE(1);
  if (version === 0) return { version: "QUIC version negotiation" };
  const known: Record<number, string> = { 0x00000001: "QUIC v1 / TLS 1.3", 0x6b3343cf: "QUIC v2 / TLS 1.3" };
  return { version: known[version] ?? `QUIC 0x${version.toString(16)}` };
}

function normalizeEndpoint(ip: string, port: number) {
  return `${ip}:${port}`;
}

function deriveFlowKey(protocol: string, sourceIp: string, sourcePort: number, destinationIp: string, destinationPort: number) {
  const left = normalizeEndpoint(sourceIp, sourcePort);
  const right = normalizeEndpoint(destinationIp, destinationPort);
  return left <= right ? `${protocol}|${left}|${right}` : `${protocol}|${right}|${left}`;
}

export function analyzePcap(buffer: Buffer): PcapAnalysis {
  if (buffer.length < 24) throw new Error("文件不是有效的 PCAP：全局头长度不足");
  const magic = buffer.readUInt32BE(0);
  const littleEndian = magic === 0xd4c3b2a1 || magic === 0x4d3cb2a1;
  const bigEndian = magic === 0xa1b2c3d4 || magic === 0xa1b23c4d;
  if (!littleEndian && !bigEndian) throw new Error("仅支持标准 libpcap 格式（.pcap），暂不支持 PCAPNG");
  const read32 = (offset: number) => (littleEndian ? buffer.readUInt32LE(offset) : buffer.readUInt32BE(offset));
  const linkType = read32(20);
  if (linkType !== 1) throw new Error("当前仅支持以太网链路层的 PCAP 文件");

  const protocolDistribution: Record<string, number> = { TCP: 0, UDP: 0, TLS: 0, QUIC: 0, OTHER: 0 };
  const flows = new Map<string, MutableFlow>();
  let packetCount = 0;
  let offset = 24;

  while (offset + 16 <= buffer.length && packetCount < MAX_PACKETS) {
    const seconds = read32(offset);
    const fraction = read32(offset + 4);
    const includedLength = read32(offset + 8);
    const frameStart = offset + 16;
    const frameEnd = frameStart + includedLength;
    if (includedLength === 0 || frameEnd > buffer.length) break;
    offset = frameEnd;
    packetCount += 1;
    const frame = buffer.subarray(frameStart, frameEnd);
    if (frame.length < 14) {
      protocolDistribution.OTHER += 1;
      continue;
    }
    const timestamp = seconds * 1000 + fraction / 1000;
    const etherType = frame.readUInt16BE(12);
    let ipOffset = 14;
    let sourceIp = "";
    let destinationIp = "";
    let transportProtocol = 0;
    if (etherType === 0x0800 && frame.length >= ipOffset + 20) {
      const headerLength = (frame[ipOffset] & 0x0f) * 4;
      if (headerLength < 20 || frame.length < ipOffset + headerLength) {
        protocolDistribution.OTHER += 1;
        continue;
      }
      transportProtocol = frame[ipOffset + 9];
      sourceIp = ipv4(frame, ipOffset + 12);
      destinationIp = ipv4(frame, ipOffset + 16);
      ipOffset += headerLength;
    } else if (etherType === 0x86dd && frame.length >= ipOffset + 40) {
      transportProtocol = frame[ipOffset + 6];
      sourceIp = ipv6(frame, ipOffset + 8);
      destinationIp = ipv6(frame, ipOffset + 24);
      ipOffset += 40;
    } else {
      protocolDistribution.OTHER += 1;
      continue;
    }
    if (transportProtocol !== 6 && transportProtocol !== 17 || frame.length < ipOffset + 4) {
      protocolDistribution.OTHER += 1;
      continue;
    }
    const sourcePort = frame.readUInt16BE(ipOffset);
    const destinationPort = frame.readUInt16BE(ipOffset + 2);
    const protocol = transportProtocol === 6 ? "TCP" : "UDP";
    protocolDistribution[protocol] += 1;
    let payloadOffset = ipOffset + (protocol === "TCP" ? ((frame[ipOffset + 12] >> 4) * 4 || 20) : 8);
    if (payloadOffset > frame.length) payloadOffset = frame.length;
    const payload = frame.subarray(payloadOffset);
    const flowKey = deriveFlowKey(protocol, sourceIp, sourcePort, destinationIp, destinationPort);
    let flow = flows.get(flowKey);
    if (!flow) {
      if (flows.size >= MAX_FLOWS) continue;
      flow = {
        firstTimestamp: timestamp,
        lastTimestamp: timestamp,
        sourceIp,
        sourcePort,
        destinationIp,
        destinationPort,
        transportProtocol: protocol,
        applicationProtocol: "UNKNOWN",
        packetLengths: [],
        iats: [],
        upPackets: 0,
        downPackets: 0,
        upBytes: 0,
        downBytes: 0,
        splt: [],
        tlsVersion: "UNKNOWN",
        ja3: null,
        sni: null,
      };
      flows.set(flowKey, flow);
    }
    const isUp = flow.sourceIp === sourceIp && flow.sourcePort === sourcePort && flow.destinationIp === destinationIp && flow.destinationPort === destinationPort;
    const iat = Math.max(0, timestamp - flow.lastTimestamp);
    if (flow.packetLengths.length) flow.iats.push(iat);
    flow.lastTimestamp = timestamp;
    flow.packetLengths.push(frame.length);
    if (isUp) {
      flow.upPackets += 1;
      flow.upBytes += frame.length;
    } else {
      flow.downPackets += 1;
      flow.downBytes += frame.length;
    }
    if (flow.splt.length < MAX_SPLT) flow.splt.push({ length: frame.length, iatMs: iat, direction: isUp ? "up" : "down" });

    if (protocol === "TCP") {
      const hello = parseTlsClientHello(payload);
      if (hello) {
        protocolDistribution.TLS += 1;
        flow.applicationProtocol = "TLS";
        flow.tlsVersion = hello.tlsVersion;
        flow.ja3 = hello.ja3;
        flow.sni = hello.sni;
      }
    } else {
      const quic = parseQuicLongHeader(payload);
      if (quic) {
        protocolDistribution.QUIC += 1;
        flow.applicationProtocol = "QUIC";
        flow.tlsVersion = quic.version;
      }
    }
  }

  const normalizedFlows = Array.from(flows.entries()).map(([flowKey, flow]) => {
    const packetCountForFlow = flow.packetLengths.length;
    const byteCount = flow.upBytes + flow.downBytes;
    const avgPacketLength = mean(flow.packetLengths);
    const avgIatMs = mean(flow.iats);
    return {
      flowKey,
      sourceIp: flow.sourceIp,
      sourcePort: flow.sourcePort,
      destinationIp: flow.destinationIp,
      destinationPort: flow.destinationPort,
      transportProtocol: flow.transportProtocol,
      applicationProtocol: flow.applicationProtocol,
      packetCount: packetCountForFlow,
      byteCount,
      upPackets: flow.upPackets,
      downPackets: flow.downPackets,
      upBytes: flow.upBytes,
      downBytes: flow.downBytes,
      durationMs: Math.max(0, flow.lastTimestamp - flow.firstTimestamp),
      avgPacketLength,
      stdPacketLength: standardDeviation(flow.packetLengths, avgPacketLength),
      avgIatMs,
      stdIatMs: standardDeviation(flow.iats, avgIatMs),
      uplinkRatio: byteCount ? flow.upBytes / byteCount : 0,
      splt: flow.splt,
      tlsVersion: flow.tlsVersion,
      ja3: flow.ja3,
      sniVisibility: flow.sni ? ("visible" as const) : ("not_observed" as const),
      sni: flow.sni,
    };
  });
  return { packetCount, flowCount: normalizedFlows.length, protocolDistribution, flows: normalizedFlows };
}
