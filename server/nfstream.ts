import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { spawn } from "node:child_process";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { analyzePcap, type FlowFeature, type PcapAnalysis } from "./trafficAnalysis";

export type NfstreamFeature = { key: string; bidirectional_packets: number; bidirectional_bytes: number; duration_ms: number; application_name?: string | null; splt_direction: number[]; splt_ps: number[]; splt_piat_ms: number[] };

function key(protocol: string, src: string, sport: number, dst: string, dport: number) { const a = `${src}:${sport}`, b = `${dst}:${dport}`; return a <= b ? `${protocol}|${a}|${b}` : `${protocol}|${b}|${a}`; }

async function extract(buffer: Buffer): Promise<NfstreamFeature[]> {
  const dir = await mkdtemp(join(tmpdir(), "trafficguard-nfstream-")); const pcap = join(dir, "capture.pcap");
  try { await writeFile(pcap, buffer); const output = await new Promise<string>((resolveOutput, reject) => { const child = spawn("python3", [resolve(process.cwd(), "scripts/extract_nfstream.py"), pcap]); let stdout = "", stderr = ""; child.stdout.on("data", chunk => stdout += chunk); child.stderr.on("data", chunk => stderr += chunk); child.on("error", reject); child.on("close", code => code === 0 ? resolveOutput(stdout) : reject(new Error(stderr || "NFStream 执行失败"))); }); return (JSON.parse(output).flows ?? []) as NfstreamFeature[]; } finally { await rm(dir, { recursive: true, force: true }); }
}

export async function analyzePcapWithNfstream(buffer: Buffer): Promise<PcapAnalysis> {
  const analysis = analyzePcap(buffer); try { const features = await extract(buffer); const lookup = new Map(features.map(feature => [feature.key, feature])); analysis.flows = analysis.flows.map(flow => ({ ...flow, nfstream: lookup.get(key(flow.transportProtocol, flow.sourceIp, flow.sourcePort, flow.destinationIp, flow.destinationPort)) ?? null } as FlowFeature)); return analysis; } catch { return analysis; }
}
