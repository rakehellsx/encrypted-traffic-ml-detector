import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { FlowFeature } from "./trafficAnalysis";
import { runAbonnenTlsEngine } from "./openSourceMl";

export const ABONNEN_FEATURE_OPTIONS = [
  "avg_cert_path", "avg_cert_valid_day", "avg_domain_name_length", "avg_duration",
  "avg_IPs_in_DNS", "avg_pkts", "avg_size", "avg_time_diff", "avg_TTL",
  "avg_valid_cert_percent", "cert_key_type", "cert_sig_alg", "cipher_suite_server",
  "is_CNs_in_SNA_dns", "is_O_in_issuer", "is_O_in_subject", "is_ST_in_subject",
  "max_duration", "max_time_diff", "number_of_domains_in_cert", "number_of_flows",
  "packet_loss", "recv_sent_pkts_ratio", "recv_sent_size_ratio", "ssl_version",
  "std_domain_name_length", "std_time_diff", "subject_only_CN", "resumed", "SNI_ssl_ratio",
] as const;

export type AbonnenFeatureName = (typeof ABONNEN_FEATURE_OPTIONS)[number];
export type AbonnenFeatureValues = Record<AbonnenFeatureName, number | string>;
export type AbonnenFeatureSource = "upstream_zeek" | "native_compatibility";
export type AbonnenExtraction = { engine: string; zeekUsed: boolean; fallbackReason: string | null };
type EngineExtraction = {
  featureSet: readonly AbonnenFeatureName[];
  flows: Array<{ flowKey: string; values: AbonnenFeatureValues; source: AbonnenFeatureSource }>;
  extraction: AbonnenExtraction;
};

/**
 * Persists the PCAP only for the lifetime of the Python child process. The child invokes
 * Zeek and applies the upstream Abonnen feature definitions; native flow fields are sent
 * only as an explicit compatibility fallback when Zeek cannot produce a matching tuple.
 */
export async function enrichWithAbonnenFeatures(buffer: Buffer, flows: FlowFeature[]): Promise<{ flows: FlowFeature[]; extraction: AbonnenExtraction }> {
  const directory = await mkdtemp(join(tmpdir(), "trafficguard-abonnen-"));
  const pcapPath = join(directory, "capture.pcap");
  try {
    await writeFile(pcapPath, buffer);
    const response = await runAbonnenTlsEngine<EngineExtraction>({ operation: "extract", pcapPath, flows });
    const byFlowKey = new Map(response.flows.map(item => [item.flowKey, item]));
    return {
      flows: flows.map(flow => {
        const item = byFlowKey.get(flow.flowKey);
        return {
          ...flow,
          abonnen: item?.values,
          abonnenSource: item?.source ?? "native_compatibility",
        };
      }),
      extraction: response.extraction,
    };
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}
