import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { analyzePcap } from '../server/trafficAnalysis.ts';

const samplePath = process.argv[2] ?? resolve(process.cwd(), '../Downloads/synthetic-tls-handshakes.pcap');
const result = analyzePcap(readFileSync(samplePath));
console.log(JSON.stringify({
  packets: result.packetCount,
  flows: result.flows.map((flow) => ({
    fiveTuple: `${flow.sourceIp}:${flow.sourcePort}->${flow.destinationIp}:${flow.destinationPort}/${flow.transportProtocol}`,
    protocol: flow.applicationProtocol,
    tlsVersion: flow.tlsVersion,
    ja3: flow.ja3,
    sni: flow.sni,
    sniVisibility: flow.sniVisibility,
    spltLength: flow.splt.length,
  })),
}, null, 2));
