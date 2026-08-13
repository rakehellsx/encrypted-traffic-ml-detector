import { readFileSync } from 'node:fs';
import { analyzePcap } from '../server/trafficAnalysis.ts';

const result = analyzePcap(readFileSync(process.argv[2]));
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
