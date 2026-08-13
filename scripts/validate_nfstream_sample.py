#!/usr/bin/env python3
"""Extract reproducible NFStream evidence from an approved public QUIC PCAP sample."""
import json
import sys
from nfstream import NFStreamer

pcap = sys.argv[1]
flows = []
for flow in NFStreamer(source=pcap, statistical_analysis=True, splt_analysis=24):
    flows.append({
        "protocol": flow.protocol,
        "src_ip": flow.src_ip,
        "src_port": flow.src_port,
        "dst_ip": flow.dst_ip,
        "dst_port": flow.dst_port,
        "bidirectional_packets": flow.bidirectional_packets,
        "bidirectional_bytes": flow.bidirectional_bytes,
        "bidirectional_duration_ms": flow.bidirectional_duration_ms,
        "splt_direction": list(flow.splt_direction) if flow.splt_direction else [],
        "splt_ps": list(flow.splt_ps) if flow.splt_ps else [],
        "splt_piat_ms": list(flow.splt_piat_ms) if flow.splt_piat_ms else [],
        "application_name": getattr(flow, "application_name", None),
    })
print(json.dumps({"source": pcap, "flow_count": len(flows), "flows": flows[:20]}, ensure_ascii=False, indent=2))
