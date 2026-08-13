#!/usr/bin/env python3
"""Emit NFStream flow records in a stable JSON form for the Node pipeline."""
import json, sys
from nfstream import NFStreamer

pcap = sys.argv[1]
records = []
for flow in NFStreamer(source=pcap, statistical_analysis=True, splt_analysis=24):
    proto = "TCP" if flow.protocol == 6 else "UDP" if flow.protocol == 17 else str(flow.protocol)
    records.append({"key": f"{proto}|{flow.src_ip}:{flow.src_port}|{flow.dst_ip}:{flow.dst_port}", "bidirectional_packets": flow.bidirectional_packets, "bidirectional_bytes": flow.bidirectional_bytes, "duration_ms": flow.bidirectional_duration_ms, "application_name": getattr(flow, "application_name", None), "splt_direction": list(getattr(flow, "splt_direction", []) or []), "splt_ps": list(getattr(flow, "splt_ps", []) or []), "splt_piat_ms": list(getattr(flow, "splt_piat_ms", []) or [])})
print(json.dumps({"source": "nfstream", "flows": records}))
