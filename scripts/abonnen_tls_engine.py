#!/usr/bin/env python3
"""Abonnen/Malicious_TLS_Detection-compatible TLS ML runtime.

The feature schema and classifier parameters below are derived from:
https://github.com/Abonnen/Malicious_TLS_Detection

This adapter keeps the upstream Zeek connection/SSL/X509/DNS feature semantics,
uses the upstream RandomForest and GBDT algorithms, and adds only the platform
boundary required for JSON I/O, stable categorical encoding and five-class labels.
"""
from __future__ import annotations

import base64
import json
import math
import os
import pickle
import shutil
import statistics
import subprocess
import sys
import tempfile
import zlib
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, precision_recall_fscore_support
from sklearn.model_selection import train_test_split

try:
    from lightgbm import LGBMClassifier, early_stopping
except ImportError:  # Allows descriptive validation failures before dependencies are installed.
    LGBMClassifier = None
    early_stopping = None

# Exact selected feature order from upstream machine_learning/include/Dataset.py.
UPSTREAM_FEATURES = [
    "avg_cert_path", "avg_cert_valid_day", "avg_domain_name_length", "avg_duration",
    "avg_IPs_in_DNS", "avg_pkts", "avg_size", "avg_time_diff", "avg_TTL",
    "avg_valid_cert_percent", "cert_key_type", "cert_sig_alg", "cipher_suite_server",
    "is_CNs_in_SNA_dns", "is_O_in_issuer", "is_O_in_subject", "is_ST_in_subject",
    "max_duration", "max_time_diff", "number_of_domains_in_cert", "number_of_flows",
    "packet_loss", "recv_sent_pkts_ratio", "recv_sent_size_ratio", "ssl_version",
    "std_domain_name_length", "std_time_diff", "subject_only_CN", "resumed",
    "SNI_ssl_ratio",
]
CATEGORICAL_FEATURES = {
    "ssl_version", "cipher_suite_server", "cert_key_alg", "cert_sig_alg", "cert_key_type"
}
PLATFORM_CLASSES = [
    "benign", "c2_channel", "data_exfiltration", "lateral_movement", "malware_transfer"
]


def emit(value: dict[str, Any]) -> None:
    print(json.dumps(value, ensure_ascii=False, allow_nan=False))


def number(value: Any, default: float = 0.0) -> float:
    try:
        parsed = float(value)
        return parsed if math.isfinite(parsed) else default
    except (TypeError, ValueError):
        return default


def mean(values: list[float], default: float = 0.0) -> float:
    return float(statistics.fmean(values)) if values else default


def population_std(values: list[float], default: float = -1.0) -> float:
    return float(statistics.pstdev(values)) if values else default


def ratio(top: float, bottom: float, default: float = -1.0) -> float:
    return top / bottom if bottom > 0 else default


def canonical_key(proto: str, src: str, sport: int, dst: str, dport: int) -> str:
    left, right = f"{src}:{sport}", f"{dst}:{dport}"
    return f"{proto.upper()}|{left}|{right}" if left <= right else f"{proto.upper()}|{right}|{left}"


def clean_category(value: Any) -> str:
    if value is None:
        return "__MISSING__"
    if isinstance(value, list):
        value = "|".join(sorted(str(item) for item in value if str(item) not in {"", "-"}))
    normalized = str(value).strip()
    return normalized if normalized and normalized != "-" else "__MISSING__"


def fallback_vector(flow: dict[str, Any]) -> dict[str, Any]:
    """Build upstream-shaped values from the platform's native per-flow telemetry.

    This path is intentionally marked as compatibility mode and is used only where
    Zeek is unavailable (for example, a developer test without the system binary).
    Production image extraction invokes Zeek first.
    """
    duration = number(flow.get("durationMs")) / 1000.0
    avg_iat = number(flow.get("avgIatMs")) / 1000.0
    std_iat = number(flow.get("stdIatMs")) / 1000.0
    up_packets = number(flow.get("upPackets"))
    down_packets = number(flow.get("downPackets"))
    up_bytes = number(flow.get("upBytes"))
    down_bytes = number(flow.get("downBytes"))
    return {
        "avg_cert_path": -1.0,
        "avg_cert_valid_day": 0.0,
        "avg_domain_name_length": 0.0,
        "avg_duration": duration,
        "avg_IPs_in_DNS": 0.0,
        "avg_pkts": up_packets + down_packets,
        "avg_size": up_bytes + down_bytes,
        "avg_time_diff": avg_iat,
        "avg_TTL": 0.0,
        "avg_valid_cert_percent": 0.0,
        "cert_key_type": "__MISSING__",
        "cert_sig_alg": "__MISSING__",
        "cipher_suite_server": "__MISSING__",
        "is_CNs_in_SNA_dns": -1.0,
        "is_O_in_issuer": 0.0,
        "is_O_in_subject": 0.0,
        "is_ST_in_subject": 0.0,
        "max_duration": duration,
        "max_time_diff": avg_iat,
        "number_of_domains_in_cert": 0.0,
        "number_of_flows": 1.0,
        "packet_loss": 0.0,
        "recv_sent_pkts_ratio": ratio(down_packets, up_packets),
        "recv_sent_size_ratio": ratio(down_bytes, up_bytes),
        "ssl_version": clean_category(flow.get("tlsVersion")),
        "std_domain_name_length": -1.0,
        "std_time_diff": std_iat if std_iat else -1.0,
        "subject_only_CN": 0.0,
        "resumed": 0.0,
        "SNI_ssl_ratio": 1.0 if flow.get("sni") else 0.0,
    }


def zeek_rows(log_file: Path) -> list[dict[str, Any]]:
    if not log_file.exists():
        return []
    rows: list[dict[str, Any]] = []
    with log_file.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                parsed = json.loads(line)
                if isinstance(parsed, dict):
                    rows.append(parsed)
            except json.JSONDecodeError:
                continue
    return rows


def extract_zeek_logs(pcap_path: str) -> tuple[dict[str, dict[str, Any]], str | None]:
    """Generate JSON Zeek logs and calculate the upstream tuple-level feature values."""
    zeek = shutil.which("zeek") or shutil.which("bro")
    if not zeek:
        return {}, "Zeek 未安装"
    with tempfile.TemporaryDirectory(prefix="trafficguard-zeek-") as temp_dir:
        command = [zeek, "-C", "-r", os.path.abspath(pcap_path), "LogAscii::use_json=T"]
        completed = subprocess.run(command, cwd=temp_dir, capture_output=True, text=True, timeout=120)
        if completed.returncode != 0:
            detail = (completed.stderr or completed.stdout or "Zeek 解析失败").strip()[-500:]
            return {}, detail
        root = Path(temp_dir)
        conn = zeek_rows(root / "conn.log")
        ssl = zeek_rows(root / "ssl.log") or zeek_rows(root / "tls.log")
        x509 = zeek_rows(root / "x509.log")
        dns = zeek_rows(root / "dns.log")
        if not conn:
            return {}, "Zeek 未生成 conn.log"
        return upstream_vectors_from_logs(conn, ssl, x509, dns), None


def upstream_vectors_from_logs(
    conn_rows: list[dict[str, Any]], ssl_rows: list[dict[str, Any]],
    x509_rows: list[dict[str, Any]], dns_rows: list[dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    """Python 3 adaptation of upstream AnalyzeLog + ConnectionTuple feature semantics."""
    ssl_by_uid = {str(row.get("uid")): row for row in ssl_rows if row.get("uid")}
    x509_by_uid = {str(row.get("id")): row for row in x509_rows if row.get("id")}
    groups: dict[str, dict[str, Any]] = {}
    for conn in conn_rows:
        src, dst = str(conn.get("id.orig_h", "")), str(conn.get("id.resp_h", ""))
        if not src or not dst:
            continue
        proto = str(conn.get("proto", "tcp")).upper()
        sport, dport = int(number(conn.get("id.orig_p"))), int(number(conn.get("id.resp_p")))
        key = canonical_key(proto, src, sport, dst, dport)
        group = groups.setdefault(key, {"key": key, "conn": [], "ssl": [], "x509": [], "dns": [], "dst": dst})
        group["conn"].append(conn)
        tls = ssl_by_uid.get(str(conn.get("uid")))
        if tls:
            group["ssl"].append(tls)
            chain = str(tls.get("cert_chain_fuids", "-"))
            if chain != "-":
                certificate = x509_by_uid.get(chain.split(",")[0])
                if certificate:
                    group["x509"].append(certificate)
    # Upstream adds DNS only to connection tuples that appeared in ssl.log.
    for group in groups.values():
        if not group["ssl"]:
            continue
        destination = group["dst"]
        for entry in dns_rows:
            answers = str(entry.get("answers", ""))
            if destination and destination in answers.split(","):
                group["dns"].append(entry)
    return {key: vector_from_group(group) for key, group in groups.items()}


def vector_from_group(group: dict[str, Any]) -> dict[str, Any]:
    conns: list[dict[str, Any]] = group["conn"]
    tls_rows: list[dict[str, Any]] = group["ssl"]
    certs: list[dict[str, Any]] = group["x509"]
    dns_rows: list[dict[str, Any]] = group["dns"]
    durations = [number(row.get("duration")) for row in conns if str(row.get("duration", "-")) != "-"]
    orig_bytes = [number(row.get("orig_bytes")) for row in conns if str(row.get("orig_bytes", "-")) != "-"]
    resp_bytes = [number(row.get("resp_bytes")) for row in conns if str(row.get("resp_bytes", "-")) != "-"]
    orig_pkts = [number(row.get("orig_pkts")) for row in conns if str(row.get("orig_pkts", "-")) != "-"]
    resp_pkts = [number(row.get("resp_pkts")) for row in conns if str(row.get("resp_pkts", "-")) != "-"]
    timestamps = sorted(number(row.get("ts")) for row in conns)
    differences = [timestamps[index + 1] - timestamps[index] for index in range(max(0, len(timestamps) - 1))]
    ssl_versions = sorted({str(row.get("version")).upper() for row in tls_rows if row.get("version") not in {None, "-"}})
    cipher_suites = sorted({str(row.get("cipher")) for row in tls_rows if row.get("cipher") not in {None, "-"}})
    path_lengths = [len(str(row.get("cert_chain_fuids")).split(",")) for row in tls_rows if row.get("cert_chain_fuids") not in {None, "-"}]
    valid_days: list[float] = []
    validity_percent: list[float] = []
    invalid_certificates = 0
    serials: set[str] = set()
    san_domains: list[str] = []
    cn_in_san: list[int] = []
    sni_in_san: list[int] = []
    subject_o: list[int] = []
    subject_st: list[int] = []
    subject_only_cn: list[int] = []
    issuer_o: list[int] = []
    subject_ip: list[int] = []
    cert_key_types: set[str] = set()
    cert_sig_algs: set[str] = set()
    for cert in certs:
        if cert.get("certificate.key_type") not in {None, "-"}:
            cert_key_types.add(str(cert["certificate.key_type"]))
        if cert.get("certificate.sig_alg") not in {None, "-"}:
            cert_sig_algs.add(str(cert["certificate.sig_alg"]))
        now, before, after = number(cert.get("ts")), number(cert.get("certificate.not_valid_before")), number(cert.get("certificate.not_valid_after"))
        if before and after:
            if now > after or now < before:
                invalid_certificates += 1
            else:
                valid_days.append(max(0.0, (after - before) / 86400.0))
                if after > before:
                    validity_percent.append((now - before) / (after - before))
        serial = str(cert.get("certificate.serial", ""))
        if serial and serial not in serials:
            serials.add(serial)
            domains = [value for value in str(cert.get("san.dns", "-")).split(",") if value and value != "-"]
            san_domains.extend(domains)
            subject_parts = str(cert.get("certificate.subject", "")).split(",")
            cn_values = [part[3:] for part in subject_parts if part.strip().startswith("CN=")]
            if cn_values and domains:
                cn_in_san.append(1 if cn_values[0] in domains else 0)
            if cn_values:
                subject_ip.append(1 if all(piece.isdigit() for piece in cn_values[0].split(".")) else 0)
            subject_o.extend(1 if part.strip().startswith("O=") else 0 for part in subject_parts)
            subject_st.extend(1 if part.strip().startswith("ST=") else 0 for part in subject_parts)
            subject_only_cn.append(1 if subject_parts and all(part.strip().startswith("CN=") for part in subject_parts) else 0)
            issuer_parts = str(cert.get("certificate.issuer", "")).split(",")
            issuer_o.extend(1 if part.strip().startswith("O=") else 0 for part in issuer_parts)
    for tls in tls_rows:
        sni = str(tls.get("server_name", "-"))
        if sni != "-":
            related = [cert for cert in certs if str(cert.get("san.dns", "-")) != "-"]
            for cert in related:
                sni_in_san.append(1 if sni in str(cert.get("san.dns", "")).split(",") else 0)
    ttls: list[float] = []
    domains: list[float] = []
    ips: list[float] = []
    destination = group["dst"]
    for dns in dns_rows:
        query = str(dns.get("query", ""))
        if query:
            domains.append(float(len(query)))
        answers = str(dns.get("answers", "")).split(",")
        ips.append(float(len(answers)))
        ttl_values = str(dns.get("TTLs", "")).split(",")
        if destination in answers:
            position = answers.index(destination)
            if position < len(ttl_values):
                ttls.append(number(ttl_values[position]))
    avg_orig, avg_resp = mean(orig_bytes), mean(resp_bytes)
    avg_orig_pkts, avg_resp_pkts = mean(orig_pkts), mean(resp_pkts)
    return {
        "avg_cert_path": mean(path_lengths, -1.0),
        "avg_cert_valid_day": mean(valid_days, 0.0),
        "avg_domain_name_length": mean(domains, 0.0),
        "avg_duration": mean(durations, 0.0),
        "avg_IPs_in_DNS": mean(ips, 0.0),
        "avg_pkts": avg_orig_pkts + avg_resp_pkts,
        "avg_size": avg_orig + avg_resp,
        "avg_time_diff": mean(differences, 0.0),
        "avg_TTL": mean(ttls, 0.0),
        "avg_valid_cert_percent": mean(validity_percent, 0.0),
        "cert_key_type": clean_category(sorted(cert_key_types)),
        "cert_sig_alg": clean_category(sorted(cert_sig_algs)),
        "cipher_suite_server": clean_category(cipher_suites),
        "is_CNs_in_SNA_dns": 0.0 if 0 in cn_in_san else (1.0 if cn_in_san else -1.0),
        "is_O_in_issuer": mean(issuer_o, 0.0),
        "is_O_in_subject": mean(subject_o, 0.0),
        "is_ST_in_subject": mean(subject_st, 0.0),
        "max_duration": max(durations) if durations else 0.0,
        "max_time_diff": max(differences) if differences else 0.0,
        "number_of_domains_in_cert": float(len(set(san_domains))),
        "number_of_flows": float(len(conns)),
        "packet_loss": sum(number(row.get("missed_bytes")) for row in conns),
        "recv_sent_pkts_ratio": ratio(avg_resp_pkts, avg_orig_pkts),
        "recv_sent_size_ratio": ratio(avg_resp, avg_orig),
        "ssl_version": clean_category(ssl_versions),
        "std_domain_name_length": population_std(domains, -1.0),
        "std_time_diff": population_std(differences, -1.0),
        "subject_only_CN": mean(subject_only_cn, 0.0),
        "resumed": float(sum(1 for row in tls_rows if "T" in str(row.get("resumed", "")))),
        "SNI_ssl_ratio": ratio(float(sum(1 for row in tls_rows if str(row.get("server_name", "-")) != "-")), float(len(tls_rows))),
    }


def extract(data: dict[str, Any]) -> dict[str, Any]:
    fallback_flows = data.get("flows") or []
    vectors: dict[str, dict[str, Any]] = {}
    reason: str | None = None
    pcap_path = data.get("pcapPath")
    if pcap_path:
        vectors, reason = extract_zeek_logs(str(pcap_path))
    output = []
    for flow in fallback_flows:
        flow_key = str(flow.get("flowKey") or canonical_key(
            str(flow.get("transportProtocol", "TCP")), str(flow.get("sourceIp", "")),
            int(number(flow.get("sourcePort"))), str(flow.get("destinationIp", "")), int(number(flow.get("destinationPort"))),
        ))
        output.append({"flowKey": flow_key, "values": vectors.get(flow_key, fallback_vector(flow)), "source": "upstream_zeek" if flow_key in vectors else "native_compatibility"})
    # Zeek may produce tuples that native parser could not expose (e.g. malformed packets).
    if not fallback_flows:
        output = [{"flowKey": key, "values": values, "source": "upstream_zeek"} for key, values in vectors.items()]
    return {"featureSet": UPSTREAM_FEATURES, "flows": output, "extraction": {"engine": "Zeek + Abonnen feature_extract", "zeekUsed": bool(vectors), "fallbackReason": reason}}


def build_encoders(rows: list[dict[str, Any]]) -> dict[str, dict[str, int]]:
    encoders: dict[str, dict[str, int]] = {}
    for feature in CATEGORICAL_FEATURES:
        categories = sorted({clean_category(row.get(feature)) for row in rows})
        encoders[feature] = {category: index + 1 for index, category in enumerate(categories)}
    return encoders


def matrix(rows: list[dict[str, Any]], encoders: dict[str, dict[str, int]]) -> np.ndarray:
    values: list[list[float]] = []
    for row in rows:
        vector: list[float] = []
        for feature in UPSTREAM_FEATURES:
            if feature in CATEGORICAL_FEATURES:
                vocabulary = encoders[feature]
                vector.append(float(vocabulary.get(clean_category(row.get(feature)), 0)))
            else:
                vector.append(number(row.get(feature), -1.0))
        values.append(vector)
    return np.asarray(values, dtype=np.float64)


def metric_report(actual: list[str], predicted: list[str], classes: list[str]) -> dict[str, Any]:
    if not actual:
        return {"accuracy": 0.0, "precision": 0.0, "recall": 0.0, "f1": 0.0, "macroPrecision": 0.0, "macroRecall": 0.0, "macroF1": 0.0, "support": 0, "classMetrics": {}}
    precision, recall, f1, support = precision_recall_fscore_support(actual, predicted, labels=classes, average=None, zero_division=0)
    report = {classes[index]: {"precision": float(precision[index]), "recall": float(recall[index]), "f1": float(f1[index]), "support": int(support[index])} for index in range(len(classes))}
    macro_precision = float(sum(precision) / max(1, len(precision)))
    macro_recall = float(sum(recall) / max(1, len(recall)))
    macro_f1 = float(sum(f1) / max(1, len(f1)))
    return {"accuracy": float(accuracy_score(actual, predicted)), "precision": macro_precision, "recall": macro_recall, "f1": macro_f1, "macroPrecision": macro_precision, "macroRecall": macro_recall, "macroF1": macro_f1, "support": len(actual), "classMetrics": report}


def split_samples(x: np.ndarray, y: np.ndarray) -> tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
    counts = Counter(y.tolist())
    if len(y) < 10 or min(counts.values()) < 2:
        return x, x, y, y
    test_size = max(len(counts), int(round(len(y) * 0.1)))
    if test_size >= len(y) - len(counts):
        return x, x, y, y
    return train_test_split(x, y, test_size=test_size, random_state=2019, stratify=y)


def train(data: dict[str, Any]) -> dict[str, Any]:
    samples = data.get("samples") or []
    if len(samples) < 10:
        raise ValueError("至少需要 10 条已标注的上游 TLS 特征样本")
    rows = [sample.get("values") or {} for sample in samples]
    labels = [str(sample.get("label")) for sample in samples]
    unknown = sorted(set(labels) - set(PLATFORM_CLASSES))
    if unknown:
        raise ValueError(f"存在不受支持的流量类别: {', '.join(unknown)}")
    classes = [label for label in PLATFORM_CLASSES if label in set(labels)]
    if len(classes) < 2 or "benign" not in classes:
        raise ValueError("训练至少需要正常流量与一种恶意流量")
    encoders = build_encoders(rows)
    x = matrix(rows, encoders)
    y = np.asarray(labels, dtype=object)
    train_x, validation_x, train_y, validation_y = split_samples(x, y)
    algorithm = str(data.get("algorithm", "abonnen_random_forest"))
    if algorithm == "abonnen_random_forest":
        # Exact upstream parameters: n_estimators=100, max_depth=30, random_state=1024.
        model = RandomForestClassifier(n_estimators=100, max_depth=30, random_state=1024, n_jobs=1)
    elif algorithm == "abonnen_gbdt":
        if LGBMClassifier is None:
            raise RuntimeError("缺少 lightgbm，请安装 requirements-ml.txt")
        # Exact upstream parameters from machine_learning/lightGBM/gbdt.py.
        model = LGBMClassifier(boosting_type="gbdt", importance_type="split", num_leaves=50, min_child_samples=100, max_depth=8, random_state=2019, n_jobs=1, verbosity=-1)
    else:
        raise ValueError("仅支持 abonnen_random_forest 或 abonnen_gbdt")
    fit_kwargs: dict[str, Any] = {}
    if algorithm == "abonnen_gbdt" and len(train_x) != len(validation_x) and early_stopping is not None:
        fit_kwargs = {"eval_set": [(validation_x, validation_y)], "eval_metric": ["multi_logloss"], "callbacks": [early_stopping(100, verbose=False)]}
    model.fit(train_x, train_y, **fit_kwargs)
    prediction = [str(value) for value in model.predict(validation_x)]
    metrics = metric_report(validation_y.tolist(), prediction, classes)
    artifact = {"model": model, "encoders": encoders, "features": UPSTREAM_FEATURES, "algorithm": algorithm}
    compressed = base64.b64encode(zlib.compress(pickle.dumps(artifact, protocol=pickle.HIGHEST_PROTOCOL), 9)).decode("ascii")
    return {
        "payload": {
            "kind": "abonnen_tls",
            "source": "Abonnen/Malicious_TLS_Detection",
            "frameworks": ["Zeek", "NFStream (parallel)", "scikit-learn" if algorithm == "abonnen_random_forest" else "LightGBM"],
            "algorithm": algorithm,
            "classes": PLATFORM_CLASSES,
            "trainedClasses": [str(item) for item in model.classes_],
            "features": UPSTREAM_FEATURES,
            "artifact": compressed,
            "categoricalEncoders": encoders,
        },
        "metrics": metrics,
        "trainingCount": int(len(train_x)),
        "validationCount": int(len(validation_x)),
        "classes": PLATFORM_CLASSES,
    }


def score(data: dict[str, Any]) -> dict[str, Any]:
    payload = data.get("payload") or {}
    if payload.get("kind") != "abonnen_tls":
        raise ValueError("模型工件不是 Abonnen TLS 检测模型")
    artifact = pickle.loads(zlib.decompress(base64.b64decode(payload["artifact"])))
    rows = data.get("values") or []
    x = matrix(rows, artifact["encoders"])
    probabilities = artifact["model"].predict_proba(x)
    model_classes = [str(value) for value in artifact["model"].classes_]
    importances = getattr(artifact["model"], "feature_importances_", np.zeros(len(UPSTREAM_FEATURES)))
    important_indices = np.argsort(np.asarray(importances))[-3:][::-1].tolist()
    scores = []
    for row, probability in zip(rows, probabilities):
        by_class = {label: 0.0 for label in PLATFORM_CLASSES}
        for label, value in zip(model_classes, probability):
            if label in by_class:
                by_class[label] = float(value)
        predicted = max(PLATFORM_CLASSES, key=lambda label: by_class[label])
        explanation = [{"feature": UPSTREAM_FEATURES[index], "value": row.get(UPSTREAM_FEATURES[index], "__MISSING__"), "importance": float(importances[index])} for index in important_indices]
        scores.append({"probabilities": by_class, "predictedClass": predicted, "riskScore": float(1.0 - by_class["benign"]), "explanation": explanation})
    return {"scores": scores}


def main() -> None:
    request = json.load(sys.stdin)
    operation = request.get("operation")
    if operation == "extract":
        emit(extract(request))
    elif operation == "train":
        emit(train(request))
    elif operation == "score":
        emit(score(request))
    elif operation == "schema":
        emit({"features": UPSTREAM_FEATURES, "classes": PLATFORM_CLASSES})
    else:
        raise ValueError("unknown operation")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        emit({"error": str(error)})
        sys.exit(1)
