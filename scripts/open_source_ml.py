#!/usr/bin/env python3
"""Open-source ML runtime: LightGBM supervised classification + Kitsune KitNET anomaly scoring."""
import base64
import json
import os
import pickle
import sys
import zlib

import numpy as np
from lightgbm import LGBMClassifier

if not hasattr(np, "Inf"):
    np.Inf = np.inf

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "vendor", "kitsune"))
from KitNET.KitNET import KitNET


def emit(value):
    print(json.dumps(value, ensure_ascii=False))


def metrics(actual, predicted, classes):
    rows = {}
    for label in classes:
        tp = sum(1 for truth, guess in zip(actual, predicted) if truth == label and guess == label)
        fp = sum(1 for truth, guess in zip(actual, predicted) if truth != label and guess == label)
        fn = sum(1 for truth, guess in zip(actual, predicted) if truth == label and guess != label)
        precision = tp / max(1, tp + fp)
        recall = tp / max(1, tp + fn)
        f1 = 2 * precision * recall / max(1e-9, precision + recall)
        rows[label] = {"precision": precision, "recall": recall, "f1": f1, "support": sum(1 for item in actual if item == label)}
    precision = sum(row["precision"] for row in rows.values()) / max(1, len(rows))
    recall = sum(row["recall"] for row in rows.values()) / max(1, len(rows))
    f1 = sum(row["f1"] for row in rows.values()) / max(1, len(rows))
    return {"accuracy": sum(1 for truth, guess in zip(actual, predicted) if truth == guess) / max(1, len(actual)), "precision": precision, "recall": recall, "f1": f1, "macroPrecision": precision, "macroRecall": recall, "macroF1": f1, "support": len(actual), "classMetrics": rows}


def train(data):
    samples = data["samples"]
    features = data["features"]
    classes = sorted({item["label"] for item in samples})
    x = np.asarray([item["values"] for item in samples], dtype=np.float64)
    y = np.asarray([classes.index(item["label"]) for item in samples], dtype=np.int32)
    validation_mask = np.arange(len(samples)) % 5 == 0
    train_x, test_x = x[~validation_mask], x[validation_mask]
    train_y, test_y = y[~validation_mask], y[validation_mask]
    if len(train_x) < len(classes):
        train_x, train_y, test_x, test_y = x, y, x, y
    supervised = LGBMClassifier(objective="multiclass", num_class=len(classes), n_estimators=80, learning_rate=0.08, max_depth=4, num_leaves=15, min_child_samples=1, min_split_gain=0.0, n_jobs=1, verbosity=-1, random_state=42)
    supervised.fit(train_x, train_y)
    prediction = supervised.predict(test_x).astype(int)
    normal_rows = train_x[train_y == classes.index("benign")] if "benign" in classes else train_x
    fm_grace = min(4, max(1, len(normal_rows) // 3))
    ad_grace = min(6, max(1, len(normal_rows) // 2))
    kitnet = KitNET(n=len(features), max_autoencoder_size=min(10, len(features)), FM_grace_period=fm_grace, AD_grace_period=ad_grace, learning_rate=0.1, hidden_ratio=0.75)
    for row in normal_rows:
        kitnet.train(row)
    return {"payload": {"kind": "opensource_ml", "frameworks": ["NFStream", "LightGBM", "Kitsune-KitNET"], "classes": classes, "features": features, "lightgbm": base64.b64encode(zlib.compress(pickle.dumps(supervised), 9)).decode(), "kitnet": base64.b64encode(zlib.compress(pickle.dumps(kitnet), 9)).decode(), "kitnetGrace": {"featureMapping": fm_grace, "anomalyDetector": ad_grace}}, "metrics": metrics([classes[item] for item in test_y], [classes[item] for item in prediction], classes), "trainingCount": int(len(train_x)), "validationCount": int(len(test_x)), "classes": classes}


def score(data):
    payload = data["payload"]
    x = np.asarray(data["values"], dtype=np.float64)
    supervised = pickle.loads(zlib.decompress(base64.b64decode(payload["lightgbm"])))
    kitnet = pickle.loads(zlib.decompress(base64.b64decode(payload["kitnet"])))
    probabilities = supervised.predict_proba(x)
    output = []
    for row, probability in zip(x, probabilities):
        anomaly = float(kitnet.execute(row))
        normalized = 1 - np.exp(-max(0.0, anomaly))
        output.append({"probabilities": [float(value) for value in probability], "anomalyScore": normalized, "anomalyRaw": anomaly})
    return {"scores": output}


def main():
    request = json.load(sys.stdin)
    if request["operation"] == "train": emit(train(request))
    elif request["operation"] == "score": emit(score(request))
    else: raise ValueError("unknown operation")


if __name__ == "__main__":
    try: main()
    except Exception as error:
        emit({"error": str(error)})
        sys.exit(1)
