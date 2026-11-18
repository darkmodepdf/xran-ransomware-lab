"""Endpoint classification metrics and a reproducible benign alarm budget."""

import math

import numpy as np


def validated_scores(scores):
    values = np.asarray(scores, dtype=np.float64)
    if values.ndim != 1 or not np.all(np.isfinite(values)) or np.any((values < 0) | (values > 1)):
        raise ValueError("Expected a vector of finite scores in [0, 1]")
    return values


def calibrate(scores, alpha=0.05):
    values = validated_scores(scores)
    if not len(values) or not math.isfinite(alpha) or not 0 <= alpha < 1:
        raise ValueError("Calibration requires scores and a budget in [0, 1)")
    allowed = math.floor(alpha * len(values))
    boundary = np.sort(values)[::-1][allowed]
    threshold = float(np.nextafter(boundary, math.inf))
    enabled = threshold <= 1
    alerts = int(np.sum(values >= threshold)) if enabled else 0
    return {"threshold": threshold if enabled else None, "alarm_enabled": enabled,
            "target_rate": float(alpha), "n": len(values), "allowed": allowed,
            "alerts": alerts, "actual_fpr": alerts / len(values)}


def wilson(successes, total):
    if total == 0:
        return None
    z = 1.959963984540054
    p = successes / total
    denominator = 1 + z * z / total
    midpoint = (p + z * z / (2 * total)) / denominator
    half = z * math.sqrt(p * (1 - p) / total + z * z / (4 * total * total)) / denominator
    return [max(0.0, midpoint - half), min(1.0, midpoint + half)]


def ranking_metrics(labels, scores):
    order = np.argsort(-scores, kind="stable")
    target, ordered = labels[order], scores[order]
    positives, negatives = int(labels.sum()), int(len(labels) - labels.sum())
    if not len(target):
        return None, None
    ends = np.r_[np.flatnonzero(np.diff(ordered)), len(ordered) - 1]
    tp = np.cumsum(target)[ends].astype(np.float64)
    fp = ends + 1 - tp
    ap = float(np.sum(np.diff(np.r_[0.0, tp]) / positives * tp / (ends + 1))) if positives else None
    if not positives or not negatives:
        return None, ap
    tpr, fpr = np.r_[0.0, tp / positives], np.r_[0.0, fp / negatives]
    auc = float(np.sum(np.diff(fpr) * (tpr[:-1] + tpr[1:]) / 2))
    return auc, ap


def binary_metrics(labels, scores, threshold):
    values = validated_scores(scores)
    target = np.asarray(labels)
    if target.ndim != 1 or len(target) != len(values) or not np.all((target == 0) | (target == 1)):
        raise ValueError("Expected aligned binary labels and scores")
    if threshold is not None and (not math.isfinite(threshold) or not 0 <= threshold <= 1):
        raise ValueError("Invalid endpoint threshold")
    predicted = values >= threshold if threshold is not None else np.zeros(len(values), dtype=bool)
    tp = int(np.sum(predicted & (target == 1)))
    fn = int(np.sum(~predicted & (target == 1)))
    tn = int(np.sum(~predicted & (target == 0)))
    fp = int(np.sum(predicted & (target == 0)))
    undefined = {}

    def ratio(name, numerator, denominator):
        if denominator == 0:
            undefined[name] = "Denominator is zero in this cohort"
            return None
        return numerator / denominator

    accuracy = ratio("accuracy", tp + tn, len(target))
    precision = ratio("precision", tp, tp + fp)
    recall = ratio("recall", tp, tp + fn)
    specificity = ratio("specificity", tn, tn + fp)
    fpr = ratio("fpr", fp, tn + fp)
    fnr = ratio("fnr", fn, tp + fn)
    f1 = ratio("f1", 2 * tp, 2 * tp + fp + fn)
    balanced = (recall + specificity) / 2 if recall is not None and specificity is not None else None
    if balanced is None:
        undefined["balanced_accuracy"] = "Both classes are required"
    mcc = ratio("mcc", tp * tn - fp * fn, math.sqrt((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn)))
    auc, ap = ranking_metrics(target.astype(np.int64), values)
    if auc is None:
        undefined["roc_auc"] = "Both classes are required"
    if ap is None:
        undefined["average_precision"] = "At least one positive example is required"
    negative = {"precision": ratio("negative_precision", tn, tn + fn),
                "recall": specificity, "f1": ratio("negative_f1", 2 * tn, 2 * tn + fp + fn), "support": tn + fp}
    positive = {"precision": precision, "recall": recall, "f1": f1, "support": tp + fn}
    metrics = {"accuracy": accuracy, "precision": precision, "recall": recall, "f1": f1,
               "specificity": specificity, "fpr": fpr, "fnr": fnr, "balanced_accuracy": balanced,
               "mcc": mcc, "roc_auc": auc, "average_precision": ap, "undefined_reasons": undefined,
               "class_report": {"healthy": negative, "ransomware": positive},
               "intervals": {"method": "Wilson 95%; feature groups, not verified executable identities",
                             "fpr": wilson(fp, fp + tn), "recall": wilson(tp, tp + fn)}}
    return {"metrics": metrics, "confusion": {"tp": tp, "fn": fn, "tn": tn, "fp": fp}}
