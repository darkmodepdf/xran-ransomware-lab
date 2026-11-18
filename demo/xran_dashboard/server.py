"""Read-only XRan evaluation dashboard. Uses only Python's standard library."""

from __future__ import annotations

import argparse
import json
import math
import platform
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit


SCHEMA = "xran-endpoint-evaluation-v1"
STATIC = Path(__file__).with_name("static")
DEFAULT_REPORT = Path(__file__).resolve().parents[2] / "runs/xran-original/evaluation.json"
MAX_REPORT_BYTES = 16 * 1024 * 1024
METRICS = ("accuracy", "precision", "recall", "f1", "specificity", "fpr", "fnr",
           "balanced_accuracy", "mcc", "roc_auc", "average_precision")
ASSETS = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
    "/styles.css": ("styles.css", "text/css; charset=utf-8"),
}
LIMITATIONS = [
    "These are Windows behavioral feature vectors, not live telemetry or timed event streams.",
    "Exact feature grouping does not establish executable, family, or temporal independence.",
    "The nominal calibration budget does not guarantee the same false-positive rate on new data.",
    "This release cannot measure detection time, encryption damage, files saved, or ransomware prevention.",
    "Results reconstruct the released XRan dataset experiment; they are not an exact paper reproduction.",
]


class ReportError(ValueError):
    """An artifact cannot be safely presented as a completed evaluation."""


def require(condition, message):
    if not condition:
        raise ReportError(message)


def finite_number(value, low=0, high=1):
    return type(value) in (int, float) and math.isfinite(value) and low <= value <= high


def validate_confusion(confusion, location):
    require(isinstance(confusion, dict), f"{location} must be an object")
    require(all(type(confusion.get(key)) is int and confusion[key] >= 0
                for key in ("tp", "fn", "tn", "fp")),
            f"{location} requires nonnegative integer tp, fn, tn, and fp")
    return sum(confusion[key] for key in ("tp", "fn", "tn", "fp"))


def validate_metrics(metrics, location, complete=True):
    require(isinstance(metrics, dict), f"{location} must be an object")
    for key in METRICS:
        if not complete and key not in metrics:
            continue
        require(key in metrics, f"{location}.{key} is missing")
        value = metrics[key]
        require(value is None or finite_number(value, -1 if key == "mcc" else 0),
                f"{location}.{key} must be finite or null when undefined")


def validate_report(report):
    """Validate presentation-critical fields without rewriting exported evidence."""
    require(isinstance(report, dict) and report.get("schema") == SCHEMA,
            f"Expected schema {SCHEMA}")
    require(isinstance(report.get("dataset"), dict), "dataset must be an object")
    require(finite_number(report.get("nominal_fpr_budget")), "Invalid nominal_fpr_budget")
    require(isinstance(report.get("models"), list) and report["models"],
            "No evaluated models are present")
    require(isinstance(report.get("limitations", []), list)
            and all(isinstance(item, str) for item in report.get("limitations", [])),
            "limitations must be a list of strings")
    model_ids, group_counts = set(), set()
    for model in report["models"]:
        require(isinstance(model, dict), "Each model must be an object")
        identifier = model.get("id")
        require(isinstance(identifier, str) and identifier and identifier not in model_ids,
                "Each model requires a unique nonempty id")
        model_ids.add(identifier)
        require(isinstance(model.get("label"), str) and model["label"], f"{identifier}: missing label")
        require(type(model.get("seed")) is int, f"{identifier}: seed must be an integer")
        require(model.get("status", "evaluated") == "evaluated", f"{identifier}: evaluation is incomplete")
        count = validate_confusion(model.get("confusion"), f"{identifier}.confusion")
        require(count > 0, f"{identifier}: test cohort is empty")
        group_counts.add(count)
        validate_metrics(model.get("metrics"), f"{identifier}.metrics")
        calibration = model.get("calibration")
        require(isinstance(calibration, dict), f"{identifier}: calibration is missing")
        require(type(calibration.get("n")) is int and calibration["n"] > 0,
                f"{identifier}: calibration requires a positive benign-group count")
        require(finite_number(calibration.get("target_rate"))
                and calibration["target_rate"] == report["nominal_fpr_budget"],
                f"{identifier}: calibration target disagrees with the report budget")
        require(type(calibration.get("allowed")) is int
                and calibration["allowed"] == math.floor(calibration["target_rate"] * calibration["n"]),
                f"{identifier}: allowed calibration alarms disagree with the budget")
        require(type(calibration.get("alerts")) is int
                and 0 <= calibration["alerts"] <= calibration["allowed"],
                f"{identifier}: calibration alarms exceed the stated budget")
        require(finite_number(calibration.get("actual_fpr"))
                and math.isclose(calibration["actual_fpr"], calibration["alerts"] / calibration["n"], abs_tol=1e-12),
                f"{identifier}: calibration FPR disagrees with its counts")
        enabled = model.get("alarm_enabled", calibration.get("alarm_enabled"))
        threshold = model.get("threshold", calibration.get("threshold"))
        require(type(enabled) is bool, f"{identifier}: alarm_enabled must be boolean")
        require((enabled and finite_number(threshold)) or (not enabled and threshold is None),
                f"{identifier}: threshold and alarm_enabled disagree")
        require(calibration.get("alarm_enabled") is enabled
                and calibration.get("threshold") == threshold,
                f"{identifier}: model and calibration operating points disagree")
        require(enabled or calibration["alerts"] == 0,
                f"{identifier}: disabled alarms cannot have calibration alerts")
        require(isinstance(model.get("source_metrics", []), list),
                f"{identifier}: source_metrics must be a list")
        for source in model.get("source_metrics", []):
            require(isinstance(source, dict) and isinstance(source.get("source"), str),
                    f"{identifier}: invalid source metrics entry")
            source_count = validate_confusion(source.get("confusion"), f"{identifier}.{source['source']}")
            if "groups" in source:
                require(type(source["groups"]) is int and source["groups"] == source_count,
                        f"{identifier}: source group count disagrees with confusion matrix")
            validate_metrics(source.get("metrics"), f"{identifier}.{source['source']}.metrics", complete=False)
    require(len(group_counts) == 1, "Primary models do not share the same test-group count")
    test_groups = report["dataset"].get("test_groups")
    if test_groups is not None:
        require(type(test_groups) is int and test_groups in group_counts,
                "dataset.test_groups disagrees with the confusion matrices")
    return report


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, f"Duplicate JSON key: {key}")
        result[key] = value
    return result


def reject_constant(value):
    raise ReportError(f"Nonfinite JSON value: {value}")


class Dashboard:
    def __init__(self, report_path=DEFAULT_REPORT):
        self.report_path = Path(report_path)

    def read_evaluation(self):
        try:
            with self.report_path.open("rb") as stream:
                data = stream.read(MAX_REPORT_BYTES + 1)
        except FileNotFoundError:
            return 503, {"code": "evaluation_unavailable", "message":
                         "No completed XRan evaluation export is available. Train and export real results before comparing models."}
        except OSError:
            return 503, {"code": "evaluation_unavailable", "message": "The evaluation export cannot be read."}
        try:
            require(len(data) <= MAX_REPORT_BYTES, "Evaluation export exceeds the size limit")
            report = json.loads(data.decode("utf-8-sig"), object_pairs_hook=unique_object,
                                parse_constant=reject_constant)
            validate_report(report)
            # Reject nonfinite values in optional diagnostics too, before JSON transport.
            json.dumps(report, allow_nan=False)
        except (ValueError, UnicodeError, RecursionError) as error:
            return 503, {"code": "invalid_evaluation", "message": f"Evaluation export rejected: {error}"}
        return 200, report

    def metadata(self):
        status, value = self.read_evaluation()
        available = status == 200
        return {
            "schema": "xran-dashboard-metadata-v1", "evaluation_available": available,
            "dataset_label": "Windows behavioral features · XRan release",
            "task": "Endpoint ransomware-versus-benign classification",
            "prediction_unit": "Unique released feature vector",
            "feature_positions": {"api": 500, "dll": 10, "mutex": 10},
            "runtime": f"Python standard library · {platform.system()}",
            "read_only": True, "classification_available": False,
            "report_file": self.report_path.name,
            "limitations": LIMITATIONS,
            "models": [{"id": model["id"], "label": model["label"], "seed": model["seed"]}
                       for model in value["models"]] if available else [],
            "evaluation_error": None if available else value,
        }


def make_server(report_path=DEFAULT_REPORT, host="127.0.0.1", port=8766):
    dashboard = Dashboard(report_path)

    class Handler(BaseHTTPRequestHandler):
        def respond(self, status, payload, content_type="application/json; charset=utf-8"):
            body = payload if isinstance(payload, bytes) else json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            route = urlsplit(self.path).path
            if route in ASSETS:
                filename, content_type = ASSETS[route]
                self.respond(200, (STATIC / filename).read_bytes(), content_type)
            elif route == "/api/xran/evaluation":
                self.respond(*dashboard.read_evaluation())
            elif route == "/api/xran/metadata":
                self.respond(200, dashboard.metadata())
            elif route in ("/api/health", "/health"):
                self.respond(200, {"status": "ok", "evaluation_available": dashboard.read_evaluation()[0] == 200})
            else:
                self.respond(404, {"code": "not_found", "message": "Unknown dashboard resource."})

        def do_POST(self):
            self.respond(405, {"code": "read_only", "message": "This dashboard serves evaluation exports only. Classification is not connected."})

        do_PUT = do_POST
        do_PATCH = do_POST
        do_DELETE = do_POST

    return ThreadingHTTPServer((host, port), Handler)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8766)
    args = parser.parse_args()
    with make_server(args.report, args.host, args.port) as server:
        print(f"XRan evaluation dashboard: http://{args.host}:{server.server_port}/", flush=True)
        print(f"Read-only evaluation export: {args.report.resolve()}", flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    main()
