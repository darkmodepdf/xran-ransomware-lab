"""API contract tests use synthetic data; these are not model measurements."""

import copy
import importlib.util
import json
import tempfile
import threading
import unittest
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("xran_dashboard", ROOT / "demo/xran_dashboard/server.py")
dashboard = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(dashboard)


def synthetic_report():
    """Small hand-checkable evaluation solely for testing presentation and transport."""
    metrics = {"accuracy": .75, "precision": .75, "recall": .75, "f1": .75,
               "specificity": .75, "fpr": .25, "fnr": .25, "balanced_accuracy": .75,
               "mcc": .5, "roc_auc": .8, "average_precision": .8}
    model = {"id": "counts", "label": "Synthetic API test fixture", "seed": 17,
             "status": "evaluated", "metrics": metrics,
             "confusion": {"tp": 3, "fn": 1, "tn": 3, "fp": 1},
             "threshold": .6, "alarm_enabled": True,
             "calibration": {"target_rate": .05, "n": 20, "allowed": 1, "alerts": 1,
                             "actual_fpr": .05, "threshold": .6, "alarm_enabled": True},
             "source_metrics": [{"source": "Single-class synthetic source", "groups": 4,
                                 "confusion": {"tp": 3, "fn": 1, "tn": 0, "fp": 0},
                                 "metrics": {"recall": .75, "fpr": None, "f1": 6/7},
                                 "undefined_reasons": {"fpr": "No negative examples"}}]}
    return {"schema": dashboard.SCHEMA, "generated_at": "2026-11-17T00:00:00Z",
            "dataset": {"name": "SYNTHETIC TEST FIXTURE — not trained results", "test_groups": 8},
            "nominal_fpr_budget": .05, "models": [model],
            "limitations": ["Synthetic fixture, not a model measurement."], "diagnostics": {}}


class DashboardApiTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.report_path = Path(self.temp.name) / "evaluation.json"
        self.server = dashboard.make_server(self.report_path, port=0)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.server.server_port}"

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()
        self.temp.cleanup()

    def write_report(self, report=None):
        self.report_path.write_text(json.dumps(report or synthetic_report()), encoding="utf-8")

    def request(self, route, method="GET"):
        try:
            response = urlopen(Request(self.base + route, method=method), timeout=5)
        except HTTPError as error:
            response = error
        with response:
            body = response.read()
            if response.headers.get_content_type() == "application/json":
                body = json.loads(body)
            return response.status, body, response.headers

    def test_missing_export_is_unavailable_but_page_and_health_work(self):
        status, value, _ = self.request("/api/xran/evaluation")
        self.assertEqual(status, 503)
        self.assertEqual(value["code"], "evaluation_unavailable")
        status, metadata, _ = self.request("/api/xran/metadata")
        self.assertEqual(status, 200)
        self.assertFalse(metadata["evaluation_available"])
        self.assertFalse(metadata["classification_available"])
        self.assertEqual(metadata["models"], [])
        self.assertEqual(self.request("/api/health")[1], {"status": "ok", "evaluation_available": False})
        status, page, headers = self.request("/")
        self.assertEqual(status, 200)
        self.assertIn(b"No measured results available", page)
        self.assertIn("default-src 'self'", headers["Content-Security-Policy"])

    def test_real_export_transport_preserves_evidence_and_null_source_metrics(self):
        expected = synthetic_report()
        expected["dataset"]["name"] = "<script>must remain text</script>"
        self.write_report(expected)
        status, report, headers = self.request("/api/xran/evaluation")
        self.assertEqual(status, 200)
        self.assertEqual(report, expected)
        self.assertIsNone(report["models"][0]["source_metrics"][0]["metrics"]["fpr"])
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertEqual(self.request("/api/xran/metadata")[1]["models"][0]["id"], "counts")

    def test_bad_replacement_does_not_serve_stale_success(self):
        self.write_report()
        self.assertEqual(self.request("/api/xran/evaluation")[0], 200)
        self.report_path.write_text('{"schema":', encoding="utf-8")
        status, error, _ = self.request("/api/xran/evaluation")
        self.assertEqual(status, 503)
        self.assertEqual(error["code"], "invalid_evaluation")
        self.assertFalse(self.request("/api/xran/metadata")[1]["evaluation_available"])

    def test_rejects_wrong_schema_nonfinite_and_duplicate_json(self):
        bad = synthetic_report()
        bad["schema"] = "raneval-linux-benchmark-v1"
        self.write_report(bad)
        self.assertEqual(self.request("/api/xran/evaluation")[0], 503)
        self.report_path.write_text('{"schema":"a","schema":"b"}', encoding="utf-8")
        self.assertIn("Duplicate JSON key", self.request("/api/xran/evaluation")[1]["message"])
        self.report_path.write_text('{"metric":NaN}', encoding="utf-8")
        self.assertIn("Nonfinite JSON value", self.request("/api/xran/evaluation")[1]["message"])

    def test_rejects_malformed_completed_result_and_inconsistent_cohorts(self):
        for mutate in (
            lambda r: r["models"][0]["confusion"].update(tp=-1),
            lambda r: r["models"][0]["metrics"].update(fpr=1.1),
            lambda r: r["models"][0].update(status="training"),
            lambda r: r["models"][0].update(threshold=None),
            lambda r: r["models"][0]["calibration"].update(alerts=2),
            lambda r: r["models"][0]["calibration"].update(actual_fpr=.1),
            lambda r: r["models"][0]["calibration"].update(threshold=.7),
            lambda r: r["dataset"].update(test_groups=9),
        ):
            report = synthetic_report()
            mutate(report)
            self.write_report(report)
            self.assertEqual(self.request("/api/xran/evaluation")[0], 503)
        report = synthetic_report()
        second = copy.deepcopy(report["models"][0])
        second.update(id="cnn")
        second["confusion"]["tp"] = 4
        report["models"].append(second)
        self.write_report(report)
        self.assertEqual(self.request("/api/xran/evaluation")[0], 503)

    def test_disabled_alarms_and_undefined_metrics_remain_explicit(self):
        report = synthetic_report()
        model = report["models"][0]
        model.update(threshold=None, alarm_enabled=False)
        model["calibration"].update(threshold=None, alarm_enabled=False, alerts=0, actual_fpr=0)
        model["metrics"]["precision"] = None
        model["undefined_reasons"] = {"precision": "No predicted positives"}
        self.write_report(report)
        status, result, _ = self.request("/api/xran/evaluation")
        self.assertEqual(status, 200)
        self.assertIsNone(result["models"][0]["threshold"])
        self.assertFalse(result["models"][0]["alarm_enabled"])

    def test_mutation_and_arbitrary_file_reads_are_unavailable(self):
        self.write_report()
        before = self.report_path.read_bytes()
        for method in ("POST", "PUT", "PATCH", "DELETE"):
            self.assertEqual(self.request("/api/xran/classify", method)[0], 405)
        for route in ("/server.py", "/../evaluation.json", "/evaluation.json"):
            self.assertEqual(self.request(route)[0], 404)
        self.assertEqual(self.report_path.read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
