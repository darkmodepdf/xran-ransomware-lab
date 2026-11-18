import json
import subprocess
import sys
import unittest
from pathlib import Path


RUNNER = Path(__file__).with_name("runner.py")


def run_cli(bundle=None):
    args = [sys.executable, str(RUNNER), "--json", "--delay-ms", "0"]
    if bundle is not None:
        args.append("--scores-stdin")
    return subprocess.run(args, input=bundle, text=True, capture_output=True, check=False)


class ResponseDemoTests(unittest.TestCase):
    def test_alert_includes_triggering_write_and_preserves_later_files(self):
        process = run_cli()
        self.assertEqual(process.returncode, 0, process.stderr)
        payload = json.loads(process.stdout)
        self.assertEqual(payload["score_origin"], "synthetic_fixture")
        self.assertEqual(payload["first_alert_observation"], 4)
        self.assertEqual(payload["blocked_writes"], 6)
        self.assertEqual(len(payload["monitor_only"]["modified_files"]), 10)
        self.assertEqual(len(payload["enforce"]["modified_files"]), 4)
        self.assertLessEqual(payload["alert_elapsed_ms"], payload["gate_closed_elapsed_ms"])
        for index, (name, initial_digest) in enumerate(payload["initial_sha256"].items(), start=1):
            final_monitor = payload["monitor_only"]["final_sha256"][name]
            final_enforce = payload["enforce"]["final_sha256"][name]
            self.assertNotEqual(final_monitor, initial_digest)
            self.assertEqual(final_enforce, final_monitor if index <= 4 else initial_digest)

    def test_no_alert_leaves_gate_open(self):
        bundle = json.dumps({"scores": [0.1, 0.2], "threshold": 0.5, "run_id": "no-alert"})
        process = run_cli(bundle)
        self.assertEqual(process.returncode, 0, process.stderr)
        payload = json.loads(process.stdout)
        self.assertEqual(payload["score_origin"], "precomputed_scores")
        self.assertIsNone(payload["first_alert_observation"])
        self.assertIsNone(payload["gate_closed_elapsed_ms"])
        self.assertEqual(payload["blocked_writes"], 0)
        self.assertEqual(payload["monitor_only"], payload["enforce"])

    def test_exact_threshold_counts_as_alert(self):
        bundle = json.dumps({"scores": [0.5, 0.2], "threshold": 0.5, "run_id": "threshold-tie"})
        process = run_cli(bundle)
        self.assertEqual(process.returncode, 0, process.stderr)
        payload = json.loads(process.stdout)
        self.assertEqual(payload["first_alert_observation"], 1)
        self.assertEqual(payload["blocked_writes"], 1)

    def test_invalid_bundle_is_rejected(self):
        process = run_cli('{"scores":[NaN],"threshold":0.5,"run_id":"bad"}')
        self.assertEqual(process.returncode, 2)
        self.assertIn("must be finite numbers", process.stderr)
