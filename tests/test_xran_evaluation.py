"""Synthetic integration evidence for frozen CPU evaluation exports."""

import hashlib
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import numpy as np

from raneval.train_xran import parser, run
from raneval.xran_data import canonical_json
from raneval.xran_models import atomic_json, digest


PROJECT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("evaluate_xran", PROJECT / "scripts/evaluate_xran.py")
evaluator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(evaluator)
dashboard_spec = importlib.util.spec_from_file_location("xran_dashboard_test", PROJECT / "demo/xran_dashboard/server.py")
dashboard = importlib.util.module_from_spec(dashboard_spec)
dashboard_spec.loader.exec_module(dashboard)


def fixture_prepared(path):
    path.mkdir()
    rng = np.random.default_rng(84)
    tokens = rng.integers(1, 8, (20, 520), dtype=np.int64)
    tokens[:, 100:500] = 0
    tokens[16, :500] = 0  # API-empty but valid nonempty DLL/mutex test report.
    labels = np.arange(20, dtype=np.uint8) % 2
    roles = np.array([0] * 8 + [1] * 4 + [2] * 4 + [3] * 4, dtype=np.uint8)
    # Positive calibration is reserved. Any accidental score attempt must fail.
    tokens[(roles == 2) & (labels == 1)] = 99999
    arrays = {"tokens": tokens, "labels": labels, "roles": roles,
              "missing_counts": np.stack([(tokens[:, start:end] == 0).sum(1)
                                           for start, end in ((0, 500), (500, 510), (510, 520))], axis=1).astype(np.uint16),
              "multiplicities": np.ones(20, dtype=np.uint32)}
    np.savez_compressed(path / "encoded.npz", **arrays)
    groups = [{"id": f"synthetic-{i}", "feature_sha256": f"synthetic-{i}",
               "sources": ["Benign" if labels[i] == 0 else "VirusShare"]} for i in range(20)]
    (path / "groups.jsonl").write_text("\n".join(json.dumps(group) for group in groups), encoding="utf-8")
    atomic_json(path / "vocabulary.json", {"schema": "xran-vocabulary-v1", "pad_id": 0, "unk_id": 1,
                                          "size": 8, "tokens": {json.dumps(["api", str(i)]): i for i in range(2, 8)}})
    manifest = {"schema": "xran-prepared-v1", "group_count": 20, "input_rows_accounted": 20,
                "source_group_counts": {"Benign": 10, "VirusShare": 10}, "quarantined_groups": 0,
                "quarantined_rows": 0, "retained_original_rows": 20, "rejected_rows": 0,
                "api_overlap": {}, "split_seed": 20261117, "split_kind": "synthetic-test-fixture",
                "role_class_counts": {}, "array_schema": {
                    name: {"shape": list(array.shape), "dtype": str(array.dtype),
                           "raw_sha256": hashlib.sha256(array.tobytes()).hexdigest()} for name, array in arrays.items()},
                "artifacts": {name: {"sha256": digest(path / name)}
                              for name in ("encoded.npz", "groups.jsonl", "vocabulary.json")}}
    manifest["identity_sha256"] = hashlib.sha256(canonical_json(manifest)).hexdigest()
    atomic_json(path / "manifest.json", manifest)


class XRanEvaluationTests(unittest.TestCase):
    def test_frozen_campaign_complete_flow_and_reserved_positive_calibration(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            data, campaign, output = root / "data", root / "campaign", root / "evaluation"
            fixture_prepared(data)
            campaign.mkdir()
            entries = []
            for kind in ("counts", "cnn", "gru"):
                args = parser().parse_args(["--data-dir", str(data), "--out", str(campaign / kind),
                    "--model", kind, "--epochs", "1", "--batch-size", "4", "--threads", "1",
                    "--budget-minutes", "5", "--reserve-minutes", "1", "--config-id", f"{kind}-lr0"])
                result = run(args)
                entries.append({"id": kind, "model": kind, "view": "all", "run": kind, "seed": 17,
                                "config_id": f"{kind}-lr0", "lr": 0.001, "data_variant": "primary",
                                "result_sha256": digest(campaign / kind / "result.json"),
                                "bundle_sha256": digest(campaign / kind / "bundle/bundle.json"),
                                "best": result["best"], "parameters": result["parameters"]})
            protocol = {"schema": "xran-campaign-protocol-v1", "primary_seed": 17, "calibration_alpha": 0.05,
                        "epochs": 1, "batch_size": 4, "weight_decay": 0.0001,
                        "datasets": {"primary": json.loads((data / "manifest.json").read_bytes())["identity_sha256"]},
                        "learning_rates": {kind: [0.001] for kind in ("counts", "cnn", "gru")},
                        "stability_seeds": [], "diagnostics": []}
            atomic_json(campaign / "protocol.json", protocol)
            source_protocol_sha = hashlib.sha256((campaign / "protocol.json").read_bytes().replace(b"\n", b"\r\n")).hexdigest()
            atomic_json(campaign / "selection.json", {"schema": "xran-campaign-selection-v1", "primary": entries,
                        "candidates": entries, "selection_frozen_at": "synthetic-fixture", "protocol_sha256": source_protocol_sha})
            complete = {"schema": "xran-campaign-complete-v1", "primary": entries, "stability": [], "diagnostics": [],
                        "selection_frozen_at": "synthetic-fixture", "test_outcomes_opened": False,
                        "protocol_sha256": digest(campaign / "protocol.json"), "selection_sha256": digest(campaign / "selection.json"),
                        "files": {path.relative_to(campaign).as_posix(): digest(path) for path in campaign.rglob("*") if path.is_file()}}
            atomic_json(campaign / "campaign-complete.json", complete)
            report = evaluator.evaluate(data, campaign, output)
            dashboard.validate_report(report)
            self.assertEqual(report["campaign_verification"]["source_protocol_line_endings"], "CRLF")
            self.assertTrue(report["campaign_verification"]["tune_selection_reproduced"])
            self.assertEqual(report["dataset"]["test_groups"], 4)
            self.assertEqual(len(report["models"]), 3)
            self.assertEqual(len(report["diagnostics"]["paired_comparisons"]), 3)
            for model in report["models"]:
                self.assertEqual(model["calibration"]["n"], 2)
                self.assertTrue(model["verification"]["independent_reload_rescore_exact"])
                self.assertEqual(model["strata"]["api_empty"]["groups"], 1)
                records = [json.loads(line) for line in (output / model["predictions_path"]).read_text().splitlines()]
                self.assertEqual({record["role"] for record in records}, {"test"})
                self.assertEqual(len(records), 4)
            initial_hash = digest(output / "evaluation.json")
            self.assertEqual(report, evaluator.evaluate(data, campaign, output))
            self.assertEqual(initial_hash, digest(output / "evaluation.json"))
            with (campaign / "counts" / "bundle" / "weights.pt").open("ab") as stream:
                stream.write(b"mutation")
            with patch.object(evaluator, "predict_endpoint", side_effect=AssertionError("Must reject before scoring")) as scorer:
                with self.assertRaisesRegex(ValueError, "ledger checksum"):
                    evaluator.evaluate(data, campaign, output)
                scorer.assert_not_called()

    def test_path_escape_and_primary_seed_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with self.assertRaises(ValueError):
                evaluator.within(root, "../outside")
            entries = [{"id": kind, "seed": 29, "run": kind} for kind in ("counts", "cnn", "gru")]
            atomic_json(root / "campaign-complete.json", {"primary": entries})
            with self.assertRaisesRegex(ValueError, "seed 17"):
                evaluator.evaluate(root, root, root / "out")


if __name__ == "__main__":
    unittest.main()
