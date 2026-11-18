"""Representation, artifact and resumability checks for new XRan models."""

import copy
import json
import tempfile
import unittest
from pathlib import Path

import numpy as np
import torch

from raneval.train_xran import candidate_rank, parser, run
from raneval.xran_models import (
    atomic_json, build_model, digest, export_bundle, load_bundle,
    model_config, predict_endpoint,
)


def synthetic_prepared(path, poison_heldout=False):
    """Small role fixture, not a scientific performance benchmark."""
    path.mkdir()
    rng = np.random.default_rng(8)
    tokens = rng.integers(0, 8, (24, 520), dtype=np.int64)
    tokens[:, 100:500] = 0
    labels = np.arange(24, dtype=np.uint8) % 2
    roles = np.array([0] * 12 + [1] * 8 + [2] * 2 + [3] * 2, dtype=np.uint8)
    if poison_heldout:
        tokens[roles >= 2] = 99999
        labels[roles >= 2] = 255
    np.savez_compressed(path / "encoded.npz", tokens=tokens, labels=labels, roles=roles)
    (path / "groups.jsonl").write_text("\n".join(json.dumps({"id": str(i)}) for i in range(24)), encoding="utf-8")
    atomic_json(path / "vocabulary.json", {"schema": "xran-vocabulary-v1", "pad_id": 0, "unk_id": 1,
                                          "size": 8, "tokens": {json.dumps(["api", str(i)]): i for i in range(2, 8)}})
    atomic_json(path / "manifest.json", {"schema": "unit-test-prepared"})
    return tokens


class XRanModelTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        torch.set_num_threads(1)

    def test_architecture_shapes_and_full_position_gru(self):
        for kind in ("counts", "cnn", "gru"):
            with self.subTest(kind=kind):
                model = build_model(model_config(kind, 8)).eval()
                tokens = torch.zeros((3, 520), dtype=torch.long)
                tokens[1, 0] = 1
                tokens[2, 519] = 2
                seen = []
                if kind == "gru":
                    hook = model.recurrent.register_forward_pre_hook(lambda module, inputs: seen.append(inputs[0].shape[1]))
                logits = model(tokens)
                self.assertEqual(tuple(logits.shape), (3,))
                self.assertTrue(torch.isfinite(logits).all())
                if kind == "gru":
                    hook.remove()
                    self.assertEqual(seen, [520])
                    self.assertEqual(torch.count_nonzero(model.embedding.weight[0]).item(), 0)

    def test_count_log1p_ignores_pad_and_counts_unknown(self):
        model = build_model(model_config("counts", 5))
        with torch.no_grad():
            model.head.weight.fill_(1)
            model.head.bias.zero_()
        tokens = torch.zeros((1, 520), dtype=torch.long)
        tokens[0, :3] = torch.tensor([1, 1, 3])
        self.assertAlmostEqual(model(tokens).item(), np.log1p(2) + np.log1p(1), places=6)

    def test_api_and_missingness_diagnostics(self):
        original = torch.zeros((2, 520), dtype=torch.long)
        original[:, :20] = 2
        original[1, 500:] = 3
        api_model = build_model(model_config("counts", 8, "api"))
        self.assertEqual(*api_model(original).detach().tolist())
        missing = build_model(model_config("counts", 8, "missingness"))
        with torch.no_grad():
            missing.head.weight.fill_(1)
            missing.head.bias.zero_()
        np.testing.assert_allclose(missing(original).detach().numpy(), [2.96, 0.96], rtol=1e-6)

    def test_bundle_roundtrip_and_reject_corruption_or_streaming(self):
        vocabulary = {"schema": "xran-vocabulary-v1", "pad_id": 0, "unk_id": 1, "size": 8, "tokens": {}}
        tokens = np.ones((2, 520), dtype=np.int64)
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary)
            for kind in ("counts", "cnn", "gru"):
                model = build_model(model_config(kind, 8)).eval()
                export_bundle(path / kind, model, model.config, vocabulary, {"seed": 17})
                loaded = load_bundle(path / kind)
                np.testing.assert_array_equal(predict_endpoint(tokens, loaded, 1), predict_endpoint(tokens, {"model": model}, 1))
                self.assertEqual(loaded["bundle_sha256"], digest(path / kind / "bundle.json"))
            (path / "counts" / "weights.pt").write_bytes(b"corrupt")
            with self.assertRaisesRegex(ValueError, "checksum"):
                load_bundle(path / "counts")
            atomic_json(path / "old.json", {"schema": "streaming-bundle-v1"})
            with self.assertRaisesRegex(ValueError, "streaming"):
                load_bundle(path / "old.json")

    def test_invalid_encoded_inputs_and_config(self):
        bundle = {"model": build_model(model_config("counts", 8))}
        for tokens in (np.zeros((1, 519), dtype=np.int64), np.zeros((1, 520), dtype=float),
                       np.full((1, 520), -1), np.full((1, 520), 8)):
            with self.assertRaises(ValueError):
                predict_endpoint(tokens, bundle)
        config = model_config("gru", 8)
        config["gru_readout"] = "last_nonpad"
        with self.assertRaises(ValueError):
            build_model(config)

    def test_tune_candidate_tie_order(self):
        summary = {"metrics": {"recall": 0.5, "roc_auc": 0.75}}
        self.assertLess(candidate_rank(summary, 10, "a"), candidate_rank(summary, 11, "a"))
        self.assertLess(candidate_rank(summary, 10, "a"), candidate_rank(summary, 10, "b"))

    def test_exact_resume_all_models_and_heldout_isolation(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            synthetic_prepared(base / "data", poison_heldout=True)
            for kind in ("counts", "cnn", "gru"):
                with self.subTest(kind=kind):
                    def arguments(out):
                        return parser().parse_args(["--data-dir", str(base / "data"), "--out", str(out),
                            "--model", kind, "--epochs", "2", "--batch-size", "4", "--threads", "1",
                            "--budget-minutes", "5", "--reserve-minutes", "1"])
                    full_args = arguments(base / (kind + "-full"))
                    full = run(full_args)
                    partial_args = arguments(base / (kind + "-resumed"))
                    partial_args.stop_after_steps = 2
                    partial = run(partial_args)
                    self.assertEqual(partial["status"], "step_stopped")
                    self.assertEqual(partial["step"], 2)
                    self.assertIsNone(partial["bundle"])
                    partial_args.stop_after_steps = None
                    partial_args.resume = True
                    resumed = run(partial_args)
                    self.assertEqual(resumed["status"], "complete")
                    self.assertEqual(full["history"], resumed["history"])
                    expected = load_bundle(Path(full_args.out) / "bundle")["model"].state_dict()
                    actual = load_bundle(Path(partial_args.out) / "bundle")["model"].state_dict()
                    for name in expected:
                        self.assertTrue(torch.equal(expected[name], actual[name]), name)
                    if kind != "counts":
                        self.assertEqual(torch.count_nonzero(actual["embedding.weight"][0]).item(), 0)
                    mismatch = copy.copy(partial_args)
                    mismatch.lr *= 2
                    with self.assertRaisesRegex(ValueError, "identity"):
                        run(mismatch)


if __name__ == "__main__":
    unittest.main()
