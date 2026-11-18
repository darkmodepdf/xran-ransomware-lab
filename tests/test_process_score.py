import unittest

import torch

from raneval.context import CONTEXT_FEATURE_NAMES
from raneval.context_score import ContextGRU, ContextStreamingScorer
from raneval.core import SequenceModel
from raneval.process_score import ProcessStreamingScorer
from raneval.score import StreamingScorer


def event(actor, operation="write", target="file"):
    return {"actor": actor, "op": operation, "file": target, "directory": "directory",
            "bytes_changed": 32 if operation == "write" else None}


class ProcessScoringTests(unittest.TestCase):
    def setUp(self):
        torch.set_num_threads(1)
        torch.manual_seed(51)
        self.device = torch.device("cpu")
        self.bundle = {"horizon": 2048, "block_size": 256,
                       "vocabulary": {"open": 2, "read": 3, "write": 4, "close": 5}}

    def model(self, architecture):
        base = SequenceModel("gru" if architecture == "context" else architecture, 6).eval()
        if architecture == "context":
            weights = torch.linspace(-0.5, 0.5, len(CONTEXT_FEATURE_NAMES))
            return ContextGRU(base, weights)
        return base

    def test_interleaving_preserves_every_actors_own_score(self):
        first = [event("task-a", ("open", "read", "write")[index % 3], str(index % 4))
                 for index in range(270)]
        second = [event("task-b", ("close", "write")[index % 2], str(index % 2))
                  for index in range(270)]
        for architecture in ("counts", "cnn", "gru", "context"):
            with self.subTest(architecture=architecture):
                model = self.model(architecture)
                isolated_a = ProcessStreamingScorer(self.bundle, model, self.device)
                isolated_b = ProcessStreamingScorer(self.bundle, model, self.device)
                mixed = ProcessStreamingScorer(self.bundle, model, self.device)
                for index, (left, right) in enumerate(zip(first, second), 1):
                    actual_a, actual_b = mixed.step(left), mixed.step(right)
                    self.assertEqual(actual_a["score"], isolated_a.step(left)["score"])
                    self.assertEqual(actual_b["score"], isolated_b.step(right)["score"])
                    self.assertEqual(actual_a["actor_event"], index)
                    self.assertEqual(actual_b["actor_event"], index)
                    self.assertEqual(actual_b["stream_event"], index * 2)
                self.assertEqual(mixed.active_actor_count, 2)

    def test_continues_past_benchmark_horizon_and_resets_by_actor(self):
        for architecture in ("gru", "context"):
            with self.subTest(architecture=architecture):
                model = self.model(architecture)
                scorer = ProcessStreamingScorer(self.bundle, model, self.device)
                scores = [scorer.step(event("service")) for _ in range(2050)]
                self.assertEqual(scores[-1]["actor_event"], 2050)
                self.assertEqual(scores[-1]["stream_event"], 2050)
                self.assertEqual(scores[0]["score"], scores[2048]["score"])
                self.assertEqual(self.bundle["horizon"], 2048)

    def test_missing_identity_capacity_and_retirement_are_explicit(self):
        scorer = ProcessStreamingScorer(self.bundle, self.model("gru"), self.device, max_actors=1)
        for bad_actor in (None, "", " ", 42):
            with self.assertRaises(ValueError):
                scorer.step(event(bad_actor))
        self.assertEqual(scorer.positions, 0)
        scorer.step(event("first"))
        with self.assertRaisesRegex(RuntimeError, "Active actor limit"):
            scorer.step(event("second"))
        self.assertEqual(scorer.positions, 1)
        self.assertEqual(scorer.retire("first"),
                         {"actor": "first", "actor_event": 1, "stream_event": 1, "retired": True})
        result = scorer.step(event("second"))
        self.assertEqual(result["actor_event"], 1)
        self.assertEqual(result["stream_event"], 2)
        self.assertEqual(scorer.active_actor_count, 1)

    def test_failed_context_observation_does_not_advance_history(self):
        model = self.model("context")
        scorer = ProcessStreamingScorer(self.bundle, model, self.device)
        reference = ProcessStreamingScorer(self.bundle, model, self.device)
        scorer.step(event("first"))
        reference.step(event("first"))
        with self.assertRaises(ValueError):
            scorer.step({**event("first"), "bytes_changed": -1})
        self.assertEqual(scorer.positions, 1)
        self.assertEqual(scorer.step(event("first")), reference.step(event("first")))
        with self.assertRaises(ValueError):
            scorer.step({**event("second"), "file": 20})
        self.assertEqual(scorer.active_actor_count, 1)

    def test_single_actor_matches_existing_streaming_entry_points(self):
        for architecture in ("gru", "context"):
            with self.subTest(architecture=architecture):
                model = self.model(architecture)
                scorer = ProcessStreamingScorer(self.bundle, model, self.device)
                implementation = ContextStreamingScorer if architecture == "context" else StreamingScorer
                reference = implementation(self.bundle, model, self.device)
                for index in range(260):
                    item = event("task", ("read", "write")[index % 2], str(index % 5))
                    expected = reference.step(item if architecture == "context" else item["op"])
                    self.assertEqual(scorer.step(item)["score"], expected)


if __name__ == "__main__":
    unittest.main()
