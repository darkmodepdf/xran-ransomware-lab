import io
import json
import unittest

import torch

from raneval.core import SequenceModel
from raneval.observe_process import observe
from raneval.process_score import ProcessStreamingScorer


class ProcessObservationTests(unittest.TestCase):
    def scorer(self):
        bundle = {"horizon": 2048, "block_size": 256, "vocabulary": {"read": 2}}
        return ProcessStreamingScorer(bundle, SequenceModel("counts", 3).eval(), torch.device("cpu"))

    def event(self, sequence):
        return {"schema": "raneval-observed-syscall-v1", "order": "observed", "sequence": sequence,
                "time_ms": sequence, "completion_time_ns": sequence * 1000,
                "op": "read", "actor": "task-1"}

    def test_preserves_scores_beyond_finite_calibration_horizon(self):
        stream = io.StringIO("\n".join(json.dumps(self.event(i)) for i in range(1, 2050)))
        output = io.StringIO()
        result = observe(stream, self.scorer(), None, 2048, output)
        self.assertEqual(result["scored_events"], 2049)
        self.assertEqual(result["beyond_calibration_horizon"], 1)
        self.assertIsNone(result["first_alert"])
        rows = [json.loads(line) for line in output.getvalue().splitlines()]
        self.assertTrue(rows[-2]["within_calibration_horizon"])
        self.assertFalse(rows[-1]["within_calibration_horizon"])

    def test_sequence_gap_fails_before_scoring(self):
        scorer = self.scorer()
        with self.assertRaises(ValueError):
            observe(io.StringIO(json.dumps(self.event(2))), scorer, None, 2048, io.StringIO())
        self.assertEqual(scorer.positions, 0)
