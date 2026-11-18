import random
import unittest

import torch

from raneval.core import SequenceModel, Trace, choose_threshold, encode, first_alert, sample_early_endpoints, score_blocks
from raneval.score import StreamingScorer
from raneval.train import make_endpoints


class ReplayTests(unittest.TestCase):
    def test_online_and_batch_match_across_resets_and_unknown_tokens(self):
        torch.set_num_threads(1)
        torch.manual_seed(17)
        vocabulary = {'open': 2, 'read': 3, 'write': 4}
        observations = ['open', 'unknown', 'read', 'write', 'read', 'open', 'write']
        cpu = torch.device('cpu')
        for architecture in ('cnn', 'gru', 'counts'):
            with self.subTest(architecture=architecture):
                model = SequenceModel(architecture, 5).eval()
                bundle = {'horizon': 0, 'block_size': 3, 'vocabulary': vocabulary}
                if architecture == 'counts':
                    with torch.no_grad():
                        model.coefficient.copy_(torch.arange(5, dtype=torch.float64) / 10)
                replay = StreamingScorer(bundle, model, cpu)
                live = [replay.step(api) for api in observations]
                offline = list(score_blocks(model, encode(observations, vocabulary), 3, cpu))
                alternate = ['write', 'write', 'open', *observations[3:]]
                reset = StreamingScorer(bundle, model, cpu)
                alternate_scores = [reset.step(api) for api in alternate]
                self.assertEqual(len(live), len(offline))
                for left, right in zip(live, offline):
                    self.assertAlmostEqual(left, right, places=6)
                self.assertEqual(live[3:], alternate_scores[3:])

    def test_tied_calibration_scores_never_exceed_the_cap(self):
        threshold = choose_threshold([0.8, 0.8, 0.1], 0.34)
        self.assertIsNone(first_alert([0.1, 0.8], threshold))
        self.assertEqual(first_alert([0.8, 0.9], threshold), 2)
        never = choose_threshold([1, 1], 0.05)
        self.assertEqual(never['mode'], 'never_alert')
        self.assertIsNone(first_alert([1], never))

    def test_early_endpoints_cover_each_available_band_without_replacement(self):
        positions = sample_early_endpoints(1024, 16, random.Random(771))
        self.assertEqual(positions[0], 1)
        self.assertEqual(len(set(positions)), 16)
        bands = ((1, 120), (121, 256), (257, 512), (513, 1024))
        self.assertEqual([sum(left <= item <= right for item in positions) for left, right in bands], [8, 3, 2, 3])
        self.assertEqual(positions, sample_early_endpoints(1024, 16, random.Random(771)))
        for length in [1, 15, 17, 120, 121, 256, 257, 512, 513]:
            with self.subTest(length=length):
                short = sample_early_endpoints(length, 16, random.Random(771))
                self.assertEqual(len(set(short)), min(16, length))
                self.assertTrue(all(1 <= position <= length for position in short))

    def test_early_loss_weights_sum_to_one_for_both_classes(self):
        train = [Trace(label, label, 'train', label, ('api',)) for label in ('BENIGN', 'RANSOMWARE')]
        encoded = {trace.trace_id: [2] * 1024 for trace in train}
        positions, endpoints = make_endpoints(train, encoded, 16, 771, 'early', 2.0)
        for trace in train:
            chosen = [(position, weight) for trace_id, position, _, weight in endpoints if trace_id == trace.trace_id]
            self.assertEqual([position for position, _ in chosen], positions[trace.trace_id])
            self.assertAlmostEqual(sum(weight for _, weight in chosen), 1.0)
            self.assertAlmostEqual(sum(weight for position, weight in chosen if position <= 120), 2 / 3)


if __name__ == '__main__':
    unittest.main()
