import math
import unittest

import numpy as np

from raneval.xran_metrics import binary_metrics, calibrate


class XRanMetricTests(unittest.TestCase):
    def test_ties_and_smallest_admissible_boundary(self):
        values = [0.1] * 18 + [0.7, 0.7]
        result = calibrate(values)
        self.assertEqual(result["allowed"], 1)
        self.assertEqual(result["threshold"], math.nextafter(0.7, math.inf))
        self.assertEqual(result["alerts"], 0)
        self.assertGreater(sum(x >= 0.7 for x in values), result["allowed"])

    def test_disabled_and_invalid(self):
        self.assertIsNone(calibrate([1.0] * 20)["threshold"])
        for values in ([], [math.nan], [-0.1], [[0.1]]):
            with self.assertRaises(ValueError):
                calibrate(values)

    def test_confusion_and_ranking(self):
        result = binary_metrics([0, 0, 1, 1], [0.1, 0.4, 0.35, 0.8], 0.5)
        self.assertEqual(result["confusion"], {"tp": 1, "fn": 1, "tn": 2, "fp": 0})
        self.assertAlmostEqual(result["metrics"]["roc_auc"], 0.75)
        self.assertAlmostEqual(result["metrics"]["average_precision"], (1 + 2 / 3) / 2)
        tied = binary_metrics([0, 1], [0.5, 0.5], 0.5)
        self.assertEqual(tied["metrics"]["roc_auc"], 0.5)
        self.assertEqual(tied["metrics"]["average_precision"], 0.5)

    def test_undefined_class_metrics_are_explicit(self):
        result = binary_metrics([0, 0], [0.1, 0.2], None)
        self.assertIsNone(result["metrics"]["recall"])
        self.assertIsNone(result["metrics"]["roc_auc"])
        self.assertIn("recall", result["metrics"]["undefined_reasons"])
        self.assertEqual(result["metrics"]["specificity"], 1)

    def test_independent_sklearn_if_available(self):
        try:
            from sklearn.metrics import average_precision_score, roc_auc_score
        except ImportError:
            self.skipTest("Optional independent reference is unavailable")
        rng = np.random.default_rng(7)
        y = rng.integers(0, 2, 200)
        p = rng.integers(0, 10, 200) / 10
        result = binary_metrics(y, p, 0.5)["metrics"]
        self.assertAlmostEqual(result["roc_auc"], roc_auc_score(y, p))
        self.assertAlmostEqual(result["average_precision"], average_precision_score(y, p))


if __name__ == "__main__":
    unittest.main()
