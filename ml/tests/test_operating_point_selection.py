"""Low-FPR model selection regressions; synthetic arrays are not an accuracy study."""
from __future__ import annotations

from pathlib import Path
import sys
import unittest

import numpy as np

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'ml/src'))

from train_model import (NoFeasibleThresholdError, probability_metrics,
                         select_fpr_threshold, select_tuning_candidate,
                         tuning_selection_contract)


class OperatingPointSelectionTests(unittest.TestCase):
    def test_lower_global_auc_can_detect_more_phishing_at_zero_false_positives(self):
        labels = [0] * 10 + [1] * 10
        # A single high-scoring legitimate page blocks all phishing detections
        # under a zero-FP constraint, despite an attractive global ROC AUC.
        high_auc = [.01 * i for i in range(1, 10)] + [.99] + [.5 + .01 * i for i in range(10)]
        low_fpr_recall = [.1] * 10 + [.9] * 5 + [.05] * 5
        winner, results = select_tuning_candidate(
            labels, {'high_auc': high_auc, 'low_fpr_recall': low_fpr_recall}, 0)
        self.assertGreater(results['high_auc']['roc_auc'], results['low_fpr_recall']['roc_auc'])
        self.assertEqual(winner, 'low_fpr_recall')
        self.assertEqual(results['high_auc']['recall'], 0)
        self.assertEqual(results[winner]['recall'], .5)
        self.assertEqual(results[winner]['false_positive_rate'], 0)
        self.assertGreater(results[winner]['false_positive_rate_95ci'][1], 0)

    def test_infeasible_saturated_candidate_does_not_block_usable_candidate(self):
        winner, results = select_tuning_candidate(
            [0, 0, 1, 1], {'saturated': [1, 1, 1, 1], 'usable': [.1, .2, .8, .9]}, 0)
        self.assertEqual(winner, 'usable')
        self.assertFalse(results['saturated']['operating_point_feasible'])
        self.assertTrue(results['usable']['operating_point_feasible'])
        with self.assertRaisesRegex(ValueError, 'No candidate'):
            select_tuning_candidate([0, 1], {'saturated': [1, 1]}, 0)
        with self.assertRaises(NoFeasibleThresholdError):
            select_fpr_threshold([0, 1], [1, 1], 0)

    def test_fpr_is_tie_breaker_before_global_ranking_metrics(self):
        labels = [0, 0, 0, 0, 1, 1]
        # Same recall at a permissive tuning budget, but the first candidate
        # needs a false positive to reach it. Prefer the lower warning burden.
        winner, results = select_tuning_candidate(
            labels, {'costly': [.1, .2, .3, .9, .8, .95],
                     'clean': [.1, .2, .3, .4, .8, .95]}, .25)
        self.assertEqual(results['costly']['recall'], results['clean']['recall'])
        self.assertEqual(winner, 'clean')

    def test_tuning_threshold_is_not_reused_for_final_model_calibration(self):
        labels = [0, 0, 1, 1]
        _, tuning = select_tuning_candidate(labels, {'candidate': [.1, .2, .8, .9]}, 0)
        final_threshold, final = select_fpr_threshold(labels, [.3, .4, .5, .6], 0)
        self.assertNotEqual(tuning['candidate']['threshold'], final_threshold)
        self.assertEqual(final['recall'], 1)
        self.assertFalse(tuning_selection_contract(0)['threshold_is_final'])

    def test_invalid_probabilities_are_errors_rather_than_infeasible_models(self):
        for probabilities in [[-.1, .8], [.1, 1.1], [.1], [.1, float('nan')]]:
            with self.subTest(probabilities=probabilities), self.assertRaises(ValueError):
                select_tuning_candidate([0, 1], {'malformed': probabilities}, .01)
        with self.assertRaisesRegex(ValueError, 'At least one'):
            select_tuning_candidate([0, 1], {}, .01)

    def test_average_precision_is_reported_with_its_class_prevalence_baseline(self):
        metrics = probability_metrics([0, 0, 0, 1], [.1, .2, .3, .9], .5)
        self.assertEqual(metrics['average_precision'], 1)
        self.assertEqual(metrics['positive_prevalence'], .25)
        self.assertTrue(np.isfinite(metrics['average_precision']))


if __name__ == '__main__':
    unittest.main()
