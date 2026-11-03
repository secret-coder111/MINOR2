"""Offline research ensemble checks; synthetic fixtures establish no accuracy."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock

import joblib
import numpy as np

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'ml/src'))

from dataset_contract import assert_separated
from feature_engineering import URL_FEATURE_SCHEMA
from train_model import partition_records, select_fpr_threshold
from train_hybrid_model import BUNDLE_KIND, predict_bundle, train
from export_browser_model import export_model as export_tree
from export_browser_char_model import export_model as export_character


class HybridModelTests(unittest.TestCase):
    def test_convex_blend_uses_final_document_url_and_validates_components(self):
        numeric = Mock(classes_=np.asarray([0, 1]))
        numeric.predict_proba.return_value = np.asarray([[.2, .8], [.6, .4]])
        character = Mock(classes_=np.asarray([0, 1]))
        character.predict_proba.return_value = np.asarray([[.6, .4], [.8, .2]])
        vectorizer = Mock()
        bundle = {'kind': BUNDLE_KIND, 'feature_schema': URL_FEATURE_SCHEMA,
            'numeric_weight': .25, 'numeric_model': numeric,
            'character_model': character, 'vectorizer': vectorizer}
        records = [{'url': 'https://original.test/start', 'final_url': 'https://final.test/Aa?Case=X'},
                   {'url': 'https://another.test/Login'}]
        actual = predict_bundle(bundle, records)
        np.testing.assert_allclose(actual, [[.5, .5], [.75, .25]])
        vectorizer.transform.assert_called_once_with(['https://final.test/Aa?Case=X', 'https://another.test/Login'])
        vectorizer.reset_mock()
        predict_bundle({**bundle, 'text_transform': 'strip_scheme_v1'}, records)
        vectorizer.transform.assert_called_once_with(['final.test/Aa?Case=X', 'another.test/Login'])
        with self.assertRaisesRegex(ValueError, 'input transform'):
            predict_bundle({**bundle, 'text_transform': 'unrecognized'}, records)
        self.assertEqual(predict_bundle(bundle, []).shape, (0, 2))
        for weight in [-.1, 1.1, True, float('nan')]:
            with self.subTest(weight=weight), self.assertRaises(ValueError):
                predict_bundle({**bundle, 'numeric_weight': weight}, records)
        numeric.predict_proba.return_value = np.asarray([[.8, .8], [.2, .2]])
        with self.assertRaisesRegex(ValueError, 'sum to one'):
            predict_bundle(bundle, records)

    def test_single_component_weights_do_not_require_unused_estimators(self):
        estimator = Mock(classes_=np.asarray([0, 1]))
        estimator.predict_proba.return_value = np.asarray([[.1, .9]])
        records = [{'url': 'https://one.test/'}]
        numeric = {'kind': BUNDLE_KIND, 'feature_schema': URL_FEATURE_SCHEMA,
                   'numeric_weight': 1., 'numeric_model': estimator}
        character = {'kind': BUNDLE_KIND, 'feature_schema': URL_FEATURE_SCHEMA,
                     'numeric_weight': 0., 'character_model': estimator, 'vectorizer': Mock()}
        np.testing.assert_allclose(predict_bundle(numeric, records), [[.1, .9]])
        np.testing.assert_allclose(predict_bundle(character, records), [[.1, .9]])
        with self.assertRaisesRegex(ValueError, 'research bundle'):
            predict_bundle({}, records)

    def test_training_round_trip_calibration_and_browser_export_rejection(self):
        records = [{'url': f'https://start-safe{i}.test/', 'final_url': f'https://safe{i}.test/about-Aa',
                    'label': 0} for i in range(40)]
        records += [{'url': f'https://start-bad{i}.test/', 'final_url': f'http://verify-account{i}.test/wallet-login',
                     'label': 1} for i in range(40)]
        artifact, bundle = train(records, seed=42, fpr_budget=.1)
        self.assertFalse(artifact['deployment_eligible'])
        self.assertFalse(artifact['browser_inference_supported'])
        self.assertEqual(artifact['deployment_status'], 'research_only')
        self.assertEqual(artifact['candidate_search']['candidate_count'], 23)
        self.assertEqual(set(artifact['family_comparison']), {'numeric', 'character', 'hybrid'})
        self.assertEqual(artifact['feature_scope'], 'hybrid_url')
        partitions = partition_records(records, 42)
        probabilities = predict_bundle(bundle, partitions['calibration'])[:, 1]
        threshold, metrics = select_fpr_threshold([r['label'] for r in partitions['calibration']], probabilities, .1)
        self.assertEqual(artifact['threshold'], threshold)
        self.assertEqual(artifact['calibration']['confusion_matrix'], metrics['confusion_matrix'])
        for name, left in artifact['manifests'].items():
            for other, right in artifact['manifests'].items():
                if name != other:
                    assert_separated(left, right)
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            model_path, metadata_path, export_path = [root / name for name in ['hybrid.joblib', 'hybrid.json', 'browser.js']]
            joblib.dump(bundle, model_path)
            loaded = joblib.load(model_path)
            np.testing.assert_allclose(predict_bundle(bundle, records), predict_bundle(loaded, records))
            artifact['model_file_sha256'] = hashlib.sha256(model_path.read_bytes()).hexdigest()
            metadata_path.write_text(json.dumps(artifact), encoding='utf-8')
            with self.assertRaisesRegex(ValueError, 'tree ensembles only'):
                export_tree(metadata_path, model_path, export_path, diagnostic_only=True)
            with self.assertRaisesRegex(ValueError, 'model and vectorizer'):
                export_character(metadata_path, model_path, export_path, diagnostic_only=True)
            self.assertFalse(export_path.exists())


if __name__ == '__main__':
    unittest.main()
