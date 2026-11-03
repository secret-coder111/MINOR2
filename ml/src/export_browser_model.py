"""Export a fitted tree model as a browser-readable PhishGuard model."""

from __future__ import annotations

import argparse
import json
import math
import hashlib
from pathlib import Path

import joblib
import numpy as np

from feature_engineering import FEATURE_SCHEMA, URL_FEATURE_SCHEMA, FEATURE_SCHEMA_VERSION, extractor_source_hash
from dataset_contract import sha256
from release_contract import release_gate


def serialize_tree(estimator) -> list[list[float | int]]:
    tree = estimator.tree_
    feature_count = int(tree.n_features)
    nodes = []
    for index in range(tree.node_count):
        left = int(tree.children_left[index])
        right = int(tree.children_right[index])
        if left == -1:
            values = tree.value[index][0]
            total = float(values.sum())
            probability = float(values[1] / total) if total else 0.0
            if not math.isfinite(probability) or not 0 <= probability <= 1:
                raise ValueError(f'Invalid leaf probability at node {index}')
            nodes.append([-1, 0.0, -1, -1, probability])
        else:
            feature = int(tree.feature[index])
            if not 0 <= feature < feature_count:
                raise ValueError(f'Invalid feature index at node {index}: {feature}')
            if not 0 <= left < tree.node_count or not 0 <= right < tree.node_count:
                raise ValueError(f'Invalid child index at node {index}')
            nodes.append([
                feature,
                float(tree.threshold[index]),
                left,
                right,
                0.0,
            ])
    return nodes


def export_model(
    metadata_path: Path,
    model_path: Path,
    output_path: Path,
    max_trees: int | None = None,
    max_bytes: int = 20_000_000,
    diagnostic_only: bool = False,
    evaluation_report_path: Path | None = None,
) -> None:
    metadata = json.loads(metadata_path.read_text(encoding='utf-8'))
    model = joblib.load(model_path)
    if not hasattr(model, 'estimators_'):
        raise ValueError('Browser export currently supports tree ensembles only')
    feature_schema = metadata.get('feature_schema')
    if not isinstance(feature_schema, list) or not feature_schema:
        raise ValueError('Metadata must contain a non-empty feature_schema list')
    if feature_schema not in [FEATURE_SCHEMA, URL_FEATURE_SCHEMA]:
        raise ValueError('Export schema must match the explicit current URL subset or full observed-DOM contract')
    if metadata.get('feature_schema_version') != FEATURE_SCHEMA_VERSION or metadata.get('extractor_version') != FEATURE_SCHEMA_VERSION:
        raise ValueError('Legacy feature/extractor contract cannot be deployed; retrain with the current extractor')
    if metadata.get('extractor_sha256') != extractor_source_hash():
        raise ValueError('Extractor source hash changed since training')
    if metadata.get('feature_schema_sha256') != sha256(json.dumps(feature_schema, separators=(',', ':'))):
        raise ValueError('Feature schema hash mismatch')
    if metadata.get('model_file_sha256') != hashlib.sha256(model_path.read_bytes()).hexdigest():
        raise ValueError('Estimator file hash does not match training metadata')
    if int(model.n_features_in_) != len(feature_schema) or list(model.classes_) != [0, 1]:
        raise ValueError('Estimator dimensions/classes do not match browser binary feature contract')
    calibration = metadata.get('calibration', {})
    if calibration.get('method') != 'independent_fpr_budget' or calibration.get('false_positive_rate', 1) > calibration.get('fpr_budget', -1):
        raise ValueError('Independent false-positive-budget calibration is required')
    if set(metadata.get('manifests', {})) != {'fit', 'tuning', 'calibration', 'test'}:
        raise ValueError('Fit/tuning/calibration/test identity manifests are required')
    threshold = float(metadata.get('threshold', 0.5))
    if not math.isfinite(threshold) or not 0 <= threshold <= 1:
        raise ValueError('Metadata threshold must be a finite probability in [0, 1]')
    if calibration.get('threshold') != threshold:
        raise ValueError('Export threshold differs from independently calibrated threshold')
    if any(len(estimator.tree_.feature) != len(estimator.tree_.threshold) for estimator in model.estimators_):
        raise ValueError('Tree feature and threshold arrays do not match')

    estimators = model.estimators_
    if max_trees is not None:
        if max_trees != len(estimators):
            raise ValueError('Tree truncation changes the predictor. Train a compact ensemble directly and recalibrate it')
    if metadata.get('tree_count') != len(estimators):
        raise ValueError('Tree count differs from trained/calibrated metadata')

    evaluation = None
    if not diagnostic_only:
        if evaluation_report_path is None:
            raise ValueError('Deployment needs a frozen source/time-separated evaluation report; use --diagnostic-only for offline research')
        evaluation = json.loads(evaluation_report_path.read_text(encoding='utf-8'))
        if evaluation.get('model_sha256') != metadata['model_file_sha256'] or not evaluation.get('leakage_check', {}).get('passed') or not evaluation.get('frozen_before_training'):
            raise ValueError('Evaluation does not prove this exact model and a pre-frozen separated test')
        if evaluation.get('metadata_sha256') != hashlib.sha256(metadata_path.read_bytes()).hexdigest():
            raise ValueError('Evaluation metadata hash mismatch')
        if metadata.get('label_scope') != 'phishing' or not evaluation.get('representative_login_reviewed'):
            raise ValueError('Phishing deployment requires phishing labels and an explicitly reviewed representative legitimate-login test')
        if evaluation['metrics']['false_positive_rate_95ci'][1] > calibration['fpr_budget']:
            raise ValueError('Evaluation FPR uncertainty exceeds the configured budget')
        if evaluation['metrics'].get('threshold') != threshold:
            raise ValueError('Evaluation used a different threshold from this export')
        if evaluation.get('release_requirements') != metadata.get('release_requirements'):
            raise ValueError('Evaluation release requirements differ from predeclared training requirements')
        gate = release_gate(evaluation.get('metrics', {}), evaluation.get('independent_group_metrics', {}),
            evaluation.get('benchmark_review', {}), metadata.get('release_requirements'), calibration['fpr_budget'])
        if not gate['passed']:
            raise ValueError('Release criteria failed: ' + '; '.join(gate['errors']))

    browser_model = {
        'model_version': metadata['model_version'],
        'algorithm': metadata['algorithm'],
        'feature_schema': feature_schema,
        'threshold': threshold,
        'feature_schema_version': FEATURE_SCHEMA_VERSION,
        'extractor_version': FEATURE_SCHEMA_VERSION,
        'extractor_sha256': metadata['extractor_sha256'],
        'feature_schema_sha256': metadata['feature_schema_sha256'],
        'feature_scope': metadata['feature_scope'],
        'model_file_sha256': metadata['model_file_sha256'],
        'tree_count': len(estimators),
        'calibration': calibration,
        'release_requirements': metadata.get('release_requirements'),
        'deployment_status': 'diagnostic_only' if diagnostic_only else 'validated',
        'deployment_eligible': not diagnostic_only,
        'trees': [serialize_tree(estimator) for estimator in estimators],
    }
    browser_model['predictor_sha256'] = sha256(json.dumps({'feature_schema': feature_schema, 'trees': browser_model['trees']}, separators=(',', ':')))
    # Verify actual sklearn and exact serialized predictor, including float32 casting.
    probes = np.random.default_rng(42).uniform(-1, 500, (128, len(feature_schema)))
    probes = np.vstack([probes, np.zeros(len(feature_schema)), np.ones(len(feature_schema))])
    expected = model.predict_proba(probes)[:, 1]
    actual = serialized_probabilities(browser_model, probes)
    if not np.allclose(expected, actual, rtol=0, atol=1e-12):
        raise ValueError('Serialized predictor does not match fitted sklearn estimator')
    browser_model['serialization_parity'] = {'probes': len(probes), 'max_abs_error': float(np.max(np.abs(expected-actual))), 'input_dtype': 'float32'}
    if evaluation_report_path:
        browser_model['evaluation_report_sha256'] = hashlib.sha256(evaluation_report_path.read_bytes()).hexdigest()
    javascript = (
        'self.PHISH_GUARD_TRAINED_MODEL = '
        + json.dumps(browser_model, separators=(',', ':'))
        + ';\n'
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    encoded_size = len(javascript.encode('utf-8'))
    if encoded_size > max_bytes:
        raise ValueError(
            f'Browser model is {encoded_size} bytes over the {max_bytes}-byte limit; train a smaller predictor and recalibrate'
        )
    output_path.write_text(javascript, encoding='utf-8')
    print(f'Exported {len(browser_model["trees"])} trees to {output_path}')


def serialized_probabilities(browser_model: dict, features) -> np.ndarray:
    probabilities = []
    for row in np.asarray(features, dtype=np.float32):
        total = 0.
        for tree in browser_model['trees']:
            index = 0
            while tree[index][0] != -1:
                feature, threshold, left, right, _ = tree[index]
                index = left if row[feature] <= threshold else right
            total += tree[index][4]
        probabilities.append(total / len(browser_model['trees']))
    return np.asarray(probabilities)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--metadata', type=Path, required=True)
    parser.add_argument('--model', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--max-trees', type=int, default=None, help='Compatibility assertion only; never truncates')
    parser.add_argument('--max-bytes', type=int, default=20_000_000)
    parser.add_argument('--diagnostic-only', action='store_true')
    parser.add_argument('--evaluation-report', type=Path)
    args = parser.parse_args()
    export_model(args.metadata, args.model, args.output, args.max_trees, args.max_bytes,
                 args.diagnostic_only, args.evaluation_report)


if __name__ == '__main__':
    main()
