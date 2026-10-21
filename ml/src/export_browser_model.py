"""Export a fitted tree model as a browser-readable PhishGuard model."""

from __future__ import annotations

import argparse
import json
import math
from pathlib import Path

import joblib


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


def export_model(metadata_path: Path, model_path: Path, output_path: Path) -> None:
    metadata = json.loads(metadata_path.read_text(encoding='utf-8'))
    model = joblib.load(model_path)
    if not hasattr(model, 'estimators_'):
        raise ValueError('Browser export currently supports tree ensembles only')
    feature_schema = metadata.get('feature_schema')
    if not isinstance(feature_schema, list) or not feature_schema:
        raise ValueError('Metadata must contain a non-empty feature_schema list')
    threshold = float(metadata.get('threshold', 0.5))
    if not math.isfinite(threshold) or not 0 < threshold < 1:
        raise ValueError('Metadata threshold must be a finite probability between 0 and 1')
    if any(len(estimator.tree_.feature) != len(estimator.tree_.threshold) for estimator in model.estimators_):
        raise ValueError('Tree feature and threshold arrays do not match')

    browser_model = {
        'model_version': metadata['model_version'],
        'algorithm': metadata['algorithm'],
        'feature_schema': feature_schema,
        'threshold': threshold,
        'trees': [serialize_tree(estimator) for estimator in model.estimators_],
    }
    javascript = (
        'self.PHISH_GUARD_TRAINED_MODEL = '
        + json.dumps(browser_model, separators=(',', ':'))
        + ';\n'
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(javascript, encoding='utf-8')
    print(f'Exported {len(browser_model["trees"])} trees to {output_path}')


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--metadata', type=Path, required=True)
    parser.add_argument('--model', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    export_model(args.metadata, args.model, args.output)


if __name__ == '__main__':
    main()
