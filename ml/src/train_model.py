"""Train and export a raw-URL phishing baseline for PhishGuard."""

from __future__ import annotations

import argparse
import csv
import json
import random
from pathlib import Path
from urllib.request import urlopen

import joblib
import numpy as np
from sklearn.ensemble import ExtraTreesClassifier, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score, roc_auc_score
from sklearn.model_selection import GroupShuffleSplit
from sklearn.preprocessing import StandardScaler

from feature_engineering import FEATURE_SCHEMA, build_feature_row, normalize_url, validate_feature_row

DATASET_URL = (
    'https://raw.githubusercontent.com/faizann24/Using-machine-learning-to-detect-'
    'malicious-URLs/master/data/data.csv'
)
EDGEPHISH_DATASET_URL = 'https://raw.githubusercontent.com/Hassan-Albattra/URL_Phishing_Detection_Dataset/main/balanced_urls.csv'
LABELS = {
    'benign': 0,
    'legitimate': 0,
    'good': 0,
    'safe': 0,
    'bad': 1,
    'defacement': 1,
    'phishing': 1,
    'malware': 1,
    'malicious': 1,
}


def download_dataset(destination: Path, source_url: str = DATASET_URL) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    with urlopen(source_url, timeout=60) as response:
        destination.write_bytes(response.read())


def read_dataset(
    paths: list[Path],
    limit: int | None = None,
    seed: int = 42,
    balanced: bool = False,
) -> list[dict]:
    rows_by_url: dict[str, dict | None] = {}
    for path in paths:
        with path.open('r', encoding='utf-8', newline='') as handle:
            reader = csv.DictReader(handle)
            if not reader.fieldnames or 'url' not in reader.fieldnames:
                raise ValueError(f'Expected a CSV column named url in {path}')
            label_column = 'type' if 'type' in reader.fieldnames else 'label'
            if label_column not in reader.fieldnames:
                raise ValueError(f'Expected a CSV column named type or label in {path}')
            for row in reader:
                url = normalize_url(row.get('url') or '')
                label = LABELS.get((row.get(label_column) or '').strip().lower())
                if not url or label is None:
                    continue
                record = {
                    'url': url,
                    'label': label,
                    'source': (row.get('source') or path.stem).strip(),
                    'title': (row.get('title') or '').strip(),
                    'html': row.get('html') or '',
                    'observed_at': (row.get('observed_at') or row.get('date') or '').strip(),
                }
                if url in rows_by_url and rows_by_url[url] and rows_by_url[url]['label'] != label:
                    rows_by_url[url] = None
                else:
                    rows_by_url[url] = record

    rows = [row for row in rows_by_url.values() if row is not None]

    if balanced:
        grouped = {label: [row for row in rows if row['label'] == label] for label in {row['label'] for row in rows}}
        target = min(len(group) for group in grouped.values())
        if limit:
            target = min(target, limit // len(grouped))
        rng = random.Random(seed)
        selected = []
        for group in grouped.values():
            selected.extend(rng.sample(group, target))
        rng.shuffle(selected)
        return selected
    if limit and len(rows) > limit:
        selected = random.Random(seed).sample(rows, limit)
        return selected
    return rows


def build_matrix(records: list[dict]) -> list[list[float]]:
    matrix = []
    for record in records:
        row = build_feature_row(record['url'], record['title'], record['html'])
        validate_feature_row(row)
        matrix.append([float(row[name]) for name in FEATURE_SCHEMA])
    return matrix


def registrable_domain(url: str) -> str:
    """Return a stable grouping key to keep related URLs in one split."""
    from urllib.parse import urlsplit

    hostname = (urlsplit(normalize_url(url)).hostname or '').lower().strip('.')
    labels = hostname.split('.')
    if len(labels) <= 2:
        return hostname
    multi_label_suffixes = {
        'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'com.au', 'net.au',
        'org.au', 'co.in', 'com.br', 'com.cn', 'co.jp', 'co.nz',
    }
    suffix = '.'.join(labels[-2:])
    if suffix in multi_label_suffixes and len(labels) >= 3:
        return '.'.join(labels[-3:])
    return suffix


def grouped_split(records: list[dict], test_size: float, seed: int) -> tuple[list[dict], list[dict]]:
    """Split by domain and require both classes in each partition."""
    if len({registrable_domain(record['url']) for record in records}) < 3:
        raise ValueError('Grouped evaluation needs at least three distinct registrable domains')

    groups = np.asarray([registrable_domain(record['url']) for record in records])
    labels = np.asarray([record['label'] for record in records])
    splitter = GroupShuffleSplit(n_splits=100, test_size=test_size, random_state=seed)
    for train_indices, test_indices in splitter.split(records, labels, groups):
        if len(set(labels[train_indices])) < 2 or len(set(labels[test_indices])) < 2:
            continue
        return (
            [records[index] for index in train_indices],
            [records[index] for index in test_indices],
        )
    raise ValueError('Could not create grouped train/test partitions containing both classes')


def score_model(model, x_test, y_test, threshold: float | None = None) -> tuple[dict, np.ndarray]:
    probabilities = model.predict_proba(x_test)[:, 1]
    if threshold is None:
        thresholds = np.linspace(0.1, 0.9, 81)
        threshold = max(
            thresholds,
            key=lambda value: f1_score(y_test, probabilities >= value, zero_division=0),
        )
    predictions = probabilities >= threshold
    metrics = {
        'accuracy': round(accuracy_score(y_test, predictions), 4),
        'precision': round(precision_score(y_test, predictions, zero_division=0), 4),
        'recall': round(recall_score(y_test, predictions, zero_division=0), 4),
        'f1': round(f1_score(y_test, predictions, zero_division=0), 4),
        'roc_auc': round(roc_auc_score(y_test, probabilities), 4),
        'threshold': round(float(threshold), 4),
    }
    return metrics, probabilities


def train(
    records: list[dict],
    seed: int = 42,
    model_version: str = 'url-tuned-ensemble-v0.3.0',
) -> tuple[dict, dict, object]:
    train_records, test_records = grouped_split(records, test_size=0.2, seed=seed)
    fit_records, validation_records = grouped_split(train_records, test_size=0.2, seed=seed + 1)
    x_fit = np.asarray(build_matrix(fit_records), dtype=float)
    x_validation = np.asarray(build_matrix(validation_records), dtype=float)
    x_train = np.asarray(build_matrix(train_records), dtype=float)
    x_test = np.asarray(build_matrix(test_records), dtype=float)
    y_fit = [record['label'] for record in fit_records]
    y_validation = [record['label'] for record in validation_records]
    y_train = [record['label'] for record in train_records]
    y_test = [record['label'] for record in test_records]
    scaler = StandardScaler().fit(x_fit)
    x_fit_scaled = scaler.transform(x_fit)
    x_validation_scaled = scaler.transform(x_validation)
    x_train_scaled = scaler.fit_transform(x_train)
    x_test_scaled = scaler.transform(x_test)

    candidates = [
        ('logistic_regression', LogisticRegression(max_iter=1000, class_weight='balanced', C=1.0, random_state=seed), True),
    ]
    rng = random.Random(seed)
    for index in range(6):
        candidates.append((
            f'random_forest_tuned_{index + 1}',
            RandomForestClassifier(
                n_estimators=rng.choice([150, 250]),
                max_depth=rng.choice([None, 18, 28]),
                min_samples_leaf=rng.choice([1, 2, 4]),
                max_features=rng.choice(['sqrt', 0.7]),
                class_weight='balanced_subsample',
                n_jobs=-1,
                random_state=seed + index,
            ),
            False,
        ))
        candidates.append((
            f'extra_trees_tuned_{index + 1}',
            ExtraTreesClassifier(
                n_estimators=rng.choice([150, 250]),
                max_depth=rng.choice([None, 18, 28]),
                min_samples_leaf=rng.choice([1, 2, 4]),
                max_features=rng.choice(['sqrt', 0.7]),
                class_weight='balanced',
                n_jobs=-1,
                random_state=seed + index,
            ),
            False,
        ))

    validation_results = {}
    for name, candidate, uses_scaling in candidates:
        fit_features = x_fit_scaled if uses_scaling else x_fit
        validation_features = x_validation_scaled if uses_scaling else x_validation
        candidate.fit(fit_features, y_fit)
        validation_results[name], _ = score_model(candidate, validation_features, y_validation)

    winner_name = max(
        validation_results,
        key=lambda name: (validation_results[name]['roc_auc'], validation_results[name]['f1']),
    )
    winner_index = next(index for index, item in enumerate(candidates) if item[0] == winner_name)
    _, winner, uses_scaling = candidates[winner_index]
    winner.fit(x_train_scaled if uses_scaling else x_train, y_train)
    test_metrics, _ = score_model(
        winner,
        x_test_scaled if uses_scaling else x_test,
        y_test,
        validation_results[winner_name]['threshold'],
    )
    test_metrics['validation_threshold'] = validation_results[winner_name]['threshold']
    metrics = {
        'samples': len(records),
        'test_samples': len(y_test),
        'split_strategy': 'registrable_domain_grouped',
        'winner': winner_name,
        'validation_models': validation_results,
        'test': test_metrics,
    }
    artifact = {
        'model_version': model_version,
        'feature_schema': FEATURE_SCHEMA,
        'algorithm': winner_name,
        'threshold': validation_results[winner_name]['threshold'],
        'means': [float(value) for value in scaler.mean_],
        'scales': [float(value) for value in scaler.scale_],
        'metrics': metrics,
    }
    return artifact, metrics, winner


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--dataset', type=Path, default=Path('ml/data/malicious_urls.csv'))
    parser.add_argument('--additional-dataset', type=Path, action='append', default=[])
    parser.add_argument('--include-edgephish', action='store_true')
    parser.add_argument('--output', type=Path, default=Path('ml/models/url-ensemble-selection-v0.2.0.json'))
    parser.add_argument('--model-version', default='url-tuned-ensemble-v0.3.0')
    parser.add_argument('--limit', type=int, default=None)
    parser.add_argument('--balanced', action='store_true')
    parser.add_argument('--refresh', action='store_true')
    args = parser.parse_args()

    dataset_paths = [args.dataset, *args.additional_dataset]
    if args.refresh or not args.dataset.exists():
        print(f'Downloading dataset to {args.dataset} ...')
        download_dataset(args.dataset)
    if args.include_edgephish:
        edgephish_path = Path('ml/data/edgephish_balanced_urls.csv')
        if args.refresh or not edgephish_path.exists():
            print(f'Downloading EdgePhish dataset to {edgephish_path} ...')
            download_dataset(edgephish_path, EDGEPHISH_DATASET_URL)
        dataset_paths.append(edgephish_path)

    records = read_dataset(dataset_paths, args.limit, balanced=args.balanced)
    if len({record['label'] for record in records}) < 2:
        raise ValueError('Dataset must contain both legitimate and phishing-like labels')

    artifact, metrics, model = train(records, model_version=args.model_version)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(artifact, indent=2) + '\n', encoding='utf-8')
    joblib.dump(model, args.output.with_suffix('.joblib'))
    print(json.dumps(metrics, indent=2))
    print(f'Exported model to {args.output}')


if __name__ == '__main__':
    main()
