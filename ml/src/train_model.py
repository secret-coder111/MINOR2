"""Train a compact, explicitly URL-only or captured-DOM research model offline."""
from __future__ import annotations

import argparse
import csv
import json
import random
from datetime import datetime, timezone
from pathlib import Path
from urllib.request import urlopen

import joblib
import numpy as np
from sklearn.base import clone
from sklearn.ensemble import ExtraTreesClassifier, RandomForestClassifier
from sklearn.metrics import (accuracy_score, average_precision_score, confusion_matrix,
                             f1_score, precision_score, recall_score, roc_auc_score)
from sklearn.model_selection import GroupShuffleSplit

from dataset_contract import (PHISHING_LABELS, assert_separated, connected_groups, label_value, canonicalize_urls,
                              manifest, normalize_url, registrable_domain, sha256, label_is_reviewed, source_identity,
                              group_annotations)
from feature_engineering import FEATURE_SCHEMA, URL_FEATURE_SCHEMA, FEATURE_SCHEMA_VERSION, build_feature_row, validate_feature_row, extractor_source_hash

DATASET_URL = 'https://raw.githubusercontent.com/faizann24/Using-machine-learning-to-detect-malicious-URLs/master/data/data.csv'
EDGEPHISH_DATASET_URL = 'https://raw.githubusercontent.com/Hassan-Albattra/URL_Phishing_Detection_Dataset/main/balanced_urls.csv'
LABELS = PHISHING_LABELS


def download_dataset(destination: Path, source_url: str = DATASET_URL) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    with urlopen(source_url, timeout=60) as response:
        destination.write_bytes(response.read())


def read_dataset(paths: list[Path], limit: int | None = None, seed: int = 42,
                 balanced: bool = False, include_other_threats: bool = False) -> list[dict]:
    rows_by_url: dict[str, dict] = {}
    quarantined: set[str] = set()
    for path in paths:
        with path.open('r', encoding='utf-8', newline='') as handle:
            reader = csv.DictReader(handle)
            if not reader.fieldnames or 'url' not in reader.fieldnames:
                raise ValueError(f'Expected a CSV url column in {path}')
            label_column = 'type' if 'type' in reader.fieldnames else 'label'
            if label_column not in reader.fieldnames:
                raise ValueError(f'Expected a CSV type or label column in {path}')
            source_rows = list(reader)
            normalized_urls = canonicalize_urls([row.get('url') or '' for row in source_rows])
            for row, url in zip(source_rows, normalized_urls):
                label = label_value(row.get(label_column), include_other_threats)
                if not url or label is None or url in quarantined or not label_is_reviewed(row):
                    continue
                if url in rows_by_url and rows_by_url[url]['label'] != label:
                    quarantined.add(url)
                    rows_by_url.pop(url)
                    continue
                source, provenance = source_identity(row, path.stem)
                annotations = group_annotations(row)
                if url in rows_by_url:
                    previous = group_annotations(rows_by_url[url])
                    if any(key in previous and previous[key] != value for key, value in annotations.items()):
                        raise ValueError('Duplicate URL has conflicting campaign/template annotations; review before splitting')
                    rows_by_url[url].update(annotations)
                rows_by_url.setdefault(url, {
                    'url': url, 'label': label,
                    'source': source,
                    # File names are useful report labels, not evidence that
                    # two datasets originated from independent sources.
                    'source_provenance': provenance,
                    'label_status': (row.get('label_status') or '').strip(),
                    'title': (row.get('title') or '').strip(), 'html': row.get('html') or '',
                    'observed_at': (row.get('observed_at') or row.get('date') or '').strip(),
                    'page_type': (row.get('page_type') or '').strip(),
                    **{name: (row.get(name) or '').strip() for name in ['reviewed_by', 'reviewed_at', 'label_evidence']},
                    **annotations,
                    'label_scope': 'mixed_threat' if include_other_threats else 'phishing',
                })
    rows = list(rows_by_url.values())
    if balanced:
        groups = [[r for r in rows if r['label'] == label] for label in [0, 1]]
        if any(not group for group in groups):
            raise ValueError('Balanced sampling requires both classes; check label scope')
        target = min(map(len, groups))
        if limit:
            target = min(target, limit // 2)
        rng = random.Random(seed)
        rows = [record for group in groups for record in rng.sample(group, target)]
        rng.shuffle(rows)
    elif limit and len(rows) > limit:
        rows = random.Random(seed).sample(rows, limit)
    return rows


def build_matrix(records: list[dict], schema: list[str] | None = None) -> list[list[float]]:
    schema = schema or FEATURE_SCHEMA
    if any(name not in FEATURE_SCHEMA for name in schema):
        raise ValueError('Unsupported model feature schema')
    if any(name not in URL_FEATURE_SCHEMA for name in schema):
        if any(not record.get('html', '').strip() for record in records):
            raise ValueError('DOM model needs observed HTML; missing DOM must not be encoded as harmless zero values')
    matrix = []
    for record in records:
        document_url = record.get('final_url') or record['url']
        row = record.get('feature_row') or build_feature_row(document_url, record.get('title', ''), record.get('html', ''))
        if record.get('feature_row') is not None and record.get('feature_schema_version') != FEATURE_SCHEMA_VERSION:
            raise ValueError('Captured browser feature version does not match the training contract')
        if record.get('feature_row') is not None and record.get('extractor_sha256') != extractor_source_hash():
            raise ValueError('Captured browser extractor hash does not match current sources; recapture or use the pinned extractor checkout')
        validate_feature_row(row)
        matrix.append([float(row[name]) for name in schema])
    return matrix


def grouped_split(records: list[dict], test_size: float, seed: int) -> tuple[list[dict], list[dict]]:
    groups = np.asarray(connected_groups(records))
    if len(set(groups)) < 3:
        raise ValueError('Grouped evaluation needs at least three independent site/content groups')
    labels = np.asarray([r['label'] for r in records])
    splitter = GroupShuffleSplit(n_splits=200, test_size=test_size, random_state=seed)
    for train_indices, test_indices in splitter.split(records, labels, groups):
        if len(set(labels[train_indices])) == 2 and len(set(labels[test_indices])) == 2:
            return [records[i] for i in train_indices], [records[i] for i in test_indices]
    raise ValueError('Cannot create grouped partitions with both classes; collect more independent sites')


def partition_records(records: list[dict], seed: int) -> dict[str, list[dict]]:
    selection, test = grouped_split(records, .2, seed)
    development, calibration = grouped_split(selection, .25, seed + 1)
    fit, tuning = grouped_split(development, .25, seed + 2)
    return {'fit': fit, 'tuning': tuning, 'calibration': calibration, 'test': test}


def wilson_interval(positives: int, samples: int) -> list[float]:
    if not samples:
        return [0., 1.]
    z = 1.959963984540054
    p = positives / samples
    center = (p + z*z/(2*samples)) / (1+z*z/samples)
    spread = z * ((p*(1-p)/samples + z*z/(4*samples*samples)) ** .5) / (1+z*z/samples)
    return [max(0., center-spread), min(1., center+spread)]


def probability_metrics(labels, probabilities, threshold: float) -> dict:
    labels, probabilities = np.asarray(labels), np.asarray(probabilities)
    predictions = probabilities >= threshold
    tn, fp, fn, tp = confusion_matrix(labels, predictions, labels=[0, 1]).ravel()
    return {
        'accuracy': float(accuracy_score(labels, predictions)),
        'precision': float(precision_score(labels, predictions, zero_division=0)),
        'recall': float(recall_score(labels, predictions, zero_division=0)),
        'f1': float(f1_score(labels, predictions, zero_division=0)),
        'roc_auc': float(roc_auc_score(labels, probabilities)),
        'average_precision': float(average_precision_score(labels, probabilities)),
        'positive_prevalence': float(np.mean(labels == 1)),
        'threshold': float(threshold),
        'false_positive_rate': float(fp / (fp + tn)),
        'false_positive_rate_95ci': wilson_interval(int(fp), int(fp+tn)),
        'recall_95ci': wilson_interval(int(tp), int(tp+fn)),
        'confusion_matrix': {k: int(v) for k, v in zip(['tn','fp','fn','tp'], [tn,fp,fn,tp])},
    }


class NoFeasibleThresholdError(ValueError):
    """No probability threshold in [0, 1] meets the empirical FPR budget."""


def select_fpr_threshold(labels, probabilities, fpr_budget: float) -> tuple[float, dict]:
    if not 0 <= fpr_budget < 1:
        raise ValueError('FPR budget must be in [0, 1)')
    labels, probabilities = np.asarray(labels), np.asarray(probabilities)
    if (labels.ndim != 1 or probabilities.ndim != 1 or labels.shape != probabilities.shape
        or set(labels) != {0, 1} or not np.isfinite(probabilities).all()
        or np.any((probabilities < 0) | (probabilities > 1))):
        raise ValueError('Calibration needs both classes and matching finite probabilities in [0, 1]')
    candidates = {1.0}
    for probability in probabilities:
        candidates.add(float(probability))
        above = float(np.nextafter(probability, np.inf))
        if above <= 1:
            candidates.add(above)
    sorted_negative = np.sort(probabilities[labels == 0])
    sorted_positive = np.sort(probabilities[labels == 1])
    feasible = []
    for threshold in sorted(candidates):
        fpr = 1 - np.searchsorted(sorted_negative, threshold, side='left') / len(sorted_negative)
        recall = 1 - np.searchsorted(sorted_positive, threshold, side='left') / len(sorted_positive)
        if fpr <= fpr_budget:
            feasible.append((float(recall), -float(fpr), threshold))
    if not feasible:
        raise NoFeasibleThresholdError('No probability threshold meets the calibration FPR budget; improve the model/data')
    threshold = max(feasible)[2]
    return threshold, probability_metrics(labels, probabilities, threshold)


def select_tuning_candidate(labels, candidate_probabilities: dict, fpr_budget: float) -> tuple[object, dict]:
    """Compare candidates at the product's operating point on tuning data only.

    Global AUC can prefer a model whose highest-scoring legitimate pages prevent
    any phishing recall at a low false-positive budget. Thresholds found here
    rank candidates only: final-fit predictions must be calibrated separately.
    Wilson intervals describe sampling uncertainty, not selection-adjusted bounds.
    """
    if not candidate_probabilities:
        raise ValueError('At least one tuning candidate is required')
    results = {}
    feasible = []
    for name, probabilities in candidate_probabilities.items():
        try:
            _, operating = select_fpr_threshold(labels, probabilities, fpr_budget)
        except NoFeasibleThresholdError:
            results[name] = {
                'operating_point_feasible': False,
                'fpr_budget': fpr_budget,
                'default_threshold_metrics': probability_metrics(labels, probabilities, .5),
                'reason': 'No threshold in [0, 1] meets the empirical tuning FPR budget',
            }
            continue
        results[name] = {
            **operating,
            'operating_point_feasible': True,
            'fpr_budget': fpr_budget,
            'default_threshold_metrics': probability_metrics(labels, probabilities, .5),
        }
        feasible.append(name)
    if not feasible:
        raise ValueError('No candidate meets the tuning FPR budget; improve the model/data')
    winner = max(feasible, key=lambda name: (
        results[name]['recall'], -results[name]['false_positive_rate'],
        results[name]['average_precision'], results[name]['roc_auc']))
    return winner, results


def tuning_selection_contract(fpr_budget: float) -> dict:
    return {
        'method': 'tuning_recall_at_empirical_fpr_budget',
        'partition': 'tuning',
        'fpr_budget': fpr_budget,
        'tie_breakers': ['lower_false_positive_rate', 'higher_average_precision', 'higher_roc_auc'],
        'threshold_is_final': False,
        'uncertainty': 'Reported intervals are descriptive; tuning selection is not release validation',
    }


def score_model(model, x_test, y_test, threshold: float = .5) -> tuple[dict, np.ndarray]:
    probabilities = model.predict_proba(x_test)[:, 1]
    return probability_metrics(y_test, probabilities, threshold), probabilities


def train(records: list[dict], seed: int = 42, model_version: str = 'url-compact-v1',
          fpr_budget: float = .01, dom: bool = False, reserved_test: dict | None = None) -> tuple[dict, dict, object]:
    started_at = datetime.now(timezone.utc).isoformat()
    from release_contract import release_requirements
    all_manifest = manifest(records, 'all_development_data')
    if reserved_test is not None:
        assert_separated(all_manifest, reserved_test, source_time=True)
    schema = FEATURE_SCHEMA if dom else URL_FEATURE_SCHEMA
    partitions = partition_records(records, seed)
    matrices = {name: np.asarray(build_matrix(rows, schema), dtype=float) for name, rows in partitions.items()}
    labels = {name: np.asarray([r['label'] for r in rows]) for name, rows in partitions.items()}
    candidates = [
        ('random_forest_32', RandomForestClassifier(n_estimators=32, max_depth=16, min_samples_leaf=2,
          class_weight='balanced_subsample', n_jobs=-1, random_state=seed)),
        ('extra_trees_32', ExtraTreesClassifier(n_estimators=32, max_depth=16, min_samples_leaf=2,
          class_weight='balanced', n_jobs=-1, random_state=seed)),
    ]
    tuning_probabilities = {}
    for name, candidate in candidates:
        candidate.fit(matrices['fit'], labels['fit'])
        tuning_probabilities[name] = candidate.predict_proba(matrices['tuning'])[:, 1]
    winner_name, validation_results = select_tuning_candidate(labels['tuning'], tuning_probabilities, fpr_budget)
    winner = clone(dict(candidates)[winner_name])
    winner.fit(np.concatenate([matrices['fit'], matrices['tuning']]), np.concatenate([labels['fit'], labels['tuning']]))
    # Calibration happens after final fitting and is never used for refitting.
    calibration_probabilities = winner.predict_proba(matrices['calibration'])[:, 1]
    threshold, calibration_metrics = select_fpr_threshold(labels['calibration'], calibration_probabilities, fpr_budget)
    test_metrics, _ = score_model(winner, matrices['test'], labels['test'], threshold)
    manifests = {name: manifest(rows, name) for name, rows in partitions.items()}
    metrics = {'samples': len(records), 'split_strategy': 'connected_original_final_psl_site_and_exact_content_grouped',
               'source_time_separated': False, 'winner': winner_name, 'tuning_models': validation_results,
               'selection': tuning_selection_contract(fpr_budget),
               'calibration': calibration_metrics, 'test': test_metrics}
    artifact = {
        'model_version': model_version, 'feature_schema': schema,
        'feature_schema_version': FEATURE_SCHEMA_VERSION, 'extractor_version': FEATURE_SCHEMA_VERSION,
        'extractor_sha256': extractor_source_hash(),
        'feature_schema_sha256': sha256(json.dumps(schema, separators=(',', ':'))),
        'feature_scope': 'observed_dom' if dom else 'url_only',
        'label_scope': 'mixed_threat' if any(r.get('label_scope') == 'mixed_threat' for r in records) else 'phishing',
        'algorithm': winner_name, 'threshold': threshold, 'tree_count': len(winner.estimators_),
        'selection': tuning_selection_contract(fpr_budget),
        'calibration': {'method': 'independent_fpr_budget', 'fpr_budget': fpr_budget, **calibration_metrics},
        'manifests': manifests, 'development_manifest': all_manifest,
        'reserved_test_manifest': reserved_test, 'training_started_at': started_at,
        'release_requirements': release_requirements(),
        'training_completed_at': datetime.now(timezone.utc).isoformat(),
        'deployment_eligible': False, 'deployment_status': 'research_only', 'metrics': metrics,
    }
    return artifact, metrics, winner


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--dataset', type=Path, required=True)
    parser.add_argument('--additional-dataset', type=Path, action='append', default=[])
    parser.add_argument('--include-edgephish', action='store_true')
    parser.add_argument('--include-other-threats', action='store_true', help='Explicitly include mixed malware/defacement/bad labels')
    parser.add_argument('--output', type=Path, default=Path('ml/models/url-compact-v1.json'))
    parser.add_argument('--model-version', default='url-compact-v1')
    parser.add_argument('--limit', type=int)
    parser.add_argument('--balanced', action='store_true')
    parser.add_argument('--refresh', action='store_true', help='Explicitly download the configured dataset')
    parser.add_argument('--fpr-budget', type=float, default=.01)
    parser.add_argument('--reserved-test-manifest', type=Path)
    args = parser.parse_args()
    paths = [args.dataset, *args.additional_dataset]
    if args.refresh:
        download_dataset(args.dataset)
    if args.include_edgephish:
        edge = Path('ml/data/edgephish_balanced_urls.csv')
        if args.refresh:
            download_dataset(edge, EDGEPHISH_DATASET_URL)
        paths.append(edge)
    records = read_dataset(paths, args.limit, balanced=args.balanced, include_other_threats=args.include_other_threats)
    reserved = json.loads(args.reserved_test_manifest.read_text(encoding='utf-8')) if args.reserved_test_manifest else None
    artifact, metrics, model = train(records, model_version=args.model_version, fpr_budget=args.fpr_budget, reserved_test=reserved)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, args.output.with_suffix('.joblib'))
    artifact['model_file_sha256'] = __import__('hashlib').sha256(args.output.with_suffix('.joblib').read_bytes()).hexdigest()
    args.output.write_text(json.dumps(artifact, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(metrics, indent=2))


if __name__ == '__main__':
    main()
