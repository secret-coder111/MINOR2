"""Evaluate phishing models on an untouched future/source-separated test set.

This evaluator deliberately keeps every phishing record. If a cap is supplied,
it is applied only to legitimate records. It also reports leakage checks and
whether DOM features are actually present in the evaluated data.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
from collections import Counter
from pathlib import Path
from datetime import datetime, timezone

import joblib
import numpy as np
import sklearn
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    confusion_matrix,
    f1_score,
    matthews_corrcoef,
    precision_score,
    recall_score,
    roc_auc_score,
)

from feature_engineering import FEATURE_SCHEMA, URL_FEATURE_SCHEMA, extractor_source_hash
from train_model import build_matrix, read_dataset, registrable_domain, wilson_interval
from dataset_contract import manifest, assert_separated, normalize_url, aware_timestamp
from release_contract import benchmark_review, independent_group_metrics, release_gate, assert_reviews_frozen

DOM_FEATURES = [
    "page_title_mismatch",
    "form_count",
    "has_password_input",
    "credential_field_count",
    "cross_domain_form_action",
    "hidden_field_count",
    "form_action_is_empty",
    "obfuscated_script_score",
    "hidden_iframe_count",
    "external_script_count",
    "meta_refresh_count",
    "brand_name_in_title",
    "brand_name_in_visible_text",
]


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_records(
    phishing_paths: list[Path],
    legitimate_paths: list[Path],
    legitimate_limit: int | None,
    seed: int,
) -> tuple[list[dict], dict]:
    def load(paths):
        from dom_dataset import load_snapshots
        records = []
        csv_paths = [path for path in paths if path.suffix.lower() != '.jsonl']
        if csv_paths:
            records.extend(read_dataset(csv_paths, seed=seed, balanced=False))
        for path in paths:
            if path.suffix.lower() == '.jsonl':
                records.extend(load_snapshots(path))
        return records
    phishing = load(phishing_paths)
    legitimate = load(legitimate_paths)
    if any(record['label'] != 1 for record in phishing) or any(record['label'] != 0 for record in legitimate):
        raise ValueError('Explicit phishing/legitimate input groups contain unexpected labels')
    records_by_url = {}
    for record in phishing + legitimate:
        previous = records_by_url.get(record['url'])
        if previous is not None and previous != record:
            raise ValueError('Different evaluation observations for the same URL must be resolved before freezing')
        records_by_url.setdefault(record['url'], record)
    phishing = [record for record in records_by_url.values() if record['label'] == 1]
    legitimate = [record for record in records_by_url.values() if record['label'] == 0]
    if legitimate_limit is not None and legitimate_limit < 1:
        raise ValueError('legitimate_limit must be positive or omitted')
    if legitimate_limit and len(legitimate) > legitimate_limit:
        import random
        legitimate = random.Random(seed).sample(legitimate, legitimate_limit)
    records = phishing + legitimate
    if len({record["label"] for record in records}) != 2:
        raise ValueError("Future evaluation requires both phishing and legitimate records")
    return records, {
        "phishing_records": len(phishing),
        "legitimate_records": len(legitimate),
        "phishing_domains": len({registrable_domain(record["url"]) for record in phishing}),
        "legitimate_domains": len({registrable_domain(record["url"]) for record in legitimate}),
        "legitimate_removed_for_domain_overlap": 0,
    }


def dom_coverage(records: list[dict]) -> dict:
    # Absence of HTML is unobserved, not an observed all-zero DOM.
    observed = [record for record in records if record.get('html', '').strip()]
    if not observed:
        return {'status': 'unobserved', 'observed_pages': 0, 'total_pages': len(records)}
    feature_rows = build_feature_rows(observed)
    coverage = {}
    for feature in DOM_FEATURES:
        values = [float(row[feature]) for row in feature_rows]
        nonzero = sum(value != 0 for value in values)
        coverage[feature] = {
            "nonzero": nonzero,
            "rate": round(nonzero / len(values), 6) if values else 0.0,
            "phishing_rate": round(
                sum(value != 0 for value, record in zip(values, observed) if record["label"] == 1)
                / max(1, sum(record["label"] == 1 for record in observed)),
                6,
            ),
            "legitimate_rate": round(
                sum(value != 0 for value, record in zip(values, observed) if record["label"] == 0)
                / max(1, sum(record["label"] == 0 for record in observed)),
                6,
            ),
        }
    return coverage


def build_feature_rows(records: list[dict]) -> list[dict]:
    matrix = build_matrix(records)
    return [
        {name: row[index] for index, name in enumerate(FEATURE_SCHEMA)}
        for row in matrix
    ]


def build_matrix_for_schema(records: list[dict], schema: list[str]) -> np.ndarray:
    return np.asarray(build_matrix(records, schema), dtype=float)


def model_probabilities(
    model_path: Path,
    records: list[dict],
    feature_schema: list[str] | None = None,
) -> tuple[np.ndarray, str]:
    artifact = joblib.load(model_path)
    if isinstance(artifact, dict) and "model" in artifact and "vectorizer" in artifact:
        urls = [record.get('final_url') or record['url'] for record in records]
        probabilities = artifact["model"].predict_proba(
            artifact["vectorizer"].transform(urls)
        )[:, 1]
        return probabilities, "character_tfidf_bundle"
    if not hasattr(artifact, "predict_proba"):
        raise TypeError(f"Unsupported model artifact: {model_path}")
    features = build_matrix_for_schema(records, feature_schema or FEATURE_SCHEMA)
    return artifact.predict_proba(features)[:, 1], "feature_estimator"


def safe_auc(metric, labels, probabilities) -> float | None:
    try:
        return round(float(metric(labels, probabilities)), 6)
    except ValueError:
        return None


def operating_points(labels: np.ndarray, probabilities: np.ndarray) -> list[dict]:
    points = []
    for threshold in np.linspace(0.1, 0.9, 17):
        predictions = probabilities >= threshold
        tn, fp, fn, tp = confusion_matrix(labels, predictions, labels=[0, 1]).ravel()
        points.append({
            "threshold": round(float(threshold), 4),
            "precision": round(float(precision_score(labels, predictions, zero_division=0)), 6),
            "recall": round(float(recall_score(labels, predictions, zero_division=0)), 6),
            "false_positive_rate": round(float(fp / max(1, fp + tn)), 6),
            "false_negative_rate": round(float(fn / max(1, fn + tp)), 6),
        })
    return points


def breakdown(records: list[dict], labels, probabilities, threshold: float, key) -> dict:
    groups = {}
    for index, record in enumerate(records):
        groups.setdefault(key(record), []).append(index)
    output = {}
    for name, indices in sorted(groups.items()):
        y = labels[indices]
        predictions = probabilities[indices] >= threshold
        tn,fp,fn,tp = confusion_matrix(y,predictions,labels=[0,1]).ravel()
        output[name] = {'samples':len(indices),
            'confusion_matrix':dict(zip(['tn','fp','fn','tp'],[int(tn),int(fp),int(fn),int(tp)])),
            'false_positive_rate':float(fp/(fp+tn)) if fp+tn else None,
            'false_positive_rate_95ci':wilson_interval(int(fp),int(fp+tn)) if fp+tn else None,
            'recall':float(tp/(tp+fn)) if tp+fn else None,
            'recall_95ci':wilson_interval(int(tp),int(tp+fn)) if tp+fn else None}
    return output


def page_type(record: dict) -> str:
    if record.get('page_type'):
        return record['page_type']
    features = record.get('feature_row')
    if features is None:
        return 'unobserved_url_only'
    return 'password_page' if features['has_password_input'] else ('identity_or_sensitive_fields' if features['credential_field_count'] else 'no_credential_fields')


def evaluate(
    model_path: Path,
    metadata_path: Path,
    records: list[dict],
    dataset_paths: list[Path],
    frozen_manifest: dict | None = None,
    exploratory: bool = False,
    representative_login_reviewed: bool = False,
) -> dict:
    if not records or {record['label'] for record in records} != {0, 1}:
        raise ValueError('Evaluation requires both phishing and legitimate records')
    normalized_urls = [normalize_url(record['url']) for record in records]
    if not all(normalized_urls):
        raise ValueError('Evaluation requires valid HTTP(S) URLs')
    if len(set(normalized_urls)) != len(records):
        raise ValueError('Duplicate evaluation URLs would inflate metrics; resolve them before evaluation')
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    current_manifest = manifest(records, 'frozen_future_test')
    if not exploratory:
        if frozen_manifest is None or not metadata.get('development_manifest') or not metadata.get('reserved_test_manifest'):
            raise ValueError('Future evaluation needs a test frozen before training and reserved in training metadata; legacy runs are exploratory only')
        identity = lambda value: {key: item for key, item in value.items() if key not in {'created_at','purpose'}}
        if identity(current_manifest) != identity(frozen_manifest) or identity(frozen_manifest) != identity(metadata['reserved_test_manifest']):
            raise ValueError('Frozen test changed or was not reserved by this training run')
        frozen_at = aware_timestamp(frozen_manifest.get('created_at'), 'Test freeze date')
        reserved_at = aware_timestamp(metadata['reserved_test_manifest'].get('created_at'), 'Reserved test freeze date')
        training_started = aware_timestamp(metadata.get('training_started_at'), 'Training start date')
        if frozen_at != reserved_at:
            raise ValueError('Test freeze date differs from the manifest reserved before training')
        if max(frozen_at, training_started) > datetime.now(timezone.utc):
            raise ValueError('Test freeze/training dates must not be in the future')
        if frozen_at >= training_started:
            raise ValueError('Test must be frozen before model selection/training starts')
        if any(aware_timestamp(value, 'Test observation date') > frozen_at for value in frozen_manifest.get('observed_at', [])):
            raise ValueError('Test observations must exist before the test manifest is frozen')
        assert_reviews_frozen(records, frozen_at)
        assert_separated(metadata['development_manifest'], frozen_manifest, source_time=True)
        if metadata.get('model_file_sha256') != file_sha256(model_path):
            raise ValueError('Model hash differs from training metadata')
        if metadata.get('feature_scope') != 'character_url' and metadata.get('extractor_sha256') != extractor_source_hash():
            raise ValueError('Extractor changed since training')
    metadata_schema = metadata.get("feature_schema")
    if metadata_schema is not None and (
        not isinstance(metadata_schema, list)
        or not all(isinstance(name, str) for name in metadata_schema)
    ):
        raise ValueError("Metadata feature_schema must be a list of feature names")
    probabilities, artifact_type = model_probabilities(model_path, records, metadata_schema)
    threshold = float(metadata.get("threshold", 0.5))
    if not np.isfinite(threshold) or not 0 <= threshold <= 1:
        raise ValueError('Evaluation threshold must be a finite probability in [0, 1]')
    if (probabilities.shape != (len(records),) or not np.isfinite(probabilities).all()
        or np.any((probabilities < 0) | (probabilities > 1))):
        raise ValueError('Model must return one finite probability in [0, 1] per record')
    labels = np.asarray([record["label"] for record in records])
    predictions = probabilities >= threshold
    tn, fp, fn, tp = confusion_matrix(labels, predictions, labels=[0, 1]).ravel()
    sources = Counter(record.get("source") or "unspecified" for record in records)
    phishing_domains = {
        registrable_domain(record["url"])
        for record in records
        if record["label"] == 1
    }
    legitimate_domains = {
        registrable_domain(record["url"])
        for record in records
        if record["label"] == 0
    }
    overlap_count = len(phishing_domains & legitimate_domains)
    report = {
        "protocol": "exploratory_only" if exploratory else "frozen_future_source_time_separated_v2",
        'frozen_before_training': not exploratory,
        'representative_login_reviewed': representative_login_reviewed,
        'model_sha256': file_sha256(model_path),
        'metadata_sha256': file_sha256(metadata_path),
        "model": str(model_path),
        "metadata": str(metadata_path),
        "artifact_type": artifact_type,
        "model_version": metadata.get("model_version", "unknown"),
        "python": platform.python_version(),
        "scikit_learn": sklearn.__version__,
        "samples": len(records),
        "class_counts": {
            "legitimate": int(sum(labels == 0)),
            "phishing": int(sum(labels == 1)),
        },
        "sources": dict(sources),
        'by_source': breakdown(records,labels,probabilities,threshold,lambda r:r.get('source') or 'unspecified'),
        'by_page_type': breakdown(records,labels,probabilities,threshold,page_type),
        "dataset_sha256": {str(path): file_sha256(path) for path in dataset_paths},
        "leakage_check": {
            "cross_class_registrable_domain_overlap": overlap_count,
            "passed": not exploratory,
            'meaning': 'Overlap between classes can be valid; separation is checked against all development manifests',
        },
        "dom_coverage": dom_coverage(records),
        "metrics": {
            "accuracy": round(float(accuracy_score(labels, predictions)), 6),
            "precision": round(float(precision_score(labels, predictions, zero_division=0)), 6),
            "recall": round(float(recall_score(labels, predictions, zero_division=0)), 6),
            "false_negative_rate": round(float(fn / max(1, fn + tp)), 6),
            "false_positive_rate": round(float(fp / max(1, fp + tn)), 6),
            'false_positive_rate_95ci': wilson_interval(int(fp), int(fp+tn)),
            'recall_95ci': wilson_interval(int(tp), int(tp+fn)),
            "f1": round(float(f1_score(labels, predictions, zero_division=0)), 6),
            "mcc": round(float(matthews_corrcoef(labels, predictions)), 6),
            "roc_auc": safe_auc(roc_auc_score, labels, probabilities),
            "pr_auc": safe_auc(average_precision_score, labels, probabilities),
            "threshold": threshold,
            "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
        },
        "operating_points": operating_points(labels, probabilities),
    }
    report['release_requirements'] = metadata.get('release_requirements')
    report['independent_group_metrics'] = independent_group_metrics(records, predictions)
    report['benchmark_review'] = benchmark_review(records, require_document_binding=metadata.get('feature_scope') == 'observed_dom')
    report['release_gate'] = release_gate(report['metrics'], report['independent_group_metrics'],
        report['benchmark_review'], metadata.get('release_requirements'), metadata.get('calibration', {}).get('fpr_budget', 0))
    if exploratory or not representative_login_reviewed:
        report['release_gate']['passed'] = False
        report['release_gate']['errors'].append('A frozen evaluation and explicit representative login review are required')
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", type=Path)
    parser.add_argument("--metadata", type=Path)
    parser.add_argument("--phishing-dataset", type=Path, action="append", required=True)
    parser.add_argument("--legitimate-dataset", type=Path, action="append", required=True)
    parser.add_argument(
        "--legitimate-limit",
        type=int,
        default=100000,
        help="Cap legitimate rows only; every phishing row is retained.",
    )
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--output", type=Path)
    parser.add_argument('--freeze-manifest', type=Path, help='Freeze input identity only, before training; does not evaluate')
    parser.add_argument('--test-manifest', type=Path)
    parser.add_argument('--exploratory', action='store_true', help='Legacy/previously seen data: never claim an untouched future test')
    parser.add_argument('--representative-login-reviewed', action='store_true', help='Assert independent human review of representative legitimate login/SSO composition and labels')
    args = parser.parse_args()

    dataset_paths = [*args.phishing_dataset, *args.legitimate_dataset]
    records, counts = load_records(
        args.phishing_dataset,
        args.legitimate_dataset,
        args.legitimate_limit,
        args.seed,
    )
    if args.freeze_manifest:
        if args.freeze_manifest.exists():
            raise ValueError('Frozen manifest already exists; do not replace an evaluation holdout')
        args.freeze_manifest.parent.mkdir(parents=True, exist_ok=True)
        args.freeze_manifest.write_text(json.dumps(manifest(records, 'frozen_future_test'), indent=2)+'\n', encoding='utf-8')
        print(f'Frozen {len(records)} records at {args.freeze_manifest}; no model evaluated')
        return
    if not args.model or not args.metadata:
        raise ValueError('--model and --metadata are required for evaluation')
    frozen = json.loads(args.test_manifest.read_text(encoding='utf-8')) if args.test_manifest else None
    receipt = args.test_manifest.with_suffix('.used.json') if args.test_manifest else None
    if not args.exploratory and receipt and receipt.exists():
        raise ValueError('This frozen holdout was already evaluated. Collect a new untouched test for new model decisions')
    result = evaluate(args.model, args.metadata, records, dataset_paths, frozen,
                      args.exploratory, args.representative_login_reviewed)
    result["input_counts"] = counts
    result["observed_at_values"] = sorted(
        {record["observed_at"] for record in records if record["observed_at"]}
    )
    rendered = json.dumps(result, indent=2)
    if args.output:
        if args.output.exists():
            raise ValueError('Use a new report path; evaluation evidence must not be overwritten')
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n", encoding="utf-8")
    if not args.exploratory and receipt:
        receipt.write_text(json.dumps({'model_sha256': result['model_sha256'], 'evaluated_at': datetime.now(timezone.utc).isoformat(),
            'report_sha256': hashlib.sha256(rendered.encode('utf-8')).hexdigest()}, indent=2)+'\n', encoding='utf-8')
    print(rendered)


if __name__ == "__main__":
    main()
