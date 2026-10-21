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

from feature_engineering import FEATURE_SCHEMA
from train_model import build_matrix, read_dataset, registrable_domain

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
    phishing = read_dataset(phishing_paths, seed=seed, balanced=False)
    legitimate = read_dataset(
        legitimate_paths,
        limit=legitimate_limit,
        seed=seed,
        balanced=False,
    )
    phishing_domains = {registrable_domain(record["url"]) for record in phishing}
    legitimate_before = len(legitimate)
    # Preserve every phishing row; remove only legitimate rows that would
    # make the future test cross-class domain-contaminated.
    legitimate = [
        record
        for record in legitimate
        if registrable_domain(record["url"]) not in phishing_domains
    ]
    records = phishing + legitimate
    if len({record["label"] for record in records}) != 2:
        raise ValueError("Future evaluation requires both phishing and legitimate records")
    return records, {
        "phishing_records": len(phishing),
        "legitimate_records": len(legitimate),
        "phishing_domains": len({registrable_domain(record["url"]) for record in phishing}),
        "legitimate_domains": len({registrable_domain(record["url"]) for record in legitimate}),
        "legitimate_removed_for_domain_overlap": legitimate_before - len(legitimate),
    }


def dom_coverage(records: list[dict]) -> dict:
    feature_rows = build_feature_rows(records)
    coverage = {}
    for feature in DOM_FEATURES:
        values = [float(row[feature]) for row in feature_rows]
        nonzero = sum(value != 0 for value in values)
        coverage[feature] = {
            "nonzero": nonzero,
            "rate": round(nonzero / len(values), 6) if values else 0.0,
            "phishing_rate": round(
                sum(value != 0 for value, record in zip(values, records) if record["label"] == 1)
                / max(1, sum(record["label"] == 1 for record in records)),
                6,
            ),
            "legitimate_rate": round(
                sum(value != 0 for value, record in zip(values, records) if record["label"] == 0)
                / max(1, sum(record["label"] == 0 for record in records)),
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
    rows = build_matrix(records)
    indices = []
    for name in schema:
        if name not in FEATURE_SCHEMA:
            raise ValueError(f"Model schema contains unsupported feature {name!r}")
        indices.append(FEATURE_SCHEMA.index(name))
    return np.asarray([[row[index] for index in indices] for row in rows], dtype=float)


def model_probabilities(
    model_path: Path,
    records: list[dict],
    feature_schema: list[str] | None = None,
) -> tuple[np.ndarray, str]:
    artifact = joblib.load(model_path)
    if isinstance(artifact, dict) and "model" in artifact and "vectorizer" in artifact:
        urls = [record["url"] for record in records]
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


def evaluate(
    model_path: Path,
    metadata_path: Path,
    records: list[dict],
    dataset_paths: list[Path],
) -> dict:
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    metadata_schema = metadata.get("feature_schema")
    if metadata_schema is not None and (
        not isinstance(metadata_schema, list)
        or not all(isinstance(name, str) for name in metadata_schema)
    ):
        raise ValueError("Metadata feature_schema must be a list of feature names")
    probabilities, artifact_type = model_probabilities(model_path, records, metadata_schema)
    threshold = float(metadata.get("threshold", 0.5))
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
    return {
        "protocol": "future_source_separated_v1",
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
        "dataset_sha256": {str(path): file_sha256(path) for path in dataset_paths},
        "leakage_check": {
            "cross_class_registrable_domain_overlap": overlap_count,
            "passed": overlap_count == 0,
        },
        "dom_coverage": dom_coverage(records),
        "metrics": {
            "accuracy": round(float(accuracy_score(labels, predictions)), 6),
            "precision": round(float(precision_score(labels, predictions, zero_division=0)), 6),
            "recall": round(float(recall_score(labels, predictions, zero_division=0)), 6),
            "false_negative_rate": round(float(fn / max(1, fn + tp)), 6),
            "false_positive_rate": round(float(fp / max(1, fp + tn)), 6),
            "f1": round(float(f1_score(labels, predictions, zero_division=0)), 6),
            "mcc": round(float(matthews_corrcoef(labels, predictions)), 6),
            "roc_auc": safe_auc(roc_auc_score, labels, probabilities),
            "pr_auc": safe_auc(average_precision_score, labels, probabilities),
            "threshold": threshold,
            "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
        },
        "operating_points": operating_points(labels, probabilities),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", type=Path, required=True)
    parser.add_argument("--metadata", type=Path, required=True)
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
    args = parser.parse_args()

    dataset_paths = [*args.phishing_dataset, *args.legitimate_dataset]
    records, counts = load_records(
        args.phishing_dataset,
        args.legitimate_dataset,
        args.legitimate_limit,
        args.seed,
    )
    result = evaluate(args.model, args.metadata, records, dataset_paths)
    result["input_counts"] = counts
    result["observed_at_values"] = sorted(
        {record["observed_at"] for record in records if record["observed_at"]}
    )
    rendered = json.dumps(result, indent=2)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)


if __name__ == "__main__":
    main()
