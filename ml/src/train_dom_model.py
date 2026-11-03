"""Train the browser-compatible DOM-aware model from JSONL snapshots."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import joblib

from dom_dataset import load_snapshots, validate_records
from train_model import train


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("snapshot_file", type=Path)
    parser.add_argument("--output", type=Path, default=Path("ml/models/dom-aware-v0.1.0.json"))
    parser.add_argument("--model-version", default="dom-aware-v0.1.0")
    parser.add_argument('--fpr-budget', type=float, default=.01)
    parser.add_argument('--reserved-test-manifest', type=Path)
    args = parser.parse_args()

    records = load_snapshots(args.snapshot_file)
    report = validate_records(records)
    if report["html_coverage"] < 1 or not report["legitimate"] or not report["phishing"]:
        raise ValueError("DOM model requires HTML and both classes")
    if report['captured_feature_coverage'] < 1:
        raise ValueError('Recapture with the versioned browser extractor: static HTML cannot reproduce computed CSS/layout')
    if any(record.get('capture_document_status') != 'bound_to_loader' for record in records):
        raise ValueError('Recapture DOM training data with document-bound HTTP status; legacy unbound snapshots are exploratory only')

    reserved = json.loads(args.reserved_test_manifest.read_text(encoding='utf-8')) if args.reserved_test_manifest else None
    artifact, metrics, model = train(records, model_version=args.model_version, dom=True,
                                     fpr_budget=args.fpr_budget, reserved_test=reserved)
    artifact["dataset"] = report
    artifact["training_input"] = str(args.snapshot_file)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, args.output.with_suffix(".joblib"))
    artifact['model_file_sha256'] = __import__('hashlib').sha256(args.output.with_suffix('.joblib').read_bytes()).hexdigest()
    args.output.write_text(json.dumps(artifact, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"dataset": report, "metrics": metrics}, indent=2))


if __name__ == "__main__":
    main()
