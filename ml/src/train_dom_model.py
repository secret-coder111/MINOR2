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
    args = parser.parse_args()

    records = load_snapshots(args.snapshot_file)
    report = validate_records(records)
    if report["cross_class_domain_overlap"]:
        raise ValueError("DOM snapshots contain cross-class domain leakage")
    if report["html_coverage"] < 1 or not report["legitimate"] or not report["phishing"]:
        raise ValueError("DOM model requires HTML and both classes")

    artifact, metrics, model = train(records, model_version=args.model_version)
    artifact["dataset"] = report
    artifact["training_input"] = str(args.snapshot_file)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(artifact, indent=2) + "\n", encoding="utf-8")
    joblib.dump(model, args.output.with_suffix(".joblib"))
    print(json.dumps({"dataset": report, "metrics": metrics}, indent=2))


if __name__ == "__main__":
    main()
