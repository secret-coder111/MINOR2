r"""Reproduce offline ML audit findings without changing production files.

Run from the repository root:
  .venv\Scripts\python.exe docs/audit/tester-ml-probes.py

All URLs/labels are synthetic fixtures. No URL is visited. The capture probe
mocks Playwright to model an already-completed JavaScript navigation; it is
not a real-browser redirect test. Temporary artifacts are automatically removed.
"""
from __future__ import annotations

import contextlib
import argparse
import csv
import hashlib
import io
import itertools
import json
import sys
import tempfile
from pathlib import Path
from types import ModuleType
from unittest.mock import MagicMock, patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "ml/src"))

import joblib
from capture_dom_snapshots import capture
from dataset_contract import assert_separated, manifest
from dom_dataset import load_snapshots
from export_browser_model import export_model
from feature_engineering import build_feature_row
from future_test_protocol import evaluate
from train_model import read_dataset, train


def provenance_roundtrip(base: Path) -> dict:
    original_manifests, reloaded_manifests, changes = [], [], []
    for name, url, label, date in [
        ("training", "https://source-train.test/", 0, "2025-01-01T00:00:00Z"),
        ("future", "https://source-future.test/", 1, "2025-02-01T00:00:00Z"),
    ]:
        source = base / (name + ".csv")
        source.write_text(
            "url,label,observed_at\n" + f"{url},{label},{date}\n", encoding="utf-8"
        )
        original = read_dataset([source])
        original_manifests.append(manifest(original, name))
        copied = base / (name + "-roundtrip.csv")
        with copied.open("w", newline="", encoding="utf-8") as output:
            writer = csv.DictWriter(output, fieldnames=list(original[0]))
            writer.writeheader()
            writer.writerows(original)
        reloaded = read_dataset([copied])
        reloaded_manifests.append(manifest(reloaded, name))
        changes.append({"dataset": name, "before": original[0]["source_provenance"],
                        "after": reloaded[0]["source_provenance"]})
    try:
        assert_separated(*original_manifests, source_time=True)
    except ValueError as error:
        original_error = str(error)
    else:
        raise AssertionError("Expected originals to fail provenance validation")
    after = assert_separated(*reloaded_manifests, source_time=True)
    assert all(change["before"] == "filename_fallback" and change["after"] == "explicit"
               for change in changes)
    assert after["source_time_separated"]
    return {"confirmed": True, "changes": changes, "original_rejection": original_error,
            "roundtrip_separation_result": after}


def all_negative_release(base: Path) -> dict:
    # Domain permutations have exactly the same lexical feature vector. The
    # alternating labels intentionally make the synthetic problem unlearnable.
    hosts = ["".join(value) for value in itertools.permutations("bcdfghj")]
    def records(values, source, date):
        return [{"url": f"https://{host}.test/", "label": index % 2,
                 "source": source, "observed_at": date}
                for index, host in enumerate(values)]
    development = records(hosts[:120], "synthetic-training", "2025-01-01T00:00:00Z")
    future = records(hosts[120:920], "synthetic-independent", "2025-02-01T00:00:00Z")
    frozen = manifest(future, "frozen_future_test")
    metadata, _, model = train(development, fpr_budget=.01, reserved_test=frozen)
    model_path, metadata_path, report_path, export_path = [
        base / value for value in ["constant.joblib", "constant.json", "evaluation.json", "validated.js"]
    ]
    joblib.dump(model, model_path)
    metadata["model_file_sha256"] = hashlib.sha256(model_path.read_bytes()).hexdigest()
    metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
    # This flag is a human provenance assertion required by the exporter. It is
    # set only to exercise the remaining gate with a clearly synthetic corpus;
    # these records are not evidence of representative login review or accuracy.
    report = evaluate(model_path, metadata_path, future, [], frozen,
                      representative_login_reviewed=True)
    report_path.write_text(json.dumps(report), encoding="utf-8")
    with contextlib.redirect_stdout(io.StringIO()):
        export_model(metadata_path, model_path, export_path, evaluation_report_path=report_path)
    exported = json.loads(export_path.read_text(encoding="utf-8").split(" = ", 1)[1].rstrip(";\n"))
    assert report["metrics"]["recall"] == 0
    assert exported["deployment_eligible"] is True
    return {"confirmed": True, "synthetic_only": True,
            "representative_login_review_assertion_supplied_for_probe": True,
            "training_samples": len(development), "future_samples": len(future),
            "threshold": metadata["threshold"], "recall": report["metrics"]["recall"],
            "confusion_matrix": report["metrics"]["confusion_matrix"],
            "false_positive_rate_95ci": report["metrics"]["false_positive_rate_95ci"],
            "fpr_budget": .01, "deployment_eligible": exported["deployment_eligible"],
            "deployment_status": exported["deployment_status"]}


def completed_navigation_status_mock(base: Path) -> dict:
    # Model goto(start) returning 200; JavaScript then completes navigation to
    # final-404 before the collector's 250 ms wait/extraction has completed.
    start, final = "https://capture-start.test/", "https://capture-final.test/missing"
    features = build_feature_row(final, "404 Not Found", "<h1>404 Not Found</h1>")
    snapshot = {"features": {**features, "credential_contexts": []},
                "html": "<html><h1>404 Not Found</h1></html>",
                "title": "404 Not Found", "final_url": final}
    manager, browser, context, page = [MagicMock() for _ in range(4)]
    manager.__enter__.return_value.chromium.launch.return_value.__enter__.return_value = browser
    browser.new_context.return_value = context
    context.new_page.return_value = page
    page.url = final
    page.goto.return_value.status = 200
    page.goto.return_value.request.redirected_from = None
    playwright_package, playwright_api = ModuleType("playwright"), ModuleType("playwright.sync_api")
    playwright_api.sync_playwright = lambda: manager
    input_path, output_path = base / "capture.csv", base / "capture.jsonl"
    input_path.write_text("url,label,source\n" + start + ",0,synthetic-reviewed\n", encoding="utf-8")
    with patch.dict(sys.modules, {"playwright": playwright_package, "playwright.sync_api": playwright_api}), \
         patch("capture_dom_snapshots.is_public_host", return_value=True), \
         patch("capture_dom_snapshots.isolated_snapshot", return_value=snapshot):
        capture(input_path, output_path, None, 1000)
    loaded = load_snapshots(output_path)
    assert loaded[0]["status"] == 200 and loaded[0]["capture_quality"] == "ok"
    return {"confirmed_in_mock": True, "real_browser_test_performed": False,
            "mock_scenario": "Completed JavaScript redirect from original 200 to final 404 before extraction",
            "stored_final_url": loaded[0]["final_url"], "stored_title": loaded[0]["title"],
            "stored_status": loaded[0]["status"], "actual_final_document_status_in_scenario": 404,
            "stored_capture_quality": loaded[0]["capture_quality"],
            "accepted_by_snapshot_validator": True}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, help="Optional JSON evidence output")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(dir=ROOT / "docs/audit", prefix="ml-probe-temp-") as folder:
        base = Path(folder)
        results = {"provenance_roundtrip": provenance_roundtrip(base),
                   "all_negative_release": all_negative_release(base),
                   "completed_navigation_status_mock": completed_navigation_status_mock(base)}
    rendered = json.dumps(results, indent=2)
    if args.output:
        args.output.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)


if __name__ == "__main__":
    main()
