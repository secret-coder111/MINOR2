"""Validate and split captured DOM snapshots without cross-domain leakage."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
from pathlib import Path
from urllib.parse import urlsplit

from train_model import LABELS, registrable_domain


def load_snapshots(path: Path) -> list[dict]:
    records = []
    seen: set[tuple[str, str]] = set()
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            record = json.loads(line)
            url = str(record.get("url") or "").strip()
            label_value = record.get("label")
            if isinstance(label_value, str):
                label_value = LABELS.get(label_value.strip().lower())
            if label_value not in (0, 1) or not url:
                raise ValueError(f"{path}:{line_number}: url and label 0/1 are required")
            parsed = urlsplit(url if "://" in url else f"https://{url}")
            if parsed.scheme not in {"http", "https"} or not parsed.hostname:
                raise ValueError(f"{path}:{line_number}: unsupported URL {url!r}")
            html = str(record.get("html") or "")
            if len(html.encode("utf-8")) > 2_000_000:
                raise ValueError(f"{path}:{line_number}: HTML exceeds 2 MiB safety limit")
            key = (url.lower(), str(label_value))
            if key in seen:
                continue
            seen.add(key)
            records.append({
                "url": url,
                "label": int(label_value),
                "title": str(record.get("title") or ""),
                "html": html,
                "source": str(record.get("source") or path.stem),
                "observed_at": str(record.get("observed_at") or ""),
                "final_url": str(record.get("final_url") or url),
                "redirect_count": int(record.get("redirect_count") or 0),
            })
    if not records:
        raise ValueError(f"{path}: no snapshots found")
    return records


def validate_records(records: list[dict]) -> dict:
    domains_by_label: dict[int, set[str]] = {0: set(), 1: set()}
    for record in records:
        domains_by_label[record["label"]].add(registrable_domain(record["url"]))
    overlap = sorted(domains_by_label[0] & domains_by_label[1])
    return {
        "samples": len(records),
        "legitimate": sum(record["label"] == 0 for record in records),
        "phishing": sum(record["label"] == 1 for record in records),
        "distinct_domains": len(domains_by_label[0] | domains_by_label[1]),
        "cross_class_domain_overlap": overlap,
        "html_coverage": round(
            sum(bool(record["html"]) for record in records) / len(records), 4
        ),
    }


def write_split(records: list[dict], output: Path, name: str) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding="utf-8", newline="") as handle:
        for record in records:
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")
    digest = hashlib.sha256(output.read_bytes()).hexdigest()
    print(json.dumps({"split": name, "path": str(output), "sha256": digest}))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("snapshot_file", type=Path)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    records = load_snapshots(args.snapshot_file)
    report = validate_records(records)
    if report["cross_class_domain_overlap"]:
        raise ValueError(
            "Cross-class registrable-domain overlap detected: "
            + ", ".join(report["cross_class_domain_overlap"][:10])
        )
    if report["html_coverage"] < 1:
        raise ValueError("Every DOM training snapshot must include captured HTML")
    if not report["legitimate"] or not report["phishing"]:
        raise ValueError("DOM dataset must contain both legitimate and phishing samples")
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
