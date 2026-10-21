"""Compatibility entry point for the future-test protocol."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from future_test_protocol import evaluate, load_records


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", type=Path, required=True)
    parser.add_argument("--metadata", type=Path, required=True)
    parser.add_argument("--dataset", type=Path, action="append", required=True)
    parser.add_argument("--limit", type=int, default=100000)
    args = parser.parse_args()

    phishing = [path for path in args.dataset if "phish" in path.name.lower()]
    legitimate = [path for path in args.dataset if path not in phishing]
    if not phishing or not legitimate:
        raise ValueError(
            "Dataset names must identify phishing and legitimate inputs; "
            "use future_test_protocol.py for explicit grouping."
        )
    records, _ = load_records(phishing, legitimate, args.limit, seed=42)
    print(json.dumps(evaluate(args.model, args.metadata, records, args.dataset), indent=2))


if __name__ == "__main__":
    main()
