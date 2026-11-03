"""Check reviewed benchmark composition without fitting or scoring a detector.

This report identifies missing review records/coverage. It does not create
labels or certify that a sample is representative of real browsing traffic.
"""
from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path

from dataset_contract import manifest
from dom_dataset import load_snapshots
from release_contract import benchmark_review, independent_group_metrics, release_requirements
from train_model import read_dataset


def review(records: list[dict], require_dom: bool = False) -> dict:
    requirements = release_requirements()
    composition = benchmark_review(records, require_document_binding=require_dom)
    groups = independent_group_metrics(records, [False] * len(records))
    errors = list(composition['errors'])
    if groups['phishing_groups'] < requirements['minimum_independent_phishing_groups']:
        errors.append('Too few independent phishing groups')
    if groups['legitimate_groups'] < requirements['minimum_independent_legitimate_groups']:
        errors.append('Too few independent legitimate groups')
    if require_dom and any(r.get('feature_row') is None or r.get('policy_features') is None
                           or r.get('capture_execution_world') != 'isolated' for r in records):
        errors.append('Current-policy benchmarks need isolated captured numeric and per-submission policy features')
    return {'passed': composition['passed'] and not errors, 'samples': len(records),
            'requirements': requirements, 'benchmark_review': composition,
            'independent_groups': {name: groups[name] for name in ['legitimate_groups', 'phishing_groups']},
            'by_label': dict(Counter(str(r['label']) for r in records)),
            'by_page_type': dict(Counter(str(r.get('page_type') or 'missing') for r in records)),
            'errors': errors,
            'meaning': 'Composition/review evidence only; freeze before model or policy selection and evaluate once'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('datasets', type=Path, nargs='+')
    parser.add_argument('--require-dom', action='store_true', help='Require current isolated document-bound policy captures')
    parser.add_argument('--output', type=Path)
    parser.add_argument('--freeze-manifest', type=Path, help='Only freeze if review/coverage passes; never overwrite')
    args = parser.parse_args()
    for output in [args.output, args.freeze_manifest]:
        if output and output.exists():
            raise ValueError('Use new output paths to preserve benchmark evidence')
    records = []
    for path in args.datasets:
        records.extend(load_snapshots(path) if path.suffix.lower() == '.jsonl' else read_dataset([path]))
    urls = [r['url'] for r in records]
    if len(set(urls)) != len(urls):
        raise ValueError('Duplicate URLs across benchmark files must be resolved before review/freeze')
    report = review(records, args.require_dom)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2)+'\n', encoding='utf-8')
    print(json.dumps(report, indent=2))
    if args.freeze_manifest:
        if not report['passed']:
            raise ValueError('Benchmark review/coverage failed; do not freeze incomplete evidence for release')
        args.freeze_manifest.parent.mkdir(parents=True, exist_ok=True)
        args.freeze_manifest.write_text(json.dumps(manifest(records, 'frozen_future_test'), indent=2)+'\n', encoding='utf-8')


if __name__ == '__main__':
    main()
