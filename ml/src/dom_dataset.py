"""Validate captured pages and optionally release connected, grouped JSONL splits."""
from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime
from pathlib import Path

from dataset_contract import connected_groups, label_value, manifest, normalize_url, record_domains, canonicalize_urls, label_is_reviewed, source_identity
from feature_engineering import (FEATURE_SCHEMA, FEATURE_SCHEMA_VERSION, POLICY_VERSION,
    validate_feature_row, filter_policy_features, extractor_source_hash, policy_source_hash)


def load_snapshots(path: Path, include_other_threats: bool = False) -> list[dict]:
    records: dict[str, dict] = {}
    with path.open('r', encoding='utf-8') as handle:
        lines = []
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as error:
                raise ValueError(f'{path}:{line_number}: invalid JSON snapshot') from error
            if not isinstance(record, dict):
                raise ValueError(f'{path}:{line_number}: snapshot must be an object')
            lines.append((line_number, record))
        normalized = canonicalize_urls([value for _,record in lines for value in [record.get('url') or '',record.get('final_url') or '']])
        for index, (line_number, record) in enumerate(lines):
            prefix = f'{path}:{line_number}'
            url, final_url = normalized[index*2:index*2+2]
            label = label_value(record.get('label'), include_other_threats)
            if not url or not final_url or label is None:
                raise ValueError(f'{prefix}: valid original/final HTTP(S) URLs and a phishing-scope label are required')
            if not label_is_reviewed(record):
                raise ValueError(f'{prefix}: unreviewed sampling seeds cannot be treated as labeled snapshots')
            html = record.get('html')
            status = record.get('status')
            if not isinstance(html, str) or not html.strip():
                raise ValueError(f'{prefix}: captured HTML must be nonempty')
            if len(html.encode('utf-8')) > 2_000_000:
                raise ValueError(f'{prefix}: HTML exceeds 2 MiB')
            if record.get('error') or record.get('capture_success') is not True or not isinstance(status, int) or not 200 <= status < 300:
                raise ValueError(f'{prefix}: failed/non-success HTTP capture cannot be a DOM training sample')
            navigation = record.get('navigation_response')
            if navigation is not None:
                if (not isinstance(navigation, dict) or navigation.get('status') != status
                    or not all(isinstance(navigation.get(name), str) and navigation[name]
                               for name in ['frame_id', 'loader_id', 'url'])
                    or not normalize_url(navigation['url'])
                    or record.get('capture_document_status') != 'bound_to_loader'):
                    raise ValueError(f'{prefix}: HTTP status must be bound to the captured document loader')
            elif record.get('capture_document_status') == 'bound_to_loader':
                raise ValueError(f'{prefix}: document binding needs navigation response evidence')
            observed_at = str(record.get('observed_at') or '')
            try:
                observed_time = datetime.fromisoformat(observed_at.replace('Z', '+00:00'))
                if observed_time.tzinfo is None:
                    raise ValueError('timezone required')
            except ValueError as error:
                raise ValueError(f'{prefix}: timezone-aware ISO observed_at is required') from error
            if record.get('capture_quality') != 'ok' or record.get('capture_partial'):
                raise ValueError(f'{prefix}: review error/challenge page and set capture_quality=ok only for actual labeled content')
            if url in records and records[url]['label'] != label:
                raise ValueError(f'{prefix}: conflicting labels for the same normalized URL; resolve/quarantine before training')
            feature_row = record.get('feature_row')
            if feature_row is not None:
                validate_feature_row(feature_row)
                if record.get('feature_schema_version') != FEATURE_SCHEMA_VERSION:
                    raise ValueError(f'{prefix}: captured features need extractor {FEATURE_SCHEMA_VERSION}')
                if record.get('extractor_sha256') != extractor_source_hash():
                    raise ValueError(f'{prefix}: captured extractor hash is stale; recapture with the current extractor')
            if record.get('policy_features') is not None:
                if filter_policy_features(record['policy_features']) != record['policy_features']:
                    raise ValueError(f'{prefix}: policy_features contain non-whitelisted data')
                if feature_row is None or any(record['policy_features'].get(name) != feature_row[name] for name in FEATURE_SCHEMA):
                    raise ValueError(f'{prefix}: policy features must agree with the captured numeric feature row')
                if record.get('policy_version') != POLICY_VERSION or record.get('policy_sha256') != policy_source_hash():
                    raise ValueError(f'{prefix}: captured policy identity is stale; recapture with the current policy')
            redirect_count = record.get('redirect_count', 0)
            if isinstance(redirect_count, bool) or not isinstance(redirect_count, int) or redirect_count < 0:
                raise ValueError(f'{prefix}: redirect_count must be a nonnegative integer')
            source, provenance = source_identity(record, path.stem)
            normalized_record = {**record, 'url': url, 'final_url': final_url, 'label': label,
                'source': source, 'observed_at': observed_at,
                'source_provenance': provenance,
                'capture_document_status': record.get('capture_document_status') or 'legacy_unbound',
                'redirect_count': redirect_count,
                'label_scope': 'mixed_threat' if include_other_threats else 'phishing'}
            if url in records and records[url] != normalized_record:
                raise ValueError(f'{prefix}: multiple different captures for one normalized URL; review and choose a single observation')
            records.setdefault(url, normalized_record)
    if not records:
        raise ValueError(f'{path}: no snapshots found')
    return list(records.values())


def validate_records(records: list[dict]) -> dict:
    domains = {label: set().union(*(record_domains(r) for r in records if r['label'] == label)) for label in [0,1]}
    return {
        'samples': len(records), 'legitimate': sum(r['label'] == 0 for r in records),
        'phishing': sum(r['label'] == 1 for r in records),
        'distinct_domains': len(domains[0] | domains[1]),
        # Mixed-label sites can be valid (a compromised site); grouping keeps them together.
        'cross_class_domain_overlap': sorted(domains[0] & domains[1]),
        'connected_site_content_groups': len(set(connected_groups(records))),
        'html_coverage': sum(bool(r.get('html','').strip()) for r in records)/len(records),
        'captured_feature_coverage': sum(r.get('feature_row') is not None for r in records)/len(records),
        'manifest': manifest(records, 'validated_dom_snapshots'),
    }


def write_split(records: list[dict], output: Path, name: str) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(''.join(json.dumps(r, ensure_ascii=False)+'\n' for r in records), encoding='utf-8')
    report = {**manifest(records, name), 'file_sha256': hashlib.sha256(output.read_bytes()).hexdigest()}
    output.with_suffix('.manifest.json').write_text(json.dumps(report, indent=2)+'\n', encoding='utf-8')


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('snapshot_file', type=Path)
    parser.add_argument('--report', type=Path)
    parser.add_argument('--split-dir', type=Path, help='Write fit/tuning/calibration/test JSONL and immutable identity manifests')
    parser.add_argument('--seed', type=int, default=42)
    parser.add_argument('--include-other-threats', action='store_true')
    args = parser.parse_args()
    records = load_snapshots(args.snapshot_file, args.include_other_threats)
    report = validate_records(records)
    if not report['legitimate'] or not report['phishing']:
        raise ValueError('DOM dataset needs both classes')
    if args.split_dir:
        from train_model import partition_records
        if args.split_dir.exists() and any(args.split_dir.iterdir()):
            raise ValueError('Split release directory must be empty to preserve frozen holdouts')
        for name, rows in partition_records(records, args.seed).items():
            write_split(rows, args.split_dir / (name+'.jsonl'), name)
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2)+'\n', encoding='utf-8')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
