"""Audit every local CSV, then run a bounded, reproducible URL-only experiment.

Never relabel generic bad/malware examples as phishing or popularity seeds as
reviewed legitimate pages. The sampled internal holdout is exploratory only.
"""
import csv
import hashlib
import json
import random
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'ml/src'))
from dataset_contract import canonicalize_urls, label_value, label_is_reviewed, source_identity
from train_hybrid_model import train
import joblib


def collect_records(sample_limit=120000, return_pool=False):
    unique, conflicts, profiles = {}, set(), []
    for file in sorted((ROOT / 'ml/data').glob('*.csv')):
        if file.name.startswith('url-checker-training-'):
            continue
        counts, labels, batch = Counter(), Counter(), []

        def flush():
            urls = canonicalize_urls([row['url'] for row in batch])
            for row, url in zip(batch, urls):
                if not url:
                    counts['invalid_url'] += 1
                    continue
                if url in conflicts:
                    counts['conflicting_url'] += 1
                    continue
                existing = unique.get(url)
                if existing and existing['label'] != row['label']:
                    unique.pop(url)
                    conflicts.add(url)
                    counts['conflicting_url'] += 1
                elif existing:
                    counts['duplicate_url'] += 1
                else:
                    row['url'] = url
                    unique[url] = row
                    counts['unique_added'] += 1
            batch.clear()

        with file.open(encoding='utf-8-sig', newline='') as handle:
            reader = csv.DictReader(handle)
            label_key = 'type' if 'type' in reader.fieldnames else 'label'
            for raw in reader:
                counts['rows'] += 1
                labels[str(raw.get(label_key, ''))] += 1
                label = label_value(raw.get(label_key))
                if label is None:
                    counts['excluded_non_phishing_scope_label'] += 1
                    continue
                if not label_is_reviewed(raw):
                    counts['excluded_unreviewed_label'] += 1
                    continue
                source, provenance = source_identity(raw, file.stem)
                batch.append({'url': raw.get('url') or '', 'label': label,
                    'source': source, 'source_provenance': provenance,
                    'label_scope': 'phishing', 'label_status': raw.get('label_status', ''),
                    'observed_at': raw.get('observed_at', ''), 'page_type': raw.get('page_type', ''),
                    'title': '', 'html': ''})
                if len(batch) == 10000:
                    flush()
            flush()
        profiles.append({'file': file.name, 'sha256': hashlib.sha256(file.read_bytes()).hexdigest(),
                         'counts': dict(counts), 'labels': dict(labels)})
        print(json.dumps(profiles[-1]), flush=True)
    strata = defaultdict(list)
    for row in unique.values():
        strata[(row['source'], row['label'])].append(row)
    rng = random.Random(20261102)
    for group in strata.values():
        rng.shuffle(group)
    selected = []
    # Round-robin source/class strata retain small sources and login controls.
    groups = list(sorted(strata))
    offsets = {key: 0 for key in groups}
    while groups and len(selected) < sample_limit:
        remaining = []
        for key in groups:
            if len(selected) == sample_limit:
                break
            index = offsets[key]
            selected.append(strata[key][index])
            offsets[key] += 1
            if offsets[key] < len(strata[key]):
                remaining.append(key)
        groups = remaining
    rng.shuffle(selected)
    audit = {'created_at': datetime.now(timezone.utc).isoformat(), 'seed': 20261102,
        'files': profiles, 'unique_eligible_urls': len(unique), 'quarantined_conflicting_urls': len(conflicts),
        'selected_rows': len(selected), 'sample_limit': sample_limit,
        'sampling': 'deterministic round-robin source/class strata, before domain-separated partitions',
        'selected_by_source_class': {f'{s}:{label}': n for (s, label), n in Counter((r['source'], r['label']) for r in selected).items()},
        'limitations': ['Feed/caller labels are not independently reviewed page captures.',
            'Internal domain-separated evaluation is exploratory, not source/time-separated production accuracy.',
            'Generic bad labels and unreviewed popularity seeds are excluded rather than relabelled.']}
    if return_pool:
        return selected, audit, list(unique.values())
    return selected, audit


def main():
    version = 'url-checker-research-2026-11-02'
    metadata = ROOT / f'ml/models/{version}.json'
    estimator = metadata.with_suffix('.joblib')
    if metadata.exists() or estimator.exists():
        raise FileExistsError('Preserve completed experiments; use a new model version.')
    selected, audit = collect_records()
    (ROOT / 'ml/reports/url-checker-data-audit-2026-11-02.json').write_text(json.dumps(audit, indent=2) + '\n')
    print(json.dumps({'selected_rows': len(selected), 'eligible': audit['unique_eligible_urls'], 'stage': 'training 23 candidates'}), flush=True)
    # Drop the large inventory before building TF-IDF matrices.
    artifact, bundle = train(selected, seed=20261102, model_version=version, fpr_budget=.01)
    joblib.dump(bundle, estimator)
    artifact['model_file_sha256'] = hashlib.sha256(estimator.read_bytes()).hexdigest()
    artifact['data_audit'] = 'ml/reports/url-checker-data-audit-2026-11-02.json'
    artifact['training_input_sha256'] = {x['file']: x['sha256'] for x in audit['files']}
    artifact['seed'] = 20261102
    artifact['internal_test_previously_inspected'] = True
    artifact['evaluation_scope'] = 'Exploratory partitions from previously used local corpora; not an untouched release test'
    metadata.write_text(json.dumps(artifact, indent=2) + '\n')
    print(json.dumps({'winner': artifact['winner'], 'test': artifact['test'],
        'family_comparison': artifact['family_comparison'], 'deployment_eligible': False}), flush=True)


if __name__ == '__main__':
    main()
