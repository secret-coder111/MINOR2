"""Predeclared, offline login-hard-negative/URL-representation experiment.

Known official-login seed sites are development data, including any records
previously assigned to internal evaluation partitions. No new labels, network
requests, page visits, or deployed model activation are performed. A reused
internal test is scored only after selecting the candidate and threshold.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import random
import sys
import time
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'ml/src'))
import joblib
import numpy as np
import sklearn
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression

from dataset_contract import assert_separated, manifest, record_domains
from feature_engineering import URL_FEATURE_SCHEMA, FEATURE_SCHEMA_VERSION, extractor_source_hash
from release_contract import independent_group_metrics, release_requirements
from train_hybrid_model import BUNDLE_KIND, predict_bundle
from train_model import partition_records, probability_metrics, select_fpr_threshold, wilson_interval

VERSION = 'url-checker-research-2026-11-06-login-boundaries'
SEED = 20261102
SOURCE = 'curated-official-login'


def character_text(records, transform='none'):
    urls = [row.get('final_url') or row['url'] for row in records]
    if transform == 'none':
        return urls
    if transform != 'host_path_boundaries_v1':
        raise ValueError('Unsupported representation')
    # Generic URL component markers, without brand lists or domain exemptions.
    # Canonicalization has already converted hostnames/Unicode identically to
    # the browser. Keep explicit scheme as a separate channel for comparison.
    result = []
    for url in urls:
        parts = urlsplit(url)
        result.append(f'host={parts.netloc}|path={parts.path}|query={parts.query}'
                      f'|fragment={parts.fragment}|scheme={parts.scheme}')
    return result


def predict_research(bundle, records):
    values = bundle['vectorizer'].transform(character_text(records, bundle['text_transform']))
    return bundle['character_model'].predict_proba(values)[:, 1]


def upper_bound_empirical_budget(negative_count, upper_target):
    """Largest empirical FPR whose negative-count Wilson bound meets target."""
    counts = [count for count in range(negative_count + 1)
              if wilson_interval(count, negative_count)[1] <= upper_target]
    if not counts:
        raise ValueError('Not enough independent negative observations for the declared bound')
    # nextafter avoids floating subtraction at the discrete boundary in the
    # shared threshold selector; it cannot admit an extra false positive.
    return float(np.nextafter(max(counts) / negative_count, 1.0))


def select_threshold(labels, probabilities, upper_target=.01):
    empirical = upper_bound_empirical_budget(int(np.sum(labels == 0)), upper_target)
    threshold, metrics = select_fpr_threshold(labels, probabilities, empirical)
    if metrics['false_positive_rate_95ci'][1] > upper_target:
        raise AssertionError('Selected threshold exceeds declared descriptive Wilson bound')
    return threshold, {**metrics, 'maximum_fpr_upper_95ci': upper_target,
                       'effective_empirical_fpr_budget': empirical,
                       'interval_scope': 'Descriptive URL-level; not selection-adjusted or a release guarantee'}


def emit(value):
    print(json.dumps(value, ensure_ascii=True), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--version', default=VERSION)
    args = parser.parse_args()
    started = datetime.now(timezone.utc).isoformat()
    metadata = ROOT / f'ml/models/{args.version}.json'
    report = ROOT / f'docs/audit/{args.version}-comparison.json'
    declaration = ROOT / f'ml/reports/{args.version}-predeclared.json'
    if any(path.exists() for path in [metadata, metadata.with_suffix('.joblib'), report, declaration]):
        raise FileExistsError('Preserve completed experiments; use a fresh version')
    candidates = {
        f'{representation}_c_{c:g}_login_{weight:g}':
            {'text_transform': representation, 'character_c': c, 'login_sample_weight': weight}
        for representation in ['none', 'host_path_boundaries_v1']
        for c in [1., 4.] for weight in [1., 50.]
    }
    predeclared = {
        'model_version': args.version, 'started_at': started, 'seed': SEED,
        'candidates': candidates, 'fit_limit': 240000,
        'selection': 'highest tuning recall at URL-level FPR Wilson-upper <=1%; tie lower FPR, AP, AUC',
        'final_threshold': 'fresh independent calibration at URL-level FPR Wilson-upper <=1%',
        'known_login_sites': 'All curated-official-login sites reserved for fitting, excluded from evaluation',
        'test_use': 'Previously inspected internal test, candidate and threshold fixed before scoring',
        'promotion': 'Research diagnostic only; no production eligibility claim or model activation',
    }
    declaration.write_text(json.dumps(predeclared, indent=2) + '\n', encoding='utf-8')
    emit({'stage': 'predeclared', 'candidates': len(candidates), 'file': str(declaration)})
    initial_hash = extractor_source_hash()
    canonicalizer_hash = hashlib.sha256((ROOT / 'ml/src/canonicalize_urls.cjs').read_bytes()).hexdigest()
    spec = importlib.util.spec_from_file_location('inventory', ROOT / 'scripts/train-url-checker.py')
    inventory = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(inventory)
    base, audit, pool = inventory.collect_records(return_pool=True)
    parts = partition_records(base, SEED)
    reserved = set().union(*(record_domains(row) for name in ['tuning', 'calibration', 'test'] for row in parts[name]))
    known = {row['url'] for row in base}
    strata = defaultdict(list)
    for row in pool:
        if row['url'] not in known and not (record_domains(row) & reserved):
            strata[(row['source'], row['label'])].append(row)
    rng = random.Random(SEED)
    for rows in strata.values():
        rng.shuffle(rows)
    additions = []
    keys = sorted(strata)
    while keys and len(parts['fit']) + len(additions) < 240000:
        remaining = []
        for key in keys:
            if len(parts['fit']) + len(additions) == 240000:
                break
            additions.append(strata[key].pop())
            if strata[key]:
                remaining.append(key)
        keys = remaining
    parts['fit'].extend(additions)
    base.extend(additions)
    seed_rows = [row for row in pool if row['source'] == SOURCE]
    if len(seed_rows) != 32 or any(row['label'] != 0 for row in seed_rows):
        raise ValueError('Expected the existing 32 labelled login seeds; review changes before another experiment')
    development_sites = set().union(*(record_domains(row) for row in seed_rows))
    moved = {}
    for name in ['tuning', 'calibration', 'test']:
        to_fit = [row for row in parts[name] if record_domains(row) & development_sites]
        parts[name] = [row for row in parts[name] if not (record_domains(row) & development_sites)]
        parts['fit'].extend(to_fit)
        moved[name] = {'records': len(to_fit), 'class_counts': dict(Counter(str(row['label']) for row in to_fit))}
    fit_urls = {row['url'] for row in parts['fit']}
    for row in seed_rows:
        if row['url'] not in fit_urls:
            parts['fit'].append(row)
            base.append(row)
            fit_urls.add(row['url'])
    labels = {name: np.asarray([row['label'] for row in rows]) for name, rows in parts.items()}
    identities = {name: manifest(rows, name) for name, rows in parts.items()}
    for index, left in enumerate(parts):
        for right in list(parts)[index + 1:]:
            assert_separated(identities[left], identities[right])
    partition_summary = {name: {'samples': len(rows), 'classes': dict(Counter(str(row['label']) for row in rows)),
                               'sources': dict(Counter(row['source'] for row in rows))}
                         for name, rows in parts.items()}
    emit({'stage': 'partitions_reserved', 'partitions': partition_summary, 'moved_to_fitting': moved})
    audit.update({'selected_rows': sum(len(rows) for rows in parts.values()),
                  'additional_fitting_rows': len(additions), 'partitions': partition_summary,
                  'known_login_seed_count': len(seed_rows), 'known_login_sites': len(development_sites),
                  'moved_known_sites_to_fit': moved,
                  'sampling': audit['sampling'] + '; disjoint expansion; known official-login sites reserved for development'})
    audit_path = ROOT / f'ml/reports/{args.version}-data-audit.json'
    audit_path.write_text(json.dumps(audit, indent=2) + '\n', encoding='utf-8')
    del pool, strata
    tuning, fitted_vectorizers = {}, {}
    for transform in ['none', 'host_path_boundaries_v1']:
        vectorizer = TfidfVectorizer(analyzer='char', ngram_range=(3, 5), min_df=2,
                                     max_features=60000, sublinear_tf=True)
        emit({'stage': 'vectorize', 'transform': transform})
        xfit = vectorizer.fit_transform(character_text(parts['fit'], transform))
        xtuning = vectorizer.transform(character_text(parts['tuning'], transform))
        fitted_vectorizers[transform] = vectorizer
        for name, config in candidates.items():
            if config['text_transform'] != transform:
                continue
            tic = time.monotonic()
            weights = np.asarray([config['login_sample_weight'] if row['source'] == SOURCE else 1.
                                  for row in parts['fit']])
            estimator = LogisticRegression(C=config['character_c'], class_weight='balanced',
                max_iter=500, solver='liblinear', random_state=SEED)
            estimator.fit(xfit, labels['fit'], sample_weight=weights)
            probabilities = estimator.predict_proba(xtuning)[:, 1]
            _, tuning[name] = select_threshold(labels['tuning'], probabilities)
            emit({'stage': 'tuning_candidate', 'name': name, 'seconds': round(time.monotonic()-tic, 2),
                  'recall': tuning[name]['recall'], 'fpr': tuning[name]['false_positive_rate'],
                  'fpr_upper': tuning[name]['false_positive_rate_95ci'][1]})
        del xfit, xtuning
    winner = max(tuning, key=lambda name: (tuning[name]['recall'], -tuning[name]['false_positive_rate'],
                                            tuning[name]['average_precision'], tuning[name]['roc_auc']))
    config = candidates[winner]
    emit({'stage': 'winner_fixed_before_calibration_or_test', 'winner': winner})
    final_rows = parts['fit'] + parts['tuning']
    final_labels = np.concatenate([labels['fit'], labels['tuning']])
    vectorizer = TfidfVectorizer(analyzer='char', ngram_range=(3, 5), min_df=2,
                                 max_features=60000, sublinear_tf=True)
    matrix = vectorizer.fit_transform(character_text(final_rows, config['text_transform']))
    estimator = LogisticRegression(C=config['character_c'], class_weight='balanced',
        max_iter=500, solver='liblinear', random_state=SEED)
    weights = np.asarray([config['login_sample_weight'] if row['source'] == SOURCE else 1. for row in final_rows])
    estimator.fit(matrix, final_labels, sample_weight=weights)
    del matrix
    bundle = {'kind': BUNDLE_KIND, 'feature_schema': list(URL_FEATURE_SCHEMA), 'numeric_weight': 0.,
              'numeric_model': None, 'character_model': estimator, 'vectorizer': vectorizer,
              'text_transform': config['text_transform']}
    calibration_probabilities = predict_research(bundle, parts['calibration'])
    threshold, calibration = select_threshold(labels['calibration'], calibration_probabilities)
    emit({'stage': 'threshold_fixed_before_test', 'threshold': threshold, 'calibration': calibration})
    probabilities = predict_research(bundle, parts['test'])
    metrics = probability_metrics(labels['test'], probabilities, threshold)
    group_metrics = independent_group_metrics(parts['test'], probabilities >= threshold)
    baseline_path = ROOT / 'ml/models/url-checker-research-2026-11-03-expanded.json'
    baseline = json.loads(baseline_path.read_text(encoding='utf-8'))
    baseline_bundle = joblib.load(baseline_path.with_suffix('.joblib'))
    baseline_values = predict_bundle(baseline_bundle, parts['test'])[:, 1]
    baseline_metrics = probability_metrics(labels['test'], baseline_values, baseline['threshold'])
    # Include recalibrated baseline as an honest common-operating-point control.
    baseline_calibration = predict_bundle(baseline_bundle, parts['calibration'])[:, 1]
    baseline_threshold, baseline_calibrated = select_threshold(labels['calibration'], baseline_calibration)
    baseline_same_budget = probability_metrics(labels['test'], baseline_values, baseline_threshold)
    controls = [{'url': row['url'], 'label': row['label'], 'scope': 'known development login seed'} for row in seed_rows]
    controls.extend({'url': url, 'scope': 'previously inspected diagnostic control; no live-page label claim'} for url in
                    ['https://paypal.com/', 'https://www.google.com/',
                     'https://www.amtso.org/check-desktop-phishing-page/', 'http://banamxr.com/1/mexico/'])
    control_values = predict_research(bundle, controls)
    baseline_controls = predict_bundle(baseline_bundle, controls)[:, 1]
    for row, value, old in zip(controls, control_values, baseline_controls):
        row.update({'model_estimate': float(value), 'above_threshold': bool(value >= threshold),
                    'baseline_model_estimate': float(old), 'baseline_above_threshold': bool(old >= baseline['threshold'])})
    manifest_path = ROOT / f'ml/models/{args.version}-partitions.json'
    manifest_path.write_text(json.dumps(identities, separators=(',', ':')) + '\n', encoding='utf-8')
    joblib.dump(bundle, metadata.with_suffix('.joblib'))
    # Source hash drift matters even for character-only inference: record rather
    # than silently relabel the experiment as having used a later extractor.
    extractor_source_hash.cache_clear()
    current_hash = extractor_source_hash()
    artifact = {'model_version': args.version, 'algorithm': 'character_logistic_regression',
        'feature_scope': 'hybrid_url', 'feature_schema': list(URL_FEATURE_SCHEMA),
        'feature_schema_version': FEATURE_SCHEMA_VERSION, 'extractor_version': FEATURE_SCHEMA_VERSION,
        'extractor_sha256': initial_hash, 'extractor_hash_at_completion': current_hash,
        'extractor_changed_during_training': initial_hash != current_hash,
        'predictor_input_contract': {'kind': 'canonical_url_characters_only',
            'canonicalizer_sha256': canonicalizer_hash,
            'numeric_or_dom_features_consumed': False},
        'seed': SEED, 'python': sys.version, 'scikit_learn': sklearn.__version__,
        'candidate_search': predeclared, 'winner': winner, 'configuration': config,
        'preprocessing': {'character': {'analyzer': 'char', 'ngram_range': [3, 5], 'min_df': 2,
                         'max_features': 60000, 'sublinear_tf': True, 'lowercase': True},
                         'text_transform': config['text_transform']},
        'selection': predeclared['selection'], 'tuning': tuning, 'threshold': threshold,
        'calibration': calibration, 'test': metrics, 'independent_group_metrics': group_metrics,
        'baseline_original_threshold': baseline_metrics, 'baseline_same_calibration_budget': baseline_same_budget,
        'baseline_recalibration': baseline_calibrated, 'baseline_model_version': baseline['model_version'],
        'controls': controls, 'partition_summary': partition_summary,
        'known_login_sites_reserved_for_development': sorted(development_sites),
        'moved_known_sites_to_fit': moved, 'partition_manifest': str(manifest_path.relative_to(ROOT)).replace('\\', '/'),
        'partition_manifest_sha256': hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
        'data_audit': str(audit_path.relative_to(ROOT)).replace('\\', '/'),
        'training_input_sha256': {row['file']: row['sha256'] for row in audit['files']},
        'model_file_sha256': hashlib.sha256(metadata.with_suffix('.joblib').read_bytes()).hexdigest(),
        'release_requirements': release_requirements(), 'label_scope': 'phishing',
        'deployment_eligible': False, 'deployment_status': 'research_only',
        'browser_inference_supported': False, 'internal_test_previously_inspected': True,
        'started_at': started, 'completed_at': datetime.now(timezone.utc).isoformat(),
        'evaluation_scope': 'Exploratory reused internal test after excluding known login development sites',
        'limitations': ['Known official-login scores are development controls, not independent generalization evidence',
                       'Feed/caller URL labels are not reviewed captured-document ground truth',
                       'No new source/time-separated or campaign-reviewed benchmark',
                       'Calibration selects a threshold, not calibrated theft probabilities',
                       'All results are URL-only; extension page verdicts remain rules-based'],
    }
    metadata.write_text(json.dumps(artifact, indent=2) + '\n', encoding='utf-8')
    summary = {key: value for key, value in artifact.items() if key not in ['python', 'training_input_sha256']}
    report.write_text(json.dumps(summary, indent=2) + '\n', encoding='utf-8')
    emit({'stage': 'complete', 'winner': winner, 'test': metrics, 'baseline_same_budget': baseline_same_budget,
          'control_false_warnings': sum(row['above_threshold'] for row in controls if row.get('label') == 0),
          'extractor_changed_during_training': initial_hash != current_hash, 'report': str(report)})


if __name__ == '__main__':
    main()
