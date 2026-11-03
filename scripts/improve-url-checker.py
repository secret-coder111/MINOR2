"""Predeclared scheme and training-size experiments on prior internal partitions.

No network requests. All reused test results are exploratory, never release
evidence. The exported browser model is not changed by this command.
"""
from datetime import datetime, timezone
import argparse
from collections import Counter, defaultdict
import hashlib
import importlib.util
import json
import random
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'ml/src'))
import joblib
import numpy as np
from train_hybrid_model import BUNDLE_KIND, _urls, _vectorizer, _character_estimator, predict_bundle
from train_model import partition_records, probability_metrics, select_fpr_threshold, select_tuning_candidate, tuning_selection_contract
from feature_engineering import URL_FEATURE_SCHEMA
from dataset_contract import record_domains, manifest, assert_separated


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--expanded', action='store_true', help='Add disjoint fitting sites; preserve original evaluation partitions')
    args = parser.parse_args()
    version = 'url-checker-research-2026-11-03' + ('-expanded' if args.expanded else '')
    output = ROOT / f'ml/models/{version}.json'
    if output.exists() or output.with_suffix('.joblib').exists():
        raise FileExistsError('Preserve completed experiments; choose a new version.')
    spec = importlib.util.spec_from_file_location('inventory', ROOT / 'scripts/train-url-checker.py')
    inventory = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(inventory)
    collected = inventory.collect_records(return_pool=args.expanded)
    rows, audit = collected[:2]
    seed, budget = 20261102, .01
    parts = partition_records(rows, seed)
    if args.expanded:
        reserved = set().union(*(record_domains(row) for name in ['tuning', 'calibration', 'test'] for row in parts[name]))
        known = {row['url'] for row in rows}
        groups = defaultdict(list)
        for row in collected[2]:
            if row['url'] not in known and not (record_domains(row) & reserved):
                groups[(row['source'], row['label'])].append(row)
        rng = random.Random(seed)
        for group in groups.values():
            rng.shuffle(group)
        additions = []
        keys = sorted(groups)
        while keys and len(parts['fit']) + len(additions) < 240000:
            remaining = []
            for key in keys:
                if len(parts['fit']) + len(additions) == 240000:
                    break
                additions.append(groups[key].pop())
                if groups[key]:
                    remaining.append(key)
            keys = remaining
        parts['fit'].extend(additions)
        rows.extend(additions)
        audit['selected_rows'] = len(rows)
        audit['base_selected_rows'] = len(rows) - len(additions)
        audit['base_sample_limit'] = audit.pop('sample_limit')
        audit['expanded_fit_limit'] = 240000
        audit['selected_by_source_class'] = {f'{source}:{label}': count for (source, label), count
            in Counter((row['source'], row['label']) for row in rows).items()}
        audit['additional_fitting_rows'] = len(additions)
        audit['sampling'] += '; expanded fitting set round-robin by source/class after excluding every tuning/calibration/test site'
        print(json.dumps({'stage': 'expanded_fit', 'additional_rows': len(additions), 'total_fit': len(parts['fit'])}), flush=True)
        del groups, collected
    labels = {name: np.array([row['label'] for row in group]) for name, group in parts.items()}
    baseline_path = ROOT / 'ml/models/url-checker-research-2026-11-02.json'
    baseline = json.loads(baseline_path.read_text())
    baseline_bundle = joblib.load(baseline_path.with_suffix('.joblib'))
    baseline_probabilities = predict_bundle(baseline_bundle, parts['test'])[:, 1]
    baseline_metrics = probability_metrics(labels['test'], baseline_probabilities, baseline['threshold'])
    if baseline_metrics['confusion_matrix'] != baseline['test']['confusion_matrix']:
        raise ValueError('Paired baseline does not reproduce the original partitions')
    # Fix candidates and selection before examining any new test predictions.
    candidates = [('none', c) for c in (1., 2., 4.)] if args.expanded else [('none', 2.), *[('strip_scheme_v1', c) for c in (2., 4., 8., 16.)]]
    predictions, configurations = {}, {}
    for transform in sorted({kind for kind, _ in candidates}):
        vectorizer = _vectorizer()
        fit = vectorizer.fit_transform(_urls(parts['fit'], transform))
        tuning = vectorizer.transform(_urls(parts['tuning'], transform))
        for kind, c in candidates:
            if kind != transform:
                continue
            name = f'{kind}_c_{c:g}'
            print(json.dumps({'stage': 'fit_tuning_candidate', 'name': name}), flush=True)
            estimator = _character_estimator(c, seed).fit(fit, labels['fit'])
            predictions[name] = estimator.predict_proba(tuning)[:, 1]
            configurations[name] = {'text_transform': kind, 'character_c': c}
    winner, tuning_metrics = select_tuning_candidate(labels['tuning'], predictions, budget)
    config = configurations[winner]
    print(json.dumps({'stage': 'winner_fixed_before_test', 'winner': winner}), flush=True)
    final_rows = parts['fit'] + parts['tuning']
    vectorizer = _vectorizer()
    final_matrix = vectorizer.fit_transform(_urls(final_rows, config['text_transform']))
    estimator = _character_estimator(config['character_c'], seed).fit(
        final_matrix, np.concatenate([labels['fit'], labels['tuning']]))
    bundle = {'kind': BUNDLE_KIND, 'feature_schema': list(URL_FEATURE_SCHEMA), 'numeric_weight': 0.,
        'numeric_model': None, 'character_model': estimator, 'vectorizer': vectorizer,
        'text_transform': config['text_transform']}
    probabilities = predict_bundle(bundle, parts['calibration'])[:, 1]
    threshold, calibration = select_fpr_threshold(labels['calibration'], probabilities, budget)
    test_probabilities = predict_bundle(bundle, parts['test'])[:, 1]
    metrics = probability_metrics(labels['test'], test_probabilities, threshold)
    print(json.dumps({'stage': 'evaluation_complete_writing_reproducibility_report', 'test': metrics}), flush=True)
    # Controls are inspected only after selection. They cannot select a candidate.
    controls = ['https://github.com/login', 'https://www.google.com/', 'https://paypal.com/',
        'http://banamxr.com/1/mexico/', 'https://www.amtso.org/check-desktop-phishing-page/']
    control_scores = predict_bundle(bundle, [{'url': url} for url in controls])[:, 1]
    paired = {'baseline': baseline_metrics, 'candidate': metrics,
        'delta': {key: metrics[key] - baseline_metrics[key]
            for key in ['accuracy', 'precision', 'recall', 'f1', 'false_positive_rate']},
        'both_wrong': int(np.sum((test_probabilities >= threshold) != labels['test']) -
            np.sum(((test_probabilities >= threshold) != labels['test']) &
                ((baseline_probabilities >= baseline['threshold']) == labels['test']))),
        'previous_errors_fixed': int(np.sum(((test_probabilities >= threshold) == labels['test']) &
            ((baseline_probabilities >= baseline['threshold']) != labels['test']))),
        'new_errors': int(np.sum(((test_probabilities >= threshold) != labels['test']) &
            ((baseline_probabilities >= baseline['threshold']) == labels['test'])))}
    joblib.dump(bundle, output.with_suffix('.joblib'))
    audit_path = ROOT / ('ml/reports/url-checker-data-audit-2026-11-03' + ('-expanded' if args.expanded else '') + '.json')
    audit_path.write_text(json.dumps(audit, indent=2) + '\n', encoding='utf-8')
    # Retain reproducible partition/extractor identity without rerunning broad search.
    artifact = {key: baseline[key] for key in ['feature_schema', 'feature_schema_version',
        'extractor_version', 'extractor_sha256', 'feature_schema_sha256', 'label_scope',
        'manifests', 'development_manifest', 'release_requirements']}
    if args.expanded:
        artifact['manifests'] = {**artifact['manifests'], 'fit': manifest(parts['fit'], 'expanded_fit')}
        for name in ['tuning', 'calibration', 'test']:
            assert_separated(artifact['manifests']['fit'], artifact['manifests'][name])
        artifact['development_manifest'] = manifest(rows, 'expanded_internal_data')
    artifact.update({'model_version': version, 'algorithm': 'character_logistic_regression',
        'feature_scope': 'hybrid_url', 'seed': seed, 'winner': winner, 'configuration': config,
        'preprocessing': {**baseline['preprocessing'], 'text_transform': config['text_transform']},
        'candidate_search': {'predeclared_candidates': configurations, 'candidate_count': len(candidates)},
        'selection': tuning_selection_contract(budget), 'tuning': tuning_metrics,
        'threshold': threshold, 'calibration': calibration, 'test': metrics, 'paired_comparison': paired,
        'controls': [{'url': url, 'model_estimate': float(p), 'above_threshold': bool(p >= threshold)}
            for url, p in zip(controls, control_scores)],
        'data_audit': str(audit_path.relative_to(ROOT)).replace('\\', '/'),
        'training_input_sha256': {x['file']: x['sha256'] for x in audit['files']},
        'model_file_sha256': hashlib.sha256(output.with_suffix('.joblib').read_bytes()).hexdigest(),
        'deployment_eligible': False, 'deployment_status': 'research_only',
        'browser_inference_supported': False, 'internal_test_previously_inspected': True,
        'evaluation_scope': 'Paired exploratory ablation on previously used internal corpora and test partitions',
        'completed_at': datetime.now(timezone.utc).isoformat(),
        'limitations': ['Reused internal test is not an untouched release benchmark.',
            'No live-page ground truth or production accuracy guarantee.',
            'Character patterns can misclassify legitimate addresses; no primary phishing verdict.']})
    output.write_text(json.dumps(artifact, indent=2) + '\n', encoding='utf-8')
    summary = {key: artifact[key] for key in ['model_version', 'winner', 'candidate_search',
        'selection', 'threshold', 'test', 'paired_comparison', 'controls',
        'deployment_eligible', 'evaluation_scope', 'limitations']}
    (ROOT / f'docs/audit/{version}-comparison.json').write_text(json.dumps(summary, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'winner': winner, 'paired': paired, 'controls': artifact['controls']}), flush=True)


if __name__ == '__main__':
    main()
