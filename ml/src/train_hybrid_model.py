"""Research-only numeric/character URL ensemble with disjoint calibration.

This is an offline experiment, not browser-ready inference. It never downloads
data, opens websites, enables a model, or treats missing DOM as observed data.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import re
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import ExtraTreesClassifier, RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression

from dataset_contract import assert_separated, manifest, sha256
from feature_engineering import (URL_FEATURE_SCHEMA, FEATURE_SCHEMA_VERSION,
                                 extractor_source_hash)
from train_model import (build_matrix, partition_records, probability_metrics,
                         read_dataset, select_fpr_threshold,
                         select_tuning_candidate, tuning_selection_contract,
                         NoFeasibleThresholdError)

BUNDLE_KIND = 'phishguard_hybrid_url_research_v1'
CHARACTER_C_VALUES = (.5, 1., 2.)
NUMERIC_WEIGHTS = (.25, .5, .75)


def _numeric_estimator(name: str, seed: int):
    common = dict(n_estimators=32, max_depth=16, min_samples_leaf=2,
                  n_jobs=-1, random_state=seed)
    if name == 'random_forest_32':
        return RandomForestClassifier(**common, class_weight='balanced_subsample')
    if name == 'extra_trees_32':
        return ExtraTreesClassifier(**common, class_weight='balanced')
    raise ValueError('Unsupported numeric estimator')


def _vectorizer():
    return TfidfVectorizer(analyzer='char', ngram_range=(3, 5), min_df=2,
                           max_features=60000, sublinear_tf=True)


def _character_estimator(c: float, seed: int):
    return LogisticRegression(C=c, class_weight='balanced', max_iter=500,
                              solver='liblinear', random_state=seed)


def _urls(records: list[dict], text_transform: str = 'none') -> list[str]:
    urls = [record.get('final_url') or record['url'] for record in records]
    if text_transform == 'strip_scheme_v1':
        return [re.sub(r'^https?://', '', url, flags=re.IGNORECASE) for url in urls]
    if text_transform != 'none':
        raise ValueError('Unsupported character input transform')
    return urls


def _positive_probabilities(values, samples: int) -> np.ndarray:
    values = np.asarray(values, dtype=float)
    if (values.shape != (samples, 2) or not np.isfinite(values).all()
            or np.any((values < 0) | (values > 1))
            or not np.allclose(values.sum(axis=1), 1)):
        raise ValueError('Binary component probabilities must be finite and sum to one')
    return values[:, 1]


def predict_bundle(bundle: dict, records: list[dict]) -> np.ndarray:
    """Predict locally from a trusted research bundle; accepts observed URLs.

    Deliberately distinct from sklearn's matrix API and from browser inference.
    Character tokenization/browser parity has not been established.
    """
    if not isinstance(bundle, dict) or bundle.get('kind') != BUNDLE_KIND:
        raise ValueError('Expected a PhishGuard hybrid URL research bundle')
    weight = bundle.get('numeric_weight')
    if isinstance(weight, bool) or not isinstance(weight, (int, float)) or not np.isfinite(weight) or not 0 <= weight <= 1:
        raise ValueError('Numeric ensemble weight must be finite and in [0, 1]')
    if bundle.get('feature_schema') != URL_FEATURE_SCHEMA:
        raise ValueError('Hybrid numeric features must use the current explicit URL subset')
    if not records:
        return np.empty((0, 2))
    positive = np.zeros(len(records))
    if weight:
        estimator = bundle.get('numeric_model')
        if estimator is None or list(estimator.classes_) != [0, 1]:
            raise ValueError('Numeric component must have binary classes [0, 1]')
        values = estimator.predict_proba(build_matrix(records, URL_FEATURE_SCHEMA))
        positive += weight * _positive_probabilities(values, len(records))
    if weight < 1:
        estimator, vectorizer = bundle.get('character_model'), bundle.get('vectorizer')
        if estimator is None or vectorizer is None or list(estimator.classes_) != [0, 1]:
            raise ValueError('Character component and fitted vectorizer are required')
        values = estimator.predict_proba(vectorizer.transform(_urls(records, bundle.get('text_transform', 'none'))))
        positive += (1 - weight) * _positive_probabilities(values, len(records))
    return np.column_stack([1 - positive, positive])


def train(records: list[dict], seed: int = 42,
          model_version: str = 'hybrid-url-research-v1', fpr_budget: float = .01,
          reserved_test: dict | None = None) -> tuple[dict, dict]:
    started = datetime.now(timezone.utc).isoformat()
    extractor_hash = extractor_source_hash()
    development_manifest = manifest(records, 'all_development_data')
    if reserved_test is not None:
        assert_separated(development_manifest, reserved_test, source_time=True)
    partitions = partition_records(records, seed)
    labels = {name: np.asarray([row['label'] for row in rows])
              for name, rows in partitions.items()}
    matrices = {name: build_matrix(rows, URL_FEATURE_SCHEMA)
                for name, rows in partitions.items()}
    tuning_probabilities, configurations = {}, {}
    numeric_tuning = {}
    for name in ['random_forest_32', 'extra_trees_32']:
        estimator = _numeric_estimator(name, seed)
        estimator.fit(matrices['fit'], labels['fit'])
        numeric_tuning[name] = estimator.predict_proba(matrices['tuning'])[:, 1]
        configurations[name] = {'family': 'numeric', 'numeric_algorithm': name,
                                 'character_c': None, 'numeric_weight': 1.}
        tuning_probabilities[name] = numeric_tuning[name]
    vectorizer = _vectorizer()
    character_fit = vectorizer.fit_transform(_urls(partitions['fit']))
    character_tuning = vectorizer.transform(_urls(partitions['tuning']))
    for c in CHARACTER_C_VALUES:
        estimator = _character_estimator(c, seed)
        estimator.fit(character_fit, labels['fit'])
        probabilities = estimator.predict_proba(character_tuning)[:, 1]
        name = f'character_c_{c:g}'
        configurations[name] = {'family': 'character', 'numeric_algorithm': None,
                                 'character_c': c, 'numeric_weight': 0.}
        tuning_probabilities[name] = probabilities
        for numeric_name, numeric_probabilities in numeric_tuning.items():
            for weight in NUMERIC_WEIGHTS:
                name = f'hybrid_{numeric_name}_c_{c:g}_numeric_{weight:g}'
                configurations[name] = {'family': 'hybrid', 'numeric_algorithm': numeric_name,
                                         'character_c': c, 'numeric_weight': weight}
                tuning_probabilities[name] = weight * numeric_probabilities + (1 - weight) * probabilities
    winner, tuning = select_tuning_candidate(labels['tuning'], tuning_probabilities, fpr_budget)
    family_winners, unavailable_families = {}, []
    for family in ['numeric', 'character', 'hybrid']:
        candidates = {name: values for name, values in tuning_probabilities.items()
                      if configurations[name]['family'] == family and tuning[name]['operating_point_feasible']}
        # All family winners are fixed before refitting/calibration/test scoring.
        if candidates:
            family_winners[family], _ = select_tuning_candidate(labels['tuning'], candidates, fpr_budget)
        else:
            unavailable_families.append(family)

    fitted_numeric, fitted_character = {}, {}
    final_rows = partitions['fit'] + partitions['tuning']
    final_labels = np.concatenate([labels['fit'], labels['tuning']])
    final_matrix = matrices['fit'] + matrices['tuning']
    final_vectorizer = _vectorizer()
    final_character = final_vectorizer.fit_transform(_urls(final_rows))
    bundles = {}
    comparisons = {family: {'status': 'no_feasible_tuning_candidate'} for family in unavailable_families}
    from release_contract import independent_group_metrics, release_requirements
    for family, name in family_winners.items():
        configuration = configurations[name]
        numeric_name, c = configuration['numeric_algorithm'], configuration['character_c']
        if numeric_name is not None and numeric_name not in fitted_numeric:
            fitted_numeric[numeric_name] = _numeric_estimator(numeric_name, seed)
            fitted_numeric[numeric_name].fit(final_matrix, final_labels)
        if c is not None and c not in fitted_character:
            fitted_character[c] = _character_estimator(c, seed)
            fitted_character[c].fit(final_character, final_labels)
        bundle = {'kind': BUNDLE_KIND, 'feature_schema': list(URL_FEATURE_SCHEMA),
            'numeric_weight': configuration['numeric_weight'],
            'numeric_model': fitted_numeric.get(numeric_name),
            'character_model': fitted_character.get(c),
            'vectorizer': final_vectorizer if c is not None else None}
        calibration_probabilities = predict_bundle(bundle, partitions['calibration'])[:, 1]
        try:
            threshold, calibration = select_fpr_threshold(labels['calibration'], calibration_probabilities, fpr_budget)
        except NoFeasibleThresholdError:
            if name == winner:
                raise
            comparisons[family] = {'candidate': name, 'configuration': configuration,
                                     'status': 'no_feasible_final_calibration_threshold'}
            continue
        test_probabilities = predict_bundle(bundle, partitions['test'])[:, 1]
        comparisons[family] = {'candidate': name, 'configuration': configuration,
            'threshold': threshold, 'calibration': calibration,
            'internal_test': probability_metrics(labels['test'], test_probabilities, threshold),
            'independent_group_metrics': independent_group_metrics(partitions['test'], test_probabilities >= threshold)}
        bundles[name] = bundle
    selected = comparisons[configurations[winner]['family']]
    if selected['candidate'] != winner:
        raise ValueError('Global winner and family winner disagree')
    if extractor_source_hash() != extractor_hash:
        raise ValueError('Extractor sources changed during training; rerun from stable sources')
    artifact = {
        'model_version': model_version, 'algorithm': 'numeric_character_probability_ensemble',
        'feature_scope': 'hybrid_url', 'feature_schema': list(URL_FEATURE_SCHEMA),
        'feature_schema_version': FEATURE_SCHEMA_VERSION, 'extractor_version': FEATURE_SCHEMA_VERSION,
        'extractor_sha256': extractor_hash,
        'feature_schema_sha256': sha256(json.dumps(URL_FEATURE_SCHEMA, separators=(',', ':'))),
        'label_scope': 'mixed_threat' if any(r.get('label_scope') == 'mixed_threat' for r in records) else 'phishing',
        'winner': winner, 'configuration': configurations[winner], 'seed': seed,
        'preprocessing': {'document_url': 'final_url when present, otherwise original url',
            'numeric_features': list(URL_FEATURE_SCHEMA),
            'character': {'analyzer': 'char', 'ngram_range': [3, 5], 'min_df': 2,
                'max_features': 60000, 'sublinear_tf': True, 'lowercase': True}},
        'candidate_search': {'numeric': ['random_forest_32', 'extra_trees_32'],
            'character_c': list(CHARACTER_C_VALUES), 'numeric_weights': list(NUMERIC_WEIGHTS),
            'candidate_count': len(configurations)},
        'selection': tuning_selection_contract(fpr_budget), 'tuning': tuning,
        'threshold': selected['threshold'],
        'calibration': {'method': 'independent_fpr_budget', 'fpr_budget': fpr_budget, **selected['calibration']},
        'test': selected['internal_test'], 'family_comparison': comparisons,
        'manifests': {name: manifest(rows, name) for name, rows in partitions.items()},
        'development_manifest': development_manifest, 'reserved_test_manifest': reserved_test,
        'release_requirements': release_requirements(),
        'training_started_at': started, 'training_completed_at': datetime.now(timezone.utc).isoformat(),
        'deployment_eligible': False, 'deployment_status': 'research_only',
        'browser_inference_supported': False,
        'limitations': ['No browser tokenization/numeric-character inference parity or hybrid exporter',
            'URL-only evidence; no observed DOM, visual or semantic page-content classifier',
            'Numeric risk scores and character patterns are correlated; blending is not independent corroboration',
            'Internal grouped comparisons are exploratory and do not establish source/time-separated accuracy',
            'A fresh reviewed benchmark and validated full-policy integration are required before deployment'],
    }
    return artifact, bundles[winner]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--dataset', type=Path, required=True)
    parser.add_argument('--additional-dataset', type=Path, action='append', default=[])
    parser.add_argument('--output', type=Path, default=Path('ml/models/hybrid-url-research-v1.json'))
    parser.add_argument('--model-version', default='hybrid-url-research-v1')
    parser.add_argument('--seed', type=int, default=42)
    parser.add_argument('--limit', type=int)
    parser.add_argument('--balanced', action='store_true')
    parser.add_argument('--fpr-budget', type=float, default=.01)
    parser.add_argument('--reserved-test-manifest', type=Path)
    args = parser.parse_args()
    if args.output.exists() or args.output.with_suffix('.joblib').exists():
        raise FileExistsError('Preserve prior experiment; choose new output paths')
    records = read_dataset([args.dataset, *args.additional_dataset], args.limit,
                           seed=args.seed, balanced=args.balanced)
    reserved = json.loads(args.reserved_test_manifest.read_text(encoding='utf-8')) if args.reserved_test_manifest else None
    artifact, bundle = train(records, seed=args.seed, model_version=args.model_version,
                              fpr_budget=args.fpr_budget, reserved_test=reserved)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(bundle, args.output.with_suffix('.joblib'))
    artifact['model_file_sha256'] = hashlib.sha256(args.output.with_suffix('.joblib').read_bytes()).hexdigest()
    artifact['training_input_sha256'] = {str(path): hashlib.sha256(path.read_bytes()).hexdigest()
                                        for path in [args.dataset, *args.additional_dataset]}
    args.output.write_text(json.dumps(artifact, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'winner': artifact['winner'], 'family_comparison': artifact['family_comparison'],
                      'deployment_eligible': False}, indent=2))


if __name__ == '__main__':
    main()
