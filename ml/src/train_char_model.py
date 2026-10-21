"""Train a character n-gram URL model on the shared phishing datasets."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import joblib
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score, roc_auc_score
from sklearn.model_selection import GroupShuffleSplit

from train_model import (
    DATASET_URL,
    EDGEPHISH_DATASET_URL,
    download_dataset,
    read_dataset,
    registrable_domain,
)


def metrics(model, features, labels, threshold=None):
    probabilities = model.predict_proba(features)[:, 1]
    if threshold is None:
        threshold = max(
            [index / 100 for index in range(10, 91)],
            key=lambda value: f1_score(labels, probabilities >= value, zero_division=0),
        )
    predictions = probabilities >= threshold
    return {
        'accuracy': round(accuracy_score(labels, predictions), 4),
        'precision': round(precision_score(labels, predictions, zero_division=0), 4),
        'recall': round(recall_score(labels, predictions, zero_division=0), 4),
        'f1': round(f1_score(labels, predictions, zero_division=0), 4),
        'roc_auc': round(roc_auc_score(labels, probabilities), 4),
        'threshold': round(float(threshold), 4),
    }


def train(records: list[dict], seed: int = 42, model_version: str = 'char-url-tfidf-v0.1.0') -> tuple[dict, object, TfidfVectorizer]:
    if len({registrable_domain(record['url']) for record in records}) < 3:
        raise ValueError('Character-model evaluation needs at least three distinct registrable domains')

    def split_grouped(items: list[dict], split_seed: int) -> tuple[list[dict], list[dict]]:
        groups = np.asarray([registrable_domain(record['url']) for record in items])
        labels = np.asarray([record['label'] for record in items])
        splitter = GroupShuffleSplit(n_splits=100, test_size=0.2, random_state=split_seed)
        for fit_indices, holdout_indices in splitter.split(items, labels, groups):
            if len(set(labels[fit_indices])) < 2 or len(set(labels[holdout_indices])) < 2:
                continue
            return (
                [items[index] for index in fit_indices],
                [items[index] for index in holdout_indices],
            )
        raise ValueError('Could not create grouped character-model partitions containing both classes')

    fit_records, test_records = split_grouped(records, seed)
    train_records, validation_records = split_grouped(fit_records, seed + 1)
    urls_fit = [record['url'] for record in fit_records]
    urls_test = [record['url'] for record in test_records]
    urls_train = [record['url'] for record in train_records]
    urls_validation = [record['url'] for record in validation_records]
    y_fit = [record['label'] for record in fit_records]
    y_test = [record['label'] for record in test_records]
    y_train = [record['label'] for record in train_records]
    y_validation = [record['label'] for record in validation_records]

    vectorizer = TfidfVectorizer(
        analyzer='char',
        ngram_range=(3, 5),
        min_df=2,
        max_features=60000,
        sublinear_tf=True,
        dtype='float32',
    )
    x_train = vectorizer.fit_transform(urls_train)
    x_validation = vectorizer.transform(urls_validation)
    x_fit = vectorizer.transform(urls_fit)
    x_test = vectorizer.transform(urls_test)

    candidates = {}
    for c_value in [0.5, 1.0, 2.0, 4.0]:
        model = LogisticRegression(
            C=c_value,
            class_weight='balanced',
            max_iter=500,
            solver='liblinear',
            random_state=seed,
        )
        model.fit(x_train, y_train)
        validation_metrics = metrics(model, x_validation, y_validation)
        candidates[c_value] = (validation_metrics, model)

    best_c = max(candidates, key=lambda value: (candidates[value][0]['roc_auc'], candidates[value][0]['f1']))
    best_validation_metrics, _ = candidates[best_c]
    winner = LogisticRegression(
        C=best_c,
        class_weight='balanced',
        max_iter=500,
        solver='liblinear',
        random_state=seed,
    )
    winner.fit(x_fit, y_fit)
    test_metrics = metrics(winner, x_test, y_test, best_validation_metrics['threshold'])
    artifact = {
        'model_version': model_version,
        'algorithm': 'character_tfidf_logistic_regression',
        'ngram_range': [3, 5],
        'max_features': 60000,
        'best_c': best_c,
        'vocabulary_size': len(vectorizer.vocabulary_),
        'samples': len(records),
        'test_samples': len(y_test),
        'split_strategy': 'registrable_domain_grouped',
        'validation_models': {str(key): value[0] for key, value in candidates.items()},
        'test': test_metrics,
    }
    return artifact, winner, vectorizer


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--dataset', type=Path, default=Path('ml/data/malicious_urls.csv'))
    parser.add_argument('--include-edgephish', action='store_true')
    parser.add_argument('--additional-dataset', type=Path, action='append', default=[])
    parser.add_argument('--model-version', default='char-url-tfidf-v0.1.0')
    parser.add_argument('--limit', type=int, default=None)
    parser.add_argument('--balanced', action='store_true')
    parser.add_argument('--output', type=Path, default=Path('ml/models/char-url-tfidf-v0.1.0.json'))
    args = parser.parse_args()

    if not args.dataset.exists():
        download_dataset(args.dataset, DATASET_URL)
    paths = [args.dataset]
    if args.include_edgephish:
        edgephish_path = Path('ml/data/edgephish_balanced_urls.csv')
        if not edgephish_path.exists():
            download_dataset(edgephish_path, EDGEPHISH_DATASET_URL)
        paths.append(edgephish_path)
    paths.extend(args.additional_dataset)

    records = read_dataset(paths, args.limit, balanced=args.balanced)
    artifact, model, vectorizer = train(records, model_version=args.model_version)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(artifact, indent=2) + '\n', encoding='utf-8')
    joblib.dump({'model': model, 'vectorizer': vectorizer}, args.output.with_suffix('.joblib'))
    print(json.dumps(artifact, indent=2))
    print(f'Exported model to {args.output}')


if __name__ == '__main__':
    main()
