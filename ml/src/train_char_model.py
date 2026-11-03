"""Character URL research model; never automatically enables browser decisions."""
from __future__ import annotations
import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression

from dataset_contract import assert_separated, manifest
from train_model import (read_dataset, partition_records, score_model, select_fpr_threshold,
                         select_tuning_candidate, tuning_selection_contract)


def train(records: list[dict], seed: int = 42, model_version: str = 'char-url-research-v1',
          fpr_budget: float = .01, reserved_test: dict | None = None):
    started = datetime.now(timezone.utc).isoformat()
    development_manifest = manifest(records, 'all_development_data')
    if reserved_test:
        assert_separated(development_manifest, reserved_test, source_time=True)
    partitions = partition_records(records, seed)
    urls = {name:[r.get('final_url') or r['url'] for r in rows] for name, rows in partitions.items()}
    labels = {name:[r['label'] for r in rows] for name, rows in partitions.items()}
    def vectorizer():
        return TfidfVectorizer(analyzer='char',ngram_range=(3,5),min_df=2,max_features=60000,sublinear_tf=True)
    tuning_vectorizer = vectorizer()
    x_fit = tuning_vectorizer.fit_transform(urls['fit'])
    x_tuning = tuning_vectorizer.transform(urls['tuning'])
    tuning_probabilities = {}
    for c in [.5, 1., 2.]:
        estimator = LogisticRegression(C=c,class_weight='balanced',max_iter=500,solver='liblinear',random_state=seed)
        estimator.fit(x_fit,labels['fit'])
        tuning_probabilities[c] = estimator.predict_proba(x_tuning)[:,1]
    best_c, tuning = select_tuning_candidate(labels['tuning'], tuning_probabilities, fpr_budget)
    fitted_vectorizer = vectorizer()
    x_development = fitted_vectorizer.fit_transform(urls['fit']+urls['tuning'])
    winner = LogisticRegression(C=best_c,class_weight='balanced',max_iter=500,solver='liblinear',random_state=seed)
    winner.fit(x_development,labels['fit']+labels['tuning'])
    probabilities = winner.predict_proba(fitted_vectorizer.transform(urls['calibration']))[:,1]
    threshold, calibration = select_fpr_threshold(labels['calibration'],probabilities,fpr_budget)
    test, _ = score_model(winner,fitted_vectorizer.transform(urls['test']),labels['test'],threshold)
    artifact = {'model_version':model_version,'algorithm':'character_tfidf_logistic_regression',
        'feature_scope':'character_url','label_scope':'mixed_threat' if any(r.get('label_scope')=='mixed_threat' for r in records) else 'phishing',
        'threshold':threshold,'best_c':best_c,'ngram_range':[3,5],
        'selection':tuning_selection_contract(fpr_budget),
        'calibration':{'method':'independent_fpr_budget','fpr_budget':fpr_budget,**calibration},
        'manifests':{name:manifest(rows,name) for name,rows in partitions.items()},
        'development_manifest':development_manifest,'reserved_test_manifest':reserved_test,
        'training_started_at':started,'training_completed_at':datetime.now(timezone.utc).isoformat(),
        'deployment_status':'research_only','deployment_eligible':False,
        'test':test,'tuning':{str(k):v for k,v in tuning.items()}}
    return artifact,winner,fitted_vectorizer


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--dataset',type=Path,required=True)
    parser.add_argument('--additional-dataset',type=Path,action='append',default=[])
    parser.add_argument('--output',type=Path,default=Path('ml/models/char-url-research-v1.json'))
    parser.add_argument('--model-version',default='char-url-research-v1')
    parser.add_argument('--limit',type=int)
    parser.add_argument('--balanced',action='store_true')
    parser.add_argument('--include-other-threats',action='store_true')
    parser.add_argument('--fpr-budget',type=float,default=.01)
    parser.add_argument('--reserved-test-manifest',type=Path)
    args = parser.parse_args()
    records = read_dataset([args.dataset,*args.additional_dataset],args.limit,balanced=args.balanced,
                           include_other_threats=args.include_other_threats)
    reserved = json.loads(args.reserved_test_manifest.read_text(encoding='utf-8')) if args.reserved_test_manifest else None
    artifact,model,vectorizer = train(records,model_version=args.model_version,fpr_budget=args.fpr_budget,reserved_test=reserved)
    args.output.parent.mkdir(parents=True,exist_ok=True)
    bundle = args.output.with_suffix('.joblib')
    joblib.dump({'model':model,'vectorizer':vectorizer},bundle)
    artifact['model_file_sha256'] = hashlib.sha256(bundle.read_bytes()).hexdigest()
    args.output.write_text(json.dumps(artifact,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(artifact['test'],indent=2))


if __name__ == '__main__':
    main()
