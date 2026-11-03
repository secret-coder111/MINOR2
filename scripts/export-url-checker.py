"""Export the standalone diagnostic URL preview, without enabling a release.

The extension's production verdict gate remains unchanged. This separate
artifact is labelled research_preview and parity-checked before public use.
"""
import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'ml/src'))
import joblib
import numpy as np
from dataset_contract import canonicalize_urls
from export_browser_model import serialize_tree
from feature_engineering import extractor_source_hash, URL_FEATURE_SCHEMA, build_feature_row
from train_hybrid_model import predict_bundle, BUNDLE_KIND


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--metadata', type=Path, default=ROOT / 'ml/models/url-checker-research-2026-11-03-expanded.json')
    parser.add_argument('--report', type=Path, default=ROOT / 'docs/audit/url-checker-model-2026-11-03.json')
    args = parser.parse_args()
    metadata = args.metadata
    meta = json.loads(metadata.read_text())
    estimator = metadata.with_suffix('.joblib')
    if hashlib.sha256(estimator.read_bytes()).hexdigest() != meta['model_file_sha256']:
        raise ValueError('Estimator hash mismatch')
    if meta['extractor_sha256'] != extractor_source_hash() or meta['feature_schema'] != URL_FEATURE_SCHEMA:
        raise ValueError('Training/extractor identity mismatch')
    bundle = joblib.load(estimator)
    if bundle['kind'] != BUNDLE_KIND:
        raise ValueError('Unsupported preview bundle')
    if bundle.get('text_transform', 'none') != 'none':
        raise ValueError('Browser export requires the established full-URL text transform')
    weight = bundle['numeric_weight']
    metrics = meta['test']
    audit = json.loads((ROOT / meta['data_audit']).read_text())
    export = {'mode': 'research_preview', 'deployment_eligible': False,
        'model_version': meta['model_version'], 'feature_schema': meta['feature_schema'],
        'numeric_weight': weight, 'threshold': meta['threshold'], 'metrics': metrics,
        'training_samples': audit['selected_rows'], 'input_files': len(audit['files']),
        'evaluation_samples': sum(metrics['confusion_matrix'].values()),
        'trees': [serialize_tree(tree) for tree in bundle['numeric_model'].estimators_] if weight else [],
        'character': None}
    if weight < 1:
        vectorizer, model = bundle['vectorizer'], bundle['character_model']
        if vectorizer.analyzer != 'char' or vectorizer.norm != 'l2' or not vectorizer.sublinear_tf or not vectorizer.lowercase:
            raise ValueError('Unsupported character preprocessing')
        export['character'] = {'vocabulary': {ngram: int(index) for ngram, index in vectorizer.vocabulary_.items()},
            'ngram_range': list(vectorizer.ngram_range), 'idf': vectorizer.idf_.tolist(),
            'coefficients': model.coef_[0].tolist(), 'intercept': float(model.intercept_[0])}
    data = json.dumps(export, separators=(',', ':'), ensure_ascii=True, allow_nan=False)
    output = ROOT / 'extension/demo/url-model.js'
    output.write_text('// Standalone research preview; never loaded by the page-verdict worker.\n'
        + 'globalThis.PHISHGUARD_URL_PREVIEW = JSON.parse(' + json.dumps(data) + ');\n', encoding='utf-8')
    # Include the training-independent public controls and URL parser/Unicode
    # boundary cases, plus deterministic randomized address combinations.
    cases = ['https://github.com/login', 'https://www.google.com/', 'https://www.amtso.org/check-desktop-phishing-page/',
        'http://http-password.badssl.com/', 'https://paypal.com/', 'https://paypal.com.example.invalid/verify',
        'https://g\u03bf\u03bfgle.example/\u767b\u5f55?x=\u0130', 'https://user:pass@example.com/',
        'https://b\u00fccher.example/path', 'https://example.com/a/../Login?q=A%20B#section', 'http://127.0.0.1:8080/']
    # Embedded credentials are deliberately rejected by the public interface.
    cases.remove('https://user:pass@example.com/')
    for i in range(1000):
        cases.append(f'{"https" if i % 3 else "http"}://{"secure-" if i % 4 else ""}portal{i % 73}.example{ "/login?x=" + str(i) if i % 2 else "/Account/" + str(i) }')
    urls = canonicalize_urls(cases)
    expected = predict_bundle(bundle, [{'url': url} for url in urls])[:, 1]
    actual = json.loads(subprocess.run(['node', str(ROOT / 'scripts/url-checker-parity.cjs')], input=json.dumps(urls),
        capture_output=True, text=True, encoding='utf-8', check=True).stdout)
    maximum = max(abs(float(a['probability']) - float(b)) for a, b in zip(actual, expected))
    if maximum > 1e-10:
        raise ValueError(f'Browser/sklearn predictor parity failed: {maximum}')
    for url, value in zip(urls, actual):
        python = build_feature_row(url)
        for name in URL_FEATURE_SCHEMA:
            if abs(python[name] - value['features'][name]) > 1e-9:
                raise ValueError(f'Browser/Python feature parity failed for {name}')
    report = {'model_version': meta['model_version'], 'mode': 'research_preview', 'deployment_eligible': False,
        'cases': len(cases), 'maximum_absolute_predictor_error': maximum, 'all_url_features_match': True,
        'artifact_sha256': hashlib.sha256(output.read_bytes()).hexdigest(), 'bytes': output.stat().st_size,
        'test': metrics, 'scope': 'Exploratory internal domain-separated URL-only model. No production accuracy claim.'}
    args.report.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
