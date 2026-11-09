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
    parser.add_argument('--output', type=Path, default=ROOT / 'extension/demo/url-model.js')
    args = parser.parse_args()
    metadata = args.metadata
    meta = json.loads(metadata.read_text())
    estimator = metadata.with_suffix('.joblib')
    if hashlib.sha256(estimator.read_bytes()).hexdigest() != meta['model_file_sha256']:
        raise ValueError('Estimator hash mismatch')
    bundle = joblib.load(estimator)
    if bundle['kind'] != BUNDLE_KIND:
        raise ValueError('Unsupported preview bundle')
    weight = bundle['numeric_weight']
    if meta['feature_schema'] != URL_FEATURE_SCHEMA:
        raise ValueError('Training/feature schema identity mismatch')
    actual_extractor_hash = extractor_source_hash()
    extractor_drift = meta['extractor_sha256'] != actual_extractor_hash
    if extractor_drift:
        # A URL-character estimator never consumes numeric/DOM features. Its
        # canonicalization identity is narrower than the complete extractor.
        # Preserve the real training hash and require an explicit input contract
        # plus unchanged canonicalizer; never rebind an old numeric estimator.
        contract = meta.get('predictor_input_contract', {})
        canonicalizer = ROOT / 'ml/src/canonicalize_urls.cjs'
        if (weight != 0 or contract.get('kind') != 'canonical_url_characters_only'
                or contract.get('canonicalizer_sha256') != hashlib.sha256(canonicalizer.read_bytes()).hexdigest()):
            raise ValueError('Training/extractor identity mismatch')
    transform = bundle.get('text_transform', 'none')
    if transform not in ['none', 'host_path_boundaries_v1']:
        raise ValueError('Unsupported browser character transform')
    metrics = meta['test']
    audit = json.loads((ROOT / meta['data_audit']).read_text())
    export = {'mode': 'research_preview', 'deployment_eligible': False,
        'model_version': meta['model_version'], 'feature_schema': meta['feature_schema'],
        'numeric_weight': weight, 'threshold': meta['threshold'], 'metrics': metrics,
        'text_transform': transform,
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
    output = args.output
    output.parent.mkdir(parents=True, exist_ok=True)
    candidate_output = output.with_name(output.name + '.parity-candidate')
    candidate_output.write_text('// Standalone research preview; never loaded by the page-verdict worker.\n'
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
    if transform == 'host_path_boundaries_v1':
        # This experiment's generic component transform has a dedicated local
        # predictor until the broader hybrid trainer supports this format.
        from importlib.util import spec_from_file_location, module_from_spec
        spec = spec_from_file_location('url_boundary_research', ROOT / 'scripts/research-url-checker-2026-11-06.py')
        experiment = module_from_spec(spec)
        spec.loader.exec_module(experiment)
        expected = experiment.predict_research(bundle, [{'url': url} for url in urls])
    else:
        expected = predict_bundle(bundle, [{'url': url} for url in urls])[:, 1]
    actual = json.loads(subprocess.run(['node', str(ROOT / 'scripts/url-checker-parity.cjs'), str(candidate_output.resolve())], input=json.dumps(urls),
        capture_output=True, text=True, encoding='utf-8', check=True).stdout)
    maximum = max(abs(float(a['probability']) - float(b)) for a, b in zip(actual, expected))
    if maximum > 1e-10:
        raise ValueError(f'Browser/sklearn predictor parity failed: {maximum}')
    for url, value in zip(urls, actual):
        python = build_feature_row(url)
        for name in URL_FEATURE_SCHEMA:
            if abs(python[name] - value['features'][name]) > 1e-9:
                raise ValueError(f'Browser/Python feature parity failed for {name}')
    # Replace the visible diagnostic only after inference and feature checks.
    candidate_output.replace(output)
    report = {'model_version': meta['model_version'], 'mode': 'research_preview', 'deployment_eligible': False,
        'cases': len(cases), 'maximum_absolute_predictor_error': maximum, 'all_url_features_match': True,
        'artifact_sha256': hashlib.sha256(output.read_bytes()).hexdigest(), 'bytes': output.stat().st_size,
        'text_transform': transform, 'training_extractor_sha256': meta['extractor_sha256'],
        'current_extractor_sha256': actual_extractor_hash, 'extractor_changed_since_training': extractor_drift,
        'predictor_input_contract': meta.get('predictor_input_contract'),
        'test': metrics, 'scope': 'Exploratory internal domain-separated URL-only model. No production accuracy claim.'}
    args.report.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
