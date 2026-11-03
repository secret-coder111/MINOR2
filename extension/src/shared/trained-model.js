(function (global) {
  'use strict';
  global.PhishGuard = global.PhishGuard || {};
  const checked = new WeakMap();
  function validStructure(model) {
    if (checked.has(model)) return checked.get(model);
    const schema = model.feature_schema;
    let valid = Array.isArray(schema) && schema.length > 0 && schema.length <= 256
      && new Set(schema).size === schema.length
      && schema.every((name) => typeof name === 'string')
      && Number.isFinite(model.threshold) && model.threshold >= 0 && model.threshold <= 1
      && Array.isArray(model.trees) && model.trees.length > 0;
    if (valid) valid = model.trees.every((nodes) => Array.isArray(nodes) && nodes.length > 0
      && nodes.every((node) => Array.isArray(node) && node.length === 5
        && Number.isInteger(node[0]) && Number.isFinite(node[1])
        && (node[0] < 0
          ? Number.isFinite(node[4]) && node[4] >= 0 && node[4] <= 1
          : node[0] < schema.length && Number.isInteger(node[2]) && Number.isInteger(node[3])
            && node[2] >= 0 && node[2] < nodes.length && node[3] >= 0 && node[3] < nodes.length)));
    checked.set(model, valid);
    return valid;
  }
  function predictFeatures(features = {}, options = {}) {
    const model = global.PHISH_GUARD_TRAINED_MODEL;
    if (!model || typeof model !== 'object' || !validStructure(model)) return null;
    const expectedVersion = global.FEATURE_SCHEMA_VERSION || '0.2.0';
    const compatible = model.feature_schema_version === expectedVersion && model.extractor_version === expectedVersion;
    if (!compatible && !options.allowLegacyDiagnostic) return null;
    const names = (global.PHISH_GUARD_FEATURES || []).map((feature) => feature.name);
    if (compatible && names.length && !model.feature_schema.every((name) => names.includes(name))) return null;
    const vector = model.feature_schema.map((name) => Math.fround(Number(features[name])));
    if (vector.some((value) => !Number.isFinite(value))) return null;
    const probabilities = [];
    for (const nodes of model.trees) {
      let index = 0;
      let probability = null;
      for (let steps = 0; steps < nodes.length; steps += 1) {
        const node = nodes[index];
        if (node[0] < 0) { probability = node[4]; break; }
        index = vector[node[0]] <= node[1] ? node[2] : node[3];
      }
      if (probability === null) return null; // Cyclic or malformed tree.
      probabilities.push(probability);
    }
    const probability = probabilities.reduce((sum, value) => sum + value, 0) / probabilities.length;
    const release = global.PHISH_GUARD_MODEL_RELEASE;
    const deploymentEligible = Boolean(compatible && release && release.mode === 'validated-model'
      && release.deployment_eligible === true && model.deployment_eligible === true
      && model.deployment_status === 'validated' && typeof model.predictor_sha256 === 'string'
      && model.predictor_sha256.length === 64 && model.predictor_sha256 === release.predictor_sha256
      && typeof model.extractor_sha256 === 'string' && model.extractor_sha256.length === 64
      && model.extractor_sha256 === release.extractor_sha256);
    return { probability, score: Math.round(probability * 100), threshold: model.threshold,
      modelVersion: model.model_version || 'unknown', compatible,
      deploymentEligible };
  }
  global.PhishGuard.predictTrainedModel = predictFeatures;
})(typeof self !== 'undefined' ? self : globalThis);
