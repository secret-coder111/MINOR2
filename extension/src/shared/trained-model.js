(function (global) {
  global.PhishGuard = global.PhishGuard || {};

  function predictFeatures(featureSet) {
    const model = global.PHISH_GUARD_TRAINED_MODEL;
    if (!model || !Array.isArray(model.trees) || !model.trees.length) {
      return null;
    }

    const vector = model.feature_schema.map((name) => Number(featureSet[name]) || 0);
    const probabilities = model.trees.map((nodes) => {
      let index = 0;
      let steps = 0;
      while (steps < nodes.length) {
        const node = nodes[index];
        if (!node || node[0] < 0) {
          return node ? Number(node[4]) || 0 : 0;
        }
        index = vector[node[0]] <= node[1] ? node[2] : node[3];
        steps += 1;
      }
      return 0;
    });

    const probability = probabilities.reduce((sum, value) => sum + value, 0) / probabilities.length;
    return {
      probability,
      score: Math.round(probability * 100),
      threshold: Number(model.threshold) || 0.5,
      modelVersion: model.model_version || 'unknown'
    };
  }

  global.PhishGuard.predictTrainedModel = predictFeatures;
})(typeof self !== 'undefined' ? self : globalThis);
