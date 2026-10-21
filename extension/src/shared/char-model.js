(function (global) {
  function sigmoid(value) {
    if (value >= 0) {
      const exponential = Math.exp(-value);
      return 1 / (1 + exponential);
    }
    const exponential = Math.exp(value);
    return exponential / (1 + exponential);
  }

  function predict(url) {
    const model = global.PHISH_GUARD_CHAR_MODEL;
    if (!model || !model.vocabulary || !Array.isArray(model.coefficients)
      || !Array.isArray(model.idf)
      || model.coefficients.length !== model.idf.length) return null;

    const text = String(url || '').toLowerCase();
    const counts = Object.create(null);
    const minimum = Number(model.ngram_range && model.ngram_range[0]) || 3;
    const maximum = Number(model.ngram_range && model.ngram_range[1]) || 5;
    for (let length = minimum; length <= maximum; length += 1) {
      for (let index = 0; index + length <= text.length; index += 1) {
        const ngram = text.slice(index, index + length);
        const featureIndex = model.vocabulary[ngram];
        if (Number.isInteger(featureIndex)
          && featureIndex >= 0
          && featureIndex < model.coefficients.length) {
          counts[featureIndex] = (counts[featureIndex] || 0) + 1;
        }
      }
    }

    let squaredNorm = 0;
    Object.keys(counts).forEach((key) => {
      const featureIndex = Number(key);
      const count = 1 + Math.log(counts[key]);
      const value = count * Number(model.idf[featureIndex] || 0);
      counts[key] = value;
      squaredNorm += value * value;
    });
    const norm = Math.sqrt(squaredNorm);
    let linear = Number(model.intercept) || 0;
    if (norm > 0) {
      Object.keys(counts).forEach((key) => {
        linear += (counts[key] / norm) * Number(model.coefficients[Number(key)] || 0);
      });
    }

    const probability = sigmoid(linear);
    if (!Number.isFinite(probability)) return null;
    return {
      probability,
      score: Math.round(probability * 100),
      threshold: Number(model.threshold) || 0.5,
      highConfidenceThreshold: Number(model.high_confidence_threshold) || 0.99,
      modelVersion: model.model_version || "unknown"
    };
  }

  global.PhishGuard = global.PhishGuard || {};
  global.PhishGuard.predictCharacterModel = predict;
})(typeof self !== "undefined" ? self : globalThis);
