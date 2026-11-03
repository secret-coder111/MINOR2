(function (global) {
  'use strict';
  const api = global.PhishGuard;
  function normalize(value) {
    if (typeof value !== 'string' || !value.trim()) throw new Error('Enter a website address first.');
    if (value.length > 4096 || /[\u0000-\u001f\u007f]/.test(value)) throw new Error('Use an address under 4097 characters with no control characters.');
    let text = value.trim();
    if (!/^https?:\/\//i.test(text)) {
      if (/^[a-z][a-z0-9+.-]*:/i.test(text) && !/^[^/?#]+:\d+(?:[/?#]|$)/.test(text)) throw new Error('Only HTTP and HTTPS website addresses can be checked.');
      text = text.startsWith('//') ? 'https:' + text : 'https://' + text;
    }
    let url;
    try { url = new URL(text); } catch (_) { throw new Error('That address is not valid. Try https://example.com/path.'); }
    if (!['http:', 'https:'].includes(url.protocol) || !url.hostname) throw new Error('Only HTTP and HTTPS website addresses can be checked.');
    if (url.username || url.password) throw new Error('Remove the username or password embedded in this address before checking it.');
    return url;
  }
  function sigmoid(value) {
    if (value >= 0) return 1 / (1 + Math.exp(-value));
    const e = Math.exp(value); return e / (1 + e);
  }
  function predict(url, features) {
    const model = global.PHISHGUARD_URL_PREVIEW;
    if (!model || model.mode !== 'research_preview' || model.deployment_eligible !== false
        || !Array.isArray(model.feature_schema) || !Number.isFinite(model.threshold)
        || !Number.isFinite(model.numeric_weight) || model.numeric_weight < 0 || model.numeric_weight > 1) {
      throw new Error('The URL model is unavailable. Reload this page or rebuild the URL checker.');
    }
    const weight = model.numeric_weight;
    let numeric = 0, character = 0, familiarPatterns = null;
    if (weight > 0) {
      const vector = model.feature_schema.map(name => Math.fround(features[name]));
      if (vector.some(value => !Number.isFinite(value)) || !model.trees?.length) throw new Error('URL feature or model mismatch.');
      for (const tree of model.trees) {
        let index = 0, leaf = null;
        for (let steps = 0; steps < tree.length; steps++) {
          const node = tree[index];
          if (!node || node.length !== 5) break;
          if (node[0] < 0) { leaf = node[4]; break; }
          index = vector[node[0]] <= node[1] ? node[2] : node[3];
        }
        if (!Number.isFinite(leaf) || leaf < 0 || leaf > 1) throw new Error('The URL model contains an invalid tree.');
        numeric += leaf / model.trees.length;
      }
    }
    if (weight < 1) {
      const char = model.character;
      if (!char?.vocabulary || char.idf.length !== char.coefficients.length) throw new Error('The character model is unavailable.');
      const text = url.toLowerCase().replace(/\s\s+/g, ' ');
      const counts = new Map();
      for (let length = char.ngram_range[0]; length <= char.ngram_range[1]; length++) {
        for (let i = 0; i + length <= text.length; i++) {
          const key = text.slice(i, i + length);
          if (!Object.prototype.hasOwnProperty.call(char.vocabulary, key)) continue;
          const index = char.vocabulary[key];
          counts.set(index, (counts.get(index) || 0) + 1);
        }
      }
      familiarPatterns = counts.size;
      let squaredNorm = 0;
      for (const [index, count] of counts) {
        const tfidf = (1 + Math.log(count)) * char.idf[index];
        counts.set(index, tfidf); squaredNorm += tfidf * tfidf;
      }
      const norm = Math.sqrt(squaredNorm);
      let linear = char.intercept;
      if (norm > 0) for (const [index, tfidf] of counts) linear += tfidf / norm * char.coefficients[index];
      character = sigmoid(linear);
    }
    const probability = weight * numeric + (1 - weight) * character;
    if (!Number.isFinite(probability) || probability < 0 || probability > 1) throw new Error('The model did not return a valid result.');
    return { probability, score: Math.round(probability * 100), threshold: model.threshold,
      band: probability >= model.threshold ? 'high' : probability >= .35 ? 'caution' : 'low', familiarPatterns };
  }
  function analyze(value) {
    const url = normalize(value);
    const features = api.extractUrlFeatures(url.href);
    if (typeof api.scoreEvidence !== 'function') throw new Error('The address-checking policy is unavailable. Reload the page.');
    const evidence = api.scoreEvidence({ ...features, url: url.href });
    // URL-only transport evidence must not depend on an unobserved password
    // field. Keep this preview separate from the unchanged loaded-page policy.
    const httpPoints = url.protocol === 'http:' && !api.domainUtils.isLoopback(url.hostname) ? 15 : 0;
    const components = Object.entries(evidence.categories).filter(([, points]) => points > 0)
      .map(([category, points]) => ({ category, points }));
    if (httpPoints) components.push({ category: 'URL HTTP transport', points: httpPoints });
    const score = Math.min(64, evidence.score + httpPoints);
    // The learned model failed the release gate. Keep its diagnostic score
    // separate; never promote it into the primary address assessment.
    let prediction = null;
    try { prediction = predict(url.href, features); } catch (_) { /* Address evidence remains usable without research diagnostics. */ }
    const site = api.domainUtils.getRegistrableDomain(url.hostname);
    const reasons = [];
    if (url.protocol === 'http:') reasons.push('This address uses HTTP. Sensitive information would lack HTTPS transport protection.');
    if (features.has_ip_address) reasons.push('The host is a numeric IP address. Verify who controls the destination.');
    if (features.has_punycode) reasons.push('The hostname uses internationalised encoding. Compare its exact ASCII spelling with the intended service.');
    if (features.brand_address_deception) reasons.push('The address resembles a known brand while its registrable site differs. Review the exact hostname.');
    if (features.subdomain_count >= 3) reasons.push('The address has several subdomains. Read the registrable site rather than the first brand-like word.');
    if (features.has_unusual_port) reasons.push('The address specifies a nonstandard port. Confirm the service you intended to reach.');
    if (features.suspicious_keyword_count > 0) reasons.push('Sign-in or account-related words appear in the URL. Legitimate sites use these words too; they are not proof of phishing.');
    if (!reasons.length) reasons.push('No listed address warning was found. The model and this checklist cannot verify website ownership or page content.');
    const securityTest = url.protocol === 'https:' && !url.port
      && ['amtso.org', 'www.amtso.org'].includes(url.hostname) && /^\/check-desktop-phishing-page\/?$/.test(url.pathname);
    const addressConcern = score > 0;
    return { url: url.href, host: url.hostname, site: site || url.hostname,
      transport: url.protocol === 'https:' ? 'HTTPS (content and ownership unchecked)' : 'HTTP (unencrypted)',
      features, probability: prediction?.probability ?? null,
      modelScore: prediction?.score ?? null, modelBand: prediction?.band ?? null,
      threshold: prediction?.threshold ?? null, score, scoreComponents: components,
      band: addressConcern ? 'caution' : 'low', reasons, securityTest,
      scope: 'URL evidence only; page and live reputation uninspected' };
  }
  api.URLChecker = { normalize, analyze, predict };
})(typeof window !== 'undefined' ? window : globalThis);
