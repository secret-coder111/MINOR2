importScripts(
  '../shared/feature-schema.js',
  '../shared/constants.js',
  '../shared/browser-api.js',
  '../shared/risk-score.js',
  '../shared/model-policy.js',
  '../shared/trained-model-data.js',
  '../shared/trained-char-model-data.js',
  '../shared/trained-model.js',
  '../shared/char-model.js',
  '../content/explanation-mapping.js'
);

self.PhishGuard = self.PhishGuard || {};

(function () {
  const browserApi = self.PhishGuard.browser;

  if (browserApi.tabs && browserApi.tabs.onUpdated) {
    browserApi.tabs.onUpdated.addListener((tabId, changeInfo) => {
      if (changeInfo.url) {
        browserApi.storage.local.remove(`tab_${tabId}`);
      }
    });
  }

  function normalizeFeatureVector(featureSet) {
    return self.PhishGuard.normalizeFeatureVector(featureSet);
  }

  function scoreFeatures(features) {
    return self.PhishGuard.scoreFeatures(features);
  }

  function getRiskLevel(score) {
    if (score <= 34) return { label: 'legitimate', title: 'No strong phishing indicators found.' };
    if (score <= 64) return { label: 'suspicious', title: 'Use caution.' };
    return { label: 'likely_phishing', title: 'Likely phishing' };
  }

  function generateReasons(features) {
    const explanationMap = self.PhishGuard.explanationMap || {};
    const reasons = [];

    const orderedChecks = [
      'cross_domain_form_action',
      'has_password_input',
      'uses_http',
      'has_punycode',
      'brand_domain_mismatch',
      'suspicious_keyword_count',
      'obfuscated_script_score',
      'meta_refresh_count',
      'page_title_mismatch',
      'hidden_iframe_count',
      'frontpage_suspicious_signal_count',
      'credential_submission_script'
    ];

    orderedChecks.forEach((key) => {
      if (!features[key]) return;
      if (key === 'suspicious_keyword_count' && Number(features[key]) < 2) return;
      if (key === 'obfuscated_script_score' && Number(features[key]) < 0.3) return;
      if (key === 'meta_refresh_count' && Number(features[key]) < 1) return;
      if (key === 'hidden_iframe_count' && Number(features[key]) < 1) return;
      if (key === 'page_title_mismatch' && Number(features[key]) < 1) return;
      if (key === 'frontpage_suspicious_signal_count' && Number(features[key]) < 3) return;
      if (key === 'credential_submission_script' && Number(features[key]) < 1) return;
      const message = explanationMap[key] || 'The page displays multiple suspicious indicators.';
      reasons.push(message);
    });

    if (!reasons.length) {
      reasons.push('No strong phishing indicators were found from the current page signals.');
    }

    return reasons.slice(0, 5);
  }

  function applyExplicitRules(score, features) {
    let adjustedScore = score;
    if (Number(features.has_ip_address) === 1) adjustedScore += 12;
    if (Number(features.brand_domain_mismatch) === 1) adjustedScore += 12;
    if (Number(features.redirect_count) >= 2) adjustedScore += 10;
    if (Number(features.suspicious_hosting) === 1 && Number(features.brand_name_in_url) === 1) adjustedScore += 10;
    if (Number(features.frontpage_suspicious_signal_count) >= 3) adjustedScore += 12;
    if (
      Number(features.is_official_brand_domain) === 1
      && !self.PhishGuard.hasHighConfidencePageEvidence(features)
    ) {
      adjustedScore = Math.min(adjustedScore, 34);
    }
    if (self.PhishGuard.isOrdinarySecureLoginPage(features)) {
      adjustedScore = Math.min(adjustedScore, 34);
    }
    return Math.min(100, adjustedScore);
  }

  function getOptions() {
    return new Promise((resolve) => {
      browserApi.storage.local.get(['phishguard_options'], (result) => {
        resolve(result && result.phishguard_options ? result.phishguard_options : {});
      });
    });
  }

  async function lookupReputation(hostname) {
    const options = await getOptions();
    if (!options.reputationEnabled || !options.reputationEndpoint || !hostname) return null;

    try {
      const endpoint = new URL(options.reputationEndpoint);
      endpoint.searchParams.set('hostname', hostname);
      const response = await fetch(endpoint.toString(), { headers: { Accept: 'application/json' } });
      if (!response.ok) return null;
      const result = await response.json();
      return {
        verdict: String(result.verdict || (result.malicious ? 'malicious' : 'unknown')).toLowerCase(),
        source: String(result.source || 'configured reputation service')
      };
    } catch (error) {
      return null;
    }
  }

  function saveTabResult(tabId, tabUrl, result) {
    if (!tabId) return;
    browserApi.storage.local.set({
      [`tab_${tabId}`]: {
        url: tabUrl,
        score: result.score,
        label: result.label,
        reasons: result.reasons,
        metadata: result.metadata,
        createdAt: Date.now()
      }
    });
  }

  async function enrichWithReputation(tab, features, result) {
    const reputation = await lookupReputation(features.hostname || '');
    if (!reputation) return;

    result.metadata.reputation = reputation;
    if (reputation.verdict === 'malicious' || reputation.verdict === 'phishing') {
      result.score = Math.max(result.score, 90);
      result.risk = getRiskLevel(result.score);
      result.label = result.risk.title;
      result.warning = true;
      result.reasons.unshift(`A configured reputation service reported this hostname as ${reputation.verdict}.`);
      result.reasons = result.reasons.slice(0, 5);
    }
    saveTabResult(tab && tab.id, tab && tab.url, result);
    if (tab && tab.id && browserApi.tabs.sendMessage) {
      try {
        const delivery = browserApi.tabs.sendMessage(tab.id, { type: 'ANALYZE_RESULT', payload: result });
        if (delivery && typeof delivery.catch === 'function') delivery.catch(() => {});
      } catch (error) {
      }
    }
  }

  function analyzePage(features) {
    const normalized = normalizeFeatureVector(features);
    const ruleScore = applyExplicitRules(scoreFeatures(normalized), features);
    const frontpageAnalysis = {
      isLandingPage: Number(features.frontpage_is_landing_page) === 1,
      credentialForm: Number(features.frontpage_has_credential_form) === 1,
      suspiciousSignalCount: Number(features.frontpage_suspicious_signal_count) || 0
    };
    const trainedPrediction = self.PhishGuard.predictTrainedModel(features);
    const characterPrediction = self.PhishGuard.predictCharacterModel(
      features.url || features.href || ''
    );
    const trainedModelApplied = Boolean(
      trainedPrediction
      && trainedPrediction.probability >= trainedPrediction.threshold
      && self.PhishGuard.shouldApplyModel(features)
    );
    const characterHighConfidence = Boolean(
      characterPrediction
      && characterPrediction.probability >= characterPrediction.highConfidenceThreshold
      && self.PhishGuard.shouldApplyModel(features)
    );
    const trainedScore = trainedModelApplied ? trainedPrediction.score : 0;
    const characterScore = characterHighConfidence ? characterPrediction.score : 0;
    const score = Math.max(ruleScore, trainedScore, characterScore);
    const risk = getRiskLevel(score);
    const reasons = generateReasons(normalized);

    return {
      score,
      risk,
      label: risk.title,
      reasons,
      warning: score >= 65,
      metadata: {
        model_version: trainedPrediction
          ? trainedPrediction.modelVersion
          : (self.PHISH_GUARD_MODEL_VERSION || 'v0.1.0'),
        features_checked: Object.keys(normalized).length,
        rule_score: ruleScore,
        trained_score: trainedScore,
        trained_probability: trainedPrediction ? trainedPrediction.probability : null,
        trained_model_applied: trainedModelApplied,
        character_probability: characterPrediction ? characterPrediction.probability : null,
        character_model_applied: characterHighConfidence,
        frontpage_analysis: frontpageAnalysis
      }
    };
  }

  browserApi.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (!message || message.type !== 'ANALYZE_PAGE') return;

    const result = analyzePage(message.payload || {});
    sendResponse({ type: 'ANALYZE_RESULT', payload: result });

    enrichWithReputation(sender.tab, message.payload || {}, result).catch(() => {});

    if (sender.tab && sender.tab.id && browserApi.tabs.sendMessage) {
      try {
        const delivery = browserApi.tabs.sendMessage(sender.tab.id, {
          type: 'ANALYZE_RESULT',
          payload: result
        });
        if (delivery && typeof delivery.catch === 'function') {
          delivery.catch(() => {});
        }
      } catch {
      }
    }

    saveTabResult(sender.tab && sender.tab.id, sender.tab && sender.tab.url, result);
  });
})();
