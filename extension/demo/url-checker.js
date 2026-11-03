(function () {
  'use strict';
  const get = id => document.getElementById(id);
  const input = get('urlInput');
  const result = get('urlResult');
  const error = get('inputError');
  const status = get('checkerStatus');
  const model = window.PHISHGUARD_URL_PREVIEW;
  const extensionApi = location.protocol === 'chrome-extension:' ? window.chrome : null;
  let generation = 0;
  if (extensionApi?.tabs && extensionApi.runtime) {
    get('openCheckedUrl').textContent = 'Load page and inspect with PhishGuard';
    get('openCheckedUrl').addEventListener('click', async event => {
      event.preventDefault();
      const address = get('openCheckedUrl').href;
      const current = ++generation;
      const panel = get('pageCheckResult');
      panel.hidden = false;
      panel.dataset.state = 'pending';
      get('pageCheckTitle').textContent = 'Loading the page for inspection...';
      get('pageCheckDetails').textContent = 'A temporary browser tab loads this address. The extension inspects its actual document. No sign-in details are entered.';
      get('pageCheckReasons').replaceChildren();
      try {
        const inspected = await window.PhishGuard.inspectLoadedURL(address, extensionApi, { cancelled: () => current !== generation });
        if (current !== generation) return;
        panel.dataset.state = inspected.outcome;
        const test = inspected.securityTest && inspected.outcome !== 'HIGH_RISK';
        get('pageCheckTitle').textContent = test ? 'Official security test recognised'
          : inspected.outcome === 'HIGH_RISK' ? `High phishing risk \u00b7 ${inspected.score}/100`
            : inspected.outcome === 'CAUTION' ? `Caution \u00b7 ${inspected.score}/100`
              : `No strong page indicators \u00b7 ${inspected.score}/100`;
        const incomplete = !inspected.coverage?.complete;
        get('pageCheckDetails').textContent = `${inspected.pageOrigin} \u00b7 ${inspected.inspectedFrames || 1} document(s) inspected.${incomplete ? ' Inspection coverage is incomplete.' : ''} This is the extension's current evidence index, not a safety guarantee. Late content or a changed page may change the result.`;
        const reasons = test ? [inspected.securityTest.explanation] : inspected.reasons || [];
        for (const reason of reasons) { const li = document.createElement('li'); li.textContent = reason; get('pageCheckReasons').appendChild(li); }
      } catch (_) {
        if (current !== generation) return;
        panel.dataset.state = 'unknown';
        get('pageCheckTitle').textContent = 'No page verdict available';
        get('pageCheckDetails').textContent = 'The browser may have blocked the page, it may be unavailable, or inspection may have timed out. No low-risk verdict is inferred from this failure.';
      }
    });
  }
  const percent = value => (value * 100).toFixed(1) + '%';
  if (model?.metrics) {
    get('metricsScope').textContent = `Research model only: ${model.evaluation_samples.toLocaleString()} internal test URLs, separated from training by registrable site. This test was previously used; these metrics do not describe the primary URL-evidence check or production accuracy.`;
    for (const [label, key] of [['Accuracy', 'accuracy'], ['Precision', 'precision'], ['Recall', 'recall'], ['F1', 'f1']]) {
      const cell = document.createElement('div');
      const dt = document.createElement('dt'); dt.textContent = label;
      const dd = document.createElement('dd'); dd.textContent = percent(model.metrics[key]);
      cell.append(dt, dd); get('modelMetrics').appendChild(cell);
    }
    const m = model.metrics;
    get('evaluationDetails').textContent = `False-positive rate: ${percent(m.false_positive_rate)} (95% interval ${m.false_positive_rate_95ci.map(percent).join(' to ')}). Recall 95% interval: ${m.recall_95ci.map(percent).join(' to ')}. ${model.training_samples.toLocaleString()} URLs were selected after auditing all ${model.input_files} local files, removing duplicate/conflicting addresses and excluding unreviewed or generic threat labels. Candidate selection used tuning data and a separate calibration partition with a 1% empirical false-positive budget. Final test results did not select the winner. The research model's caution band is an intermediate review band, not a positive phishing prediction in these metrics.`;
    get('modelVersion').textContent = `Model: ${model.model_version}. Research preview; not enabled for the extension's page verdicts.`;
  } else {
    get('metricsScope').textContent = 'Research model unavailable. The independent address-evidence check remains available.';
  }
  function check() {
    generation++;
    get('pageCheckResult').hidden = true;
    error.hidden = true;
    // Clear the old result before validation, so a failed check cannot retain a
    // previous site's apparently reassuring score or a stale navigation link.
    result.hidden = true;
    get('openCheckedUrl').hidden = true;
    get('openCheckedUrl').removeAttribute('href');
    try {
      const value = window.PhishGuard.URLChecker.analyze(input.value);
      const labels = { low: ['Limited inspection', 'No strong address evidence', 'Few address indicators were found. The page, its owner and live reputation remain unchecked. Inspect the actual page before sharing information.'],
        caution: ['Caution', 'Review the address and page', 'The address has a structural or transport concern. Read the observations and inspect the page for corroborating evidence.'] };
      const [badge, title, guidance] = labels[value.band];
      result.dataset.band = value.band;
      get('resultBand').textContent = badge;
      get('resultBand').className = 'badge ' + ({ low: 'low', caution: 'medium', high: 'high' }[value.band]);
      get('resultTitle').textContent = title;
      get('resultGuidance').textContent = guidance;
      get('urlScore').textContent = value.score;
      get('urlScoreFill').style.width = value.score + '%';
      get('scoreBreakdown').textContent = value.scoreComponents.length
        ? value.scoreComponents.map(part => `${part.category}: +${part.points}`).join(' \u00b7 ')
        : 'No scored address indicators. Page content and live reputation are unchecked.';
      get('modelDiagnostic').textContent = value.modelScore === null ? 'Research model unavailable. The address evidence above remains separate.'
        : `Experimental model score: ${value.modelScore}/100 (${value.modelBand} research band). This model failed the release criteria and can misclassify legitimate addresses, including GitHub login. Its score is not used for the primary assessment above.`;
      for (const [id, text] of Object.entries({ checkedHost: value.host, checkedSite: value.site, checkedTransport: value.transport, normalizedUrl: value.url })) get(id).textContent = text;
      get('urlReasons').replaceChildren();
      for (const reason of value.reasons) { const li = document.createElement('li'); li.textContent = reason; get('urlReasons').appendChild(li); }
      get('securityTestNote').hidden = !value.securityTest;
      get('securityTestNote').textContent = value.securityTest ? 'Official harmless AMTSO feature-check URL. The installed extension recognises this known test entry separately from the statistical URL score. This is not a live credential-stealing site.' : '';
      get('openCheckedUrl').href = value.url;
      get('openCheckedUrl').hidden = false;
      result.hidden = false;
      status.textContent = 'Address checked locally. No website was visited. Page content and live reputation remain unchecked.';
    } catch (exception) {
      error.textContent = exception.message || 'The URL check failed. Try again.';
      error.hidden = false;
      status.textContent = 'No result for this address.';
    }
  }
  get('checkUrl').addEventListener('click', check);
  input.addEventListener('input', () => {
    generation++;
    result.hidden = true;
    get('pageCheckResult').hidden = true;
    get('openCheckedUrl').hidden = true;
    get('openCheckedUrl').removeAttribute('href');
    error.hidden = true;
    status.textContent = 'Address changed. Run Check URL for a new result.';
  });
  input.addEventListener('keydown', event => { if (event.key === 'Enter') { event.preventDefault(); check(); } });
  for (const button of document.querySelectorAll('[data-url-example]')) button.addEventListener('click', () => { input.value = button.dataset.urlExample; check(); });
  get('checkUrl').disabled = false;
  for (const button of document.querySelectorAll('[data-url-example]')) button.disabled = false;
  status.textContent = 'Ready for an address.';
})();
