document.addEventListener('DOMContentLoaded', async () => {
  const api = window.PhishGuard.browser;
  const riskBadge = document.getElementById('riskBadge');
  const scoreText = document.getElementById('scoreText');
  const statusText = document.getElementById('statusText');
  const coverageText = document.getElementById('coverageText');
  const reputationText = document.getElementById('reputationText');
  const timingText = document.getElementById('timingText');
  const feedbackStatus = document.getElementById('feedbackStatus');
  const reasonList = document.getElementById('reasonList');
  const expected = document.getElementById('expectedVerdict');
  const report = document.getElementById('reportBtn');
  const siteOrigin = document.getElementById('siteOrigin');
  const evidenceOrigin = document.getElementById('evidenceOrigin');
  const nextStep = document.getElementById('nextStep');
  const rescan = document.getElementById('rescanBtn');
  const scanStatus = document.getElementById('scanStatus');
  const verdictTitle = document.getElementById('verdictTitle');
  const riskFill = document.getElementById('riskFill');
  const leave = document.getElementById('leaveBtn');
  const popup = document.querySelector('.popup');
  let resultData = null;
  let currentTab = null;
  let refreshSequence = 0;
  let savingFeedback = false;
  let rescanIdentity = null;
  let displayedContext = null;

  // Display the browser's ASCII origin, never a page-supplied title or full URL.
  function webOrigin(value) {
    try { const url = new URL(value); return ['http:', 'https:'].includes(url.protocol) ? url.origin : ''; }
    catch (_) { return ''; }
  }

  function render(data) {
    if (data && (!['SAFE', 'CAUTION', 'HIGH_RISK'].includes(data.outcome)
      || !Number.isFinite(data.score) || data.score < 0 || data.score > 100)) data = null;
    const contextKey = currentTab ? `${currentTab.id}:${data && data.identity && data.identity.documentToken || webOrigin(currentTab.url)}:${data && data.outcome || 'unknown'}` : '';
    if (contextKey !== displayedContext) {
      expected.value = '';
      feedbackStatus.textContent = '';
      displayedContext = contextKey;
    }
    resultData = data;
    reasonList.replaceChildren();
    report.disabled = !data || !!data.securityTest || savingFeedback;
    siteOrigin.textContent = webOrigin(currentTab && currentTab.url)
      || (currentTab && /^file:/i.test(currentTab.url || '') ? 'Local file' : 'This page has no inspectable web address');
    evidenceOrigin.hidden = true;
    evidenceOrigin.textContent = '';
    leave.hidden = !data || (data.outcome !== 'HIGH_RISK' && !data.securityTest);
    riskFill.style.width = data ? `${data.score}%` : '0%';
    if (!data) {
      popup.dataset.state = 'neutral';
      verdictTitle.textContent = 'No page result';
      riskBadge.textContent = 'Unknown';
      riskBadge.className = 'badge neutral';
      scoreText.textContent = 'No result yet';
      const restricted = currentTab && !/^(https?|file):/i.test(currentTab.url || '');
      statusText.textContent = restricted ? 'The browser does not allow inspection of this page.' : 'Waiting for page analysis. Refresh this tab after loading or reloading the extension.';
      coverageText.textContent = 'No document inspected.';
      reputationText.textContent = '';
      timingText.textContent = '';
      nextStep.textContent = 'Refresh the website after loading the extension, then check again.';
      return;
    }
    const names = { SAFE: ['Low risk', 'safe'], CAUTION: ['Caution', 'warn'], HIGH_RISK: ['High risk', 'danger'] };
    const incomplete = data.coverage && (data.coverage.complete === false || data.coverage.uninspectedFrames > 0
      || data.coverage.pendingFrames > 0 || data.coverage.inventoryAvailable === false);
    const band = data.outcome === 'SAFE' && incomplete ? ['Incomplete inspection', 'neutral'] : names[data.outcome] || ['Unknown', 'neutral'];
    riskBadge.textContent = band[0];
    riskBadge.className = `badge ${band[1]}`;
    popup.dataset.state = band[1];
    verdictTitle.textContent = data.outcome === 'HIGH_RISK' ? 'Possible phishing'
      : data.outcome === 'CAUTION' ? 'Check before continuing'
        : incomplete ? 'Part of this page is unchecked' : 'No strong indicators';
    scoreText.textContent = `${data.score}/100 risk index`;
    statusText.textContent = data.outcome === 'SAFE' && incomplete ? 'No strong indicators in the inspected content. Other content remains unchecked.' : data.label;
    const omitted = data.coverage && data.coverage.uninspectedFrames;
    const coverage = omitted > 0 ? ` ${omitted} embedded document(s) could not be inspected.`
      : data.coverage && !data.coverage.inventoryAvailable ? ' Embedded-document coverage could not be verified.' : '';
    const pending = data.coverage && data.coverage.pendingFrames > 0 ? ` Waiting for ${data.coverage.pendingFrames} document(s) to rescan.` : '';
    const limitations = data.coverage && Array.isArray(data.coverage.limitations) && data.coverage.limitations.length
      ? ' Some page content or controls are outside local inspection coverage.' : '';
    coverageText.textContent = `${data.inspectedFrames || 1} document(s) inspected.${coverage}${pending}${limitations} This score is not a probability or a safety guarantee.`;
    const reputationMessages = {
      disabled: 'Optional reputation lookup is off.',
      pending: 'Some optional reputation checks are pending. The result may change when they complete.',
      available: 'Optional reputation lookup completed. An unknown or clean response does not establish safety.',
      error: 'Some optional reputation checks failed. Remote coverage is incomplete. Check the endpoint in extension options.'
    };
    const remoteCoverage = data.reputationCoverage;
    const remoteSummary = remoteCoverage && ['available', 'pending', 'error'].every((key) => Number.isInteger(remoteCoverage[key]) && remoteCoverage[key] >= 0)
      && data.reputationStatus !== 'disabled' ? ` ${remoteCoverage.available} completed, ${remoteCoverage.pending} pending, ${remoteCoverage.error} failed.` : '';
    reputationText.textContent = `${reputationMessages[data.reputationStatus] || ''}${remoteSummary}`;
    const reputation = data.metadata && data.metadata.reputation;
    if (reputation && Number.isFinite(reputation.checkedAt) && Number.isFinite(reputation.expiresAt)) {
      reputationText.textContent += ` Source: user-configured service; hostname only. Checked ${new Date(reputation.checkedAt).toLocaleTimeString()}; cache expires ${new Date(reputation.expiresAt).toLocaleTimeString()}. Local rule score: ${data.metadata.rule_score}/100.`;
    }
    const timing = data.metadata && data.metadata.runtime_timing || {};
    const renderTiming = data.runtimeTiming || {};
    const measured = [];
    if (Number.isFinite(timing.extraction_ms)) measured.push(`evidence-frame extraction ${timing.extraction_ms.toFixed(1)} ms`);
    if (Number.isFinite(timing.policy_ms)) measured.push(`rules ${timing.policy_ms.toFixed(1)} ms`);
    if (Number.isFinite(renderTiming.scan_to_result_ms)) measured.push(`top-page scan to result ${renderTiming.scan_to_result_ms.toFixed(1)} ms`);
    if (Number.isFinite(renderTiming.scan_to_warning_dom_ms)) measured.push(`top-page scan to warning insertion ${renderTiming.scan_to_warning_dom_ms.toFixed(1)} ms`);
    if (Number.isFinite(renderTiming.scheduling_delay_ms)) measured.push(`scheduled wait ${renderTiming.scheduling_delay_ms.toFixed(1)} ms`);
    timingText.textContent = measured.length ? `Latest observed timing: ${measured.join('; ')}. Warning insertion does not measure paint or prevent submission.` : 'No timing sample is available for this result.';
    const sourceOrigin = webOrigin(data.evidenceFrame && data.evidenceFrame.origin);
    if (sourceOrigin && data.evidenceFrame.frameId !== 0) {
      evidenceOrigin.hidden = false;
      evidenceOrigin.textContent = `Indicators found in an embedded page: ${sourceOrigin}`;
    }
    nextStep.textContent = data.outcome === 'HIGH_RISK'
      ? 'Pause before entering passwords or payment details. Open the service using a saved bookmark or an address you know.'
      : data.outcome === 'CAUTION'
        ? 'Check the site address and the sign-in destination before continuing.'
        : incomplete ? 'Some content remains unchecked. Check the site address before sharing sensitive information.'
          : 'Check the site address before sharing sensitive information. A low score does not verify the owner.';
    if (rescanIdentity && data.identity && (data.identity.documentToken !== rescanIdentity.documentToken
      || data.identity.scanId > rescanIdentity.scanId)) {
      scanStatus.textContent = 'Page checked again.';
      rescanIdentity = null;
    }
    for (const reason of data.reasons || []) {
      const item = document.createElement('li');
      item.textContent = reason;
      reasonList.appendChild(item);
    }
    if (data.securityTest && data.outcome !== 'HIGH_RISK') {
      riskBadge.textContent = 'Security test';
      riskBadge.className = 'badge warn';
      popup.dataset.state = 'warn';
      verdictTitle.textContent = 'Official test recognised';
      statusText.textContent = data.securityTest.explanation;
      scoreText.textContent = `${data.score}/100 local rules; test URL matched`;
      nextStep.textContent = 'This harmless feature check tests a known URL entry. Use the controlled lab to explain form evidence; use an unseen benchmark to measure accuracy.';
    }
  }

  async function refresh() {
    const sequence = ++refreshSequence;
    try {
      // Worker checks the exact current URL in memory, including SPA changes.
      const tab = await window.PhishGuard.getCurrentTab();
      if (sequence !== refreshSequence) return;
      currentTab = tab;
      if (!tab) { render(null); return; }
      const response = await api.runtime.sendMessage({ type: 'GET_TAB_RESULT', tabId: tab.id, url: tab.url });
      if (sequence === refreshSequence) render(response && response.result || null);
    } catch (_) { if (sequence === refreshSequence) render(null); }
  }

  await refresh();
  document.getElementById('urlCheckerBtn').addEventListener('click', async () => {
    try { await api.tabs.create({ url: api.runtime.getURL('demo/url-checker.html') }); }
    catch (_) { scanStatus.textContent = 'Open the Test Lab and choose Check a URL.'; }
  });
  api.storage.onChanged.addListener((changes, area) => {
    if (area === 'session' && currentTab && changes[`tab_${currentTab.id}`]) refresh();
  });
  if (api.tabs.onUpdated) api.tabs.onUpdated.addListener((tabId, change) => {
    if (currentTab && tabId === currentTab.id && (change.url || change.status)) refresh();
  });

  rescan.addEventListener('click', async () => {
    if (!currentTab) { scanStatus.textContent = 'Open a website tab, then try again.'; return; }
    rescan.disabled = true;
    rescanIdentity = resultData && resultData.identity || null;
    const previousIdentity = rescanIdentity;
    scanStatus.textContent = 'Requesting a new page check…';
    try {
      const response = await api.runtime.sendMessage({ type: 'REQUEST_TAB_RESCAN', tabId: currentTab.id, url: currentTab.url });
      if (!response || response.requested !== true) throw new Error('No current document');
      scanStatus.textContent = 'Rescan requested. The result will update when analysis finishes.';
      await refresh();
      // A fast scan can arrive through storage before the request response.
      if (previousIdentity && resultData && resultData.identity
        && (resultData.identity.documentToken !== previousIdentity.documentToken
          || resultData.identity.scanId > previousIdentity.scanId)) {
        scanStatus.textContent = 'Page checked again.';
        rescanIdentity = null;
      }
    } catch (_) {
      rescanIdentity = null;
      scanStatus.textContent = 'Could not request a check. Refresh the website and try again.';
    } finally { rescan.disabled = false; }
  });
  document.getElementById('settingsBtn').addEventListener('click', async () => {
    try { await api.runtime.openOptionsPage(); }
    catch (_) { scanStatus.textContent = 'Open PhishGuard options from your browser’s Extensions page.'; }
  });

  leave.addEventListener('click', async () => {
    if (!currentTab || !resultData || (resultData.outcome !== 'HIGH_RISK' && !resultData.securityTest)) return;
    const target = { ...currentTab };
    leave.disabled = true;
    try {
      const active = await window.PhishGuard.getCurrentTab();
      if (!active || active.id !== target.id || active.url !== target.url) {
        scanStatus.textContent = 'The active page changed. Check its latest result.';
        await refresh();
        return;
      }
      await api.tabs.update(target.id, { url: 'about:blank' });
      window.close();
    } catch (_) { scanStatus.textContent = 'Could not leave this page. Close the website tab using your browser.'; }
    finally { leave.disabled = false; }
  });

  report.addEventListener('click', async () => {
    if (savingFeedback || !resultData || resultData.securityTest) return;
    if (!['SAFE', 'CAUTION', 'HIGH_RISK'].includes(expected.value)) {
      feedbackStatus.textContent = 'Choose the outcome you checked before saving a correction.';
      return;
    }
    const data = resultData;
    const coverage = data.coverage || {};
    const corrections = window.PhishGuard.sanitizeFeedback([{
      topOrigin: data.pageOrigin,
      evidenceOrigin: data.evidenceFrame && data.evidenceFrame.origin,
      evidenceFrameId: data.evidenceFrame && data.evidenceFrame.frameId,
      timestamp: Date.now(),
      expectedOutcome: expected.value,
      observedOutcome: data.outcome,
      score: data.score,
      policyVersion: data.metadata && data.metadata.policy_version || 'unknown',
      reviewed: false,
      context: {
        inspectedFrames: data.inspectedFrames,
        uninspectedFrames: coverage.uninspectedFrames,
        pendingFrames: coverage.pendingFrames,
        coverageComplete: coverage.complete === true,
        reputationStatus: data.reputationStatus,
        activeCategories: data.metadata && data.metadata.active_evidence_categories
      }
    }]);
    if (!corrections.length) { feedbackStatus.textContent = 'Corrections require a web page with an HTTP or HTTPS origin.'; return; }
    savingFeedback = true;
    report.disabled = true;
    feedbackStatus.textContent = 'Saving correction on this device…';
    try {
      const stored = await window.PhishGuard.storageCall('local', 'get', ['phishguard_feedback']);
      const feedback = window.PhishGuard.sanitizeFeedback([corrections[0], ...(Array.isArray(stored && stored.phishguard_feedback) ? stored.phishguard_feedback : [])]);
      await window.PhishGuard.storageCall('local', 'set', { phishguard_feedback: feedback });
      feedbackStatus.textContent = 'Correction saved on this device. Review or export it in extension options. It does not change predictions and has not been verified or sent anywhere.';
    } catch (_) {
      feedbackStatus.textContent = 'Could not save the correction. Device storage may be unavailable; try again.';
    } finally {
      savingFeedback = false;
      report.disabled = !resultData;
    }
  });
  document.getElementById('closeBtn').addEventListener('click', () => window.close());
});
