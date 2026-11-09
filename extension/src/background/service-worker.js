importScripts('../shared/feature-schema.js', '../shared/browser-api.js', '../shared/model-policy.js', '../shared/model-release.js');

importScripts('../shared/feedback.js');
self.PhishGuard = self.PhishGuard || {};

(function () {
  const api = self.PhishGuard.browser;
  const tabs = new Map();
  // Results expire with the browser session. Never fall back to persistent local storage.
  const session = api.storage.session;
  const titles = { SAFE: 'No strong phishing indicators found.', CAUTION: 'Use caution.', HIGH_RISK: 'High phishing risk.' };
  let configurationRevision = 0;
  const reputationControllers = new Set();
  const reputationCache = new Map();
  const reputationInflight = new Map();
  const reputationStarts = [];
  const CACHE_KEY = 'phishguard_reputation_cache';
  const MAX_CACHE = 256;
  const actionStates = new Map();
  const monotonicNow = () => self.performance && typeof self.performance.now === 'function' ? self.performance.now() : Date.now();
  const duration = (value) => Number.isFinite(value) && value >= 0 && value <= 600000 ? Math.round(value * 100) / 100 : null;

  function actionCall(method, value) {
    if (!api.action || typeof api.action[method] !== 'function') return;
    try {
      const pending = api.action[method](value);
      if (pending && pending.catch) pending.catch(() => {});
    } catch (_) { /* Unsupported/closed tabs must not interrupt local scoring. */ }
  }

  // A page can imitate or cover document UI. This status belongs to browser UI
  // and is derived only from the worker's current canonical result.
  function updateAction(tabId, result = null, pending = false) {
    const incomplete = result && result.coverage && !result.coverage.complete;
    let text = '', color = '#596b7c', title = 'PhishGuard: No current page result. Open to inspect coverage.';
    if (pending) { text = '...'; title = 'PhishGuard: Checking page. No current verdict.'; }
    if (result) {
      if (result.outcome === 'HIGH_RISK') { text = '!'; color = '#a5263c'; title = 'PhishGuard: High phishing risk. Open to review indicators.'; }
      else if (result.securityTest) { text = 'TEST'; color = '#8a5700'; title = 'PhishGuard: Known security test recognised. This does not measure detection accuracy.'; }
      else if (result.outcome === 'CAUTION') { text = '!'; color = '#8a5700'; title = 'PhishGuard: Caution. Check the address and sign-in destination.'; }
      else if (incomplete) { text = '?'; title = 'PhishGuard: Incomplete inspection. Some content remains unchecked.'; }
      else if (result.reputationStatus === 'pending') { text = '...'; title = 'PhishGuard: Local check found no strong indicators; optional reputation pending.'; }
      else if (result.reputationStatus === 'error') { text = '?'; title = 'PhishGuard: Local check found no strong indicators; optional reputation unavailable.'; }
      else title = 'PhishGuard: No strong indicators in inspected content. Website safety is not verified.';
      if (result.outcome !== 'SAFE' && incomplete) title += ' Inspection is incomplete.';
      if (result.outcome !== 'SAFE' && result.reputationStatus === 'pending') title += ' Optional reputation pending.';
      if (result.outcome !== 'SAFE' && result.reputationStatus === 'error') title += ' Optional reputation unavailable.';
    }
    const key = JSON.stringify([text, color, title]);
    if (actionStates.get(tabId) === key) return;
    actionStates.set(tabId, key);
    actionCall('setBadgeText', { tabId, text });
    actionCall('setBadgeBackgroundColor', { tabId, color });
    actionCall('setTitle', { tabId, title });
  }
  function sessionUpdate(method, ...args) {
    if (!session || typeof session[method] !== 'function') return;
    try {
      const pending = session[method](...args, () => { void api.runtime.lastError; });
      if (pending && pending.catch) pending.catch(() => {});
    } catch (_) { /* A cache/storage failure must not suppress local analysis. */ }
  }
  // Hostnames and endpoint digests only; never browsing paths or endpoint secrets.
  const cacheReady = new Promise((resolve) => {
    if (!session || !session.get) { resolve(); return; }
    try { session.get([CACHE_KEY], (data) => {
      if (api.runtime.lastError) { resolve(); return; }
      if (configurationRevision !== 0) { resolve(); return; }
      for (const entry of (Array.isArray(data && data[CACHE_KEY]) ? data[CACHE_KEY] : []).slice(-MAX_CACHE)) {
        if (!entry || !/^[a-f0-9]{64}$/.test(entry.endpointKey || '') || typeof entry.hostname !== 'string'
            || entry.hostname.length > 253 || !Number.isFinite(entry.expiresAt) || entry.expiresAt <= Date.now()
            || entry.expiresAt > Date.now() + 600000 || !Number.isFinite(entry.checkedAt)
            || entry.checkedAt > Date.now() || !['malicious', 'phishing', 'safe', 'benign', 'unknown'].includes(entry.verdict)) continue;
        try { if (new URL(`https://${entry.hostname}/`).hostname !== entry.hostname) continue; } catch (_) { continue; }
        reputationCache.set(`${entry.endpointKey}:${entry.hostname}`, { status: 'available', endpointKey: entry.endpointKey,
          hostname: entry.hostname, verdict: entry.verdict, checkedAt: entry.checkedAt, expiresAt: entry.expiresAt });
      }
      persistReputation();
      resolve();
    }); } catch (_) { resolve(); }
  });

  function persistReputation() {
    sessionUpdate('set', { [CACHE_KEY]: [...reputationCache.values()].filter((entry) => entry.status === 'available' && entry.expiresAt > Date.now()).slice(-MAX_CACHE) });
  }

  function quietSend(tabId, message, options = { frameId: 0 }) {
    try {
      const promise = api.tabs.sendMessage(tabId, message, options);
      if (promise && promise.catch) promise.catch(() => {});
    } catch (_) { /* The document may have closed or disallowed content scripts. */ }
  }

  function clearStored(tabId) {
    sessionUpdate('remove', `tab_${tabId}`);
  }

  function resetTab(tabId, url = '', documentId = null) {
    const state = { topUrl: url, committedDocumentId: documentId, frameDocuments: new Map(), expectedUrls: new Map(), frames: new Map(), frameInventory: null, requestedFrames: new Map() };
    if (url && documentId) state.expectedUrls.set(0, url);
    tabs.set(tabId, state);
    clearStored(tabId);
    updateAction(tabId, null, /^(?:https?|file):/i.test(url));
    return state;
  }

  function publicOrigin(url) {
    try { return new URL(url).origin; } catch (_) { return ''; }
  }

  function options() {
    return new Promise((resolve) => {
      try { api.storage.local.get(['phishguard_options'], (data) => {
        const saved = !api.runtime.lastError && data && data.phishguard_options || {};
        const value = Number(saved.warningThreshold);
        resolve({ ...saved, warningThreshold: Number.isFinite(value) ? Math.max(35, Math.min(90, value)) : 65 });
      }); } catch (_) { resolve({ warningThreshold: 65, reputationEnabled: false }); }
    });
  }

  function analyzePage(features, settings = {}) {
    const policyStarted = monotonicNow();
    const verdict = self.PhishGuard.scoreEvidence(features, settings);
    return {
      score: verdict.score,
      outcome: verdict.outcome,
      label: titles[verdict.outcome],
      risk: { label: verdict.outcome, title: titles[verdict.outcome] },
      warning: verdict.outcome === 'HIGH_RISK',
      reasons: verdict.reasons,
      evidence: verdict.evidence,
      metadata: {
        outcome: verdict.outcome,
        rule_score: verdict.score,
        evidence_score: verdict.score,
        evidence_categories: verdict.categories,
        active_evidence_categories: verdict.activeCategories,
        normal_first_party_login: verdict.normalFirstPartyLogin,
        policy_version: verdict.policyVersion || '0.6.0',
        warning_threshold: verdict.warningThreshold || settings.warningThreshold || 65,
        model_version: 'rules-0.6.0',
        trained_model_applied: false,
        character_model_applied: false,
        model_influence: 'disabled_pending_compatible_calibration',
        runtime_timing: { policy_ms: duration(monotonicNow() - policyStarted) },
        inspection_limits: [
          ...(features.runtime_coverage && features.runtime_coverage.visibility_watch_truncated ? ['visibility_watch_truncated'] : []),
          ...(Array.isArray(features.credential_contexts) && features.credential_contexts.some((context) => context.credential_destination_unknown === 1) ? ['credential_destination_unknown'] : [])
        ]
      }
    };
  }

  // An explicit feature check, separate from phishing evidence and its score.
  // Match the browser-supplied address, never page text, titles or payload URLs.
  function officialSecurityTest(browserUrl) {
    try {
      const url = new URL(browserUrl);
      if (url.protocol !== 'https:' || url.port || url.username || url.password) return null;
      if (['amtso.org', 'www.amtso.org'].includes(url.hostname)
          && /^\/check-desktop-phishing-page\/?$/.test(url.pathname)) {
        return { id: 'amtso-phishing-feature-check', name: 'AMTSO phishing feature check',
          explanation: 'This is a harmless official phishing-protection test URL. Recognition comes from a built-in test entry, not evidence of credential theft.' };
      }
    } catch (_) { /* Invalid or non-web addresses are not test entries. */ }
    return null;
  }

  function current(tabId, frameId, record) {
    return tabs.get(tabId)?.frames.get(frameId) === record;
  }

  function getFrames(tabId) {
    return new Promise((resolve) => {
      if (!api.webNavigation || !api.webNavigation.getAllFrames) { resolve(null); return; }
      try {
        api.webNavigation.getAllFrames({ tabId }, (frames) => {
          if (api.runtime.lastError) { resolve(null); return; }
          resolve(Array.isArray(frames) ? frames : null);
        });
      } catch (_) { resolve(null); }
    });
  }

  function matchesFrame(frame, record) {
    return frame && (!frame.documentId || !record.documentId || frame.documentId === record.documentId)
      && (!frame.url || frame.url === record.identity.url)
      && (!frame.documentLifecycle || frame.documentLifecycle === 'active');
  }

  function reconcileFrames(state, frames) {
    if (!frames) { state.frameInventory = null; return false; }
    state.frameInventory = frames;
    const byId = new Map(frames.map((frame) => [frame.frameId, frame]));
    let changed = false;
    for (const [id, existing] of state.frames) {
      if (!matchesFrame(byId.get(id), existing)) { state.frames.delete(id); changed = true; }
    }
    return changed;
  }

  function inspectableFrame(frame) {
    return (!frame.documentLifecycle || frame.documentLifecycle === 'active')
      && /^(?:https?:|file:|blob:https?:|about:(?:blank|srcdoc)(?:[?#]|$))/.test(frame.url || '');
  }

  function requestMissingFrames(tabId, state) {
    if (!state.frameInventory || tabs.get(tabId) !== state) return;
    const liveIds = new Set(state.frameInventory.map((frame) => frame.frameId));
    for (const id of state.requestedFrames.keys()) if (!liveIds.has(id)) state.requestedFrames.delete(id);
    for (const frame of state.frameInventory) {
      if (!inspectableFrame(frame) || state.frames.has(frame.frameId)) continue;
      const key = `${frame.documentId || ''}:${frame.url}`;
      const prior = state.requestedFrames.get(frame.frameId);
      if (prior && prior.key === key && Date.now() - prior.at < 3000) continue;
      state.requestedFrames.set(frame.frameId, { key, at: Date.now() });
      quietSend(tabId, { type: 'REQUEST_RESCAN' }, { frameId: frame.frameId });
    }
  }

  function aggregate(state) {
    const top = state.frames.get(0);
    if (!top || !top.result) return null;
    const order = { SAFE: 0, CAUTION: 1, HIGH_RISK: 2 };
    let selected = top;
    let selectedFrameId = 0;
    for (const [frameId, record] of state.frames) {
      if (!record.result) continue;
      if (order[record.result.outcome] > order[selected.result.outcome]
          || (record.result.outcome === selected.result.outcome && record.result.score > selected.result.score)) {
        selected = record;
        selectedFrameId = frameId;
      }
    }
    const inspectedFrames = [...state.frames.values()].filter((frame) => frame.result).length;
    const uninspectedFrames = state.frameInventory
      ? state.frameInventory.filter((frame) => !state.frames.get(frame.frameId)?.result).length : null;
    const pendingFrames = state.frameInventory
      ? state.frameInventory.filter((frame) => inspectableFrame(frame) && !state.frames.get(frame.frameId)?.result).length : 0;
    const limitations = [...new Set([...state.frames.values()].flatMap((frame) => frame.result?.metadata?.inspection_limits || []))];
    const reputationCoverage = { disabled: 0, pending: 0, available: 0, error: 0 };
    for (const frame of state.frames.values()) {
      if (frame.result && Object.prototype.hasOwnProperty.call(reputationCoverage, frame.result.reputationStatus)) reputationCoverage[frame.result.reputationStatus] += 1;
    }
    const result = {
      ...selected.result,
      reasons: [...selected.result.reasons],
      identity: { ...top.identity },
      pageOrigin: publicOrigin(top.identity.contextUrl || top.identity.url),
      inspectedFrames,
      reputationCoverage,
      reputationStatus: reputationCoverage.error ? 'error' : reputationCoverage.pending ? 'pending' : reputationCoverage.available ? 'available' : 'disabled',
      coverage: { uninspectedFrames, inventoryAvailable: !!state.frameInventory, pendingFrames,
        recovering: pendingFrames > 0, complete: !!state.frameInventory && uninspectedFrames === 0 && limitations.length === 0, limitations },
      evidenceFrame: { frameId: selectedFrameId, origin: publicOrigin(selected.identity.contextUrl || selected.identity.url) }
    };
    result.inspectionScope = { formDestinations: 'declared_only', scriptDataFlow: 'not_verified',
      closedShadowRoots: 'not_inspected', visualIdentity: 'not_verified', protection: 'advisory' };
    if (state.runtimeTiming && state.runtimeTiming.scanId === top.identity.scanId) {
      result.runtimeTiming = { ...state.runtimeTiming.values };
      if (result.outcome !== 'HIGH_RISK' && !result.securityTest) delete result.runtimeTiming.scan_to_warning_dom_ms;
    }
    if (selectedFrameId !== 0 && result.outcome !== 'SAFE') {
      result.reasons.unshift(`An embedded frame (${result.evidenceFrame.origin}) has these indicators.`);
      result.reasons = result.reasons.slice(0, 6);
    }
    return result;
  }

  function publish(tabId, notify = true) {
    const state = tabs.get(tabId);
    const result = state && aggregate(state);
    if (!result) { clearStored(tabId); updateAction(tabId, null, !!state && /^(?:https?|file):/i.test(state.topUrl)); return null; }
    // Exact URLs stay in worker/content-script memory for identity checks only.
    const stored = { ...result, identity: { documentToken: result.identity.documentToken, scanId: result.identity.scanId }, createdAt: Date.now() };
    sessionUpdate('set', { [`tab_${tabId}`]: stored });
    updateAction(tabId, result);
    if (notify) quietSend(tabId, { type: 'ANALYZE_RESULT', payload: result });
    return result;
  }

  async function prepareReputation(hostname, settings, revision) {
    if (!settings.reputationEnabled) return { initial: { status: 'disabled' } };
    let endpoint;
    try {
      endpoint = new URL(settings.reputationEndpoint);
      if (!hostname || endpoint.username || endpoint.password || endpoint.hash
          || (endpoint.protocol !== 'https:' && !(endpoint.protocol === 'http:' && ['localhost', '127.0.0.1', '[::1]'].includes(endpoint.hostname)))) throw new Error();
      endpoint.hash = '';
    } catch (_) { return { initial: { status: 'error', error: 'configuration' } }; }
    await cacheReady;
    // SHA-256 avoids storing the endpoint's path/query/API key in session output.
    let endpointKey;
    try {
      endpointKey = Array.from(new Uint8Array(await self.crypto.subtle.digest('SHA-256', new TextEncoder().encode(endpoint.href))))
        .map((byte) => byte.toString(16).padStart(2, '0')).join('');
    } catch (_) { return { initial: { status: 'error', error: 'configuration' } }; }
    if (revision !== configurationRevision) return { initial: { status: 'disabled' } };
    let pruned = false;
    for (const [cacheKey, entry] of reputationCache) if (entry.expiresAt <= Date.now()) { reputationCache.delete(cacheKey); pruned = true; }
    if (pruned) persistReputation();
    const key = `${endpointKey}:${hostname}`;
    const cached = reputationCache.get(key);
    if (cached && cached.expiresAt > Date.now()) return { initial: cached };
    if (reputationInflight.has(key)) return { initial: { status: 'pending' }, completion: reputationInflight.get(key) };
    const now = Date.now();
    while (reputationStarts.length && reputationStarts[0] <= now - 60000) reputationStarts.shift();
    if (reputationInflight.size >= 4 || reputationStarts.length >= 30) return { initial: { status: 'error', error: 'rate_limited' } };
    reputationStarts.push(now);
    endpoint.searchParams.set('hostname', hostname);
    const controller = new AbortController();
    reputationControllers.add(controller);
    const timer = setTimeout(() => controller.abort(), 5000);
    const completion = Promise.resolve().then(async () => {
      let report;
      try {
        const response = await fetch(endpoint, { credentials: 'omit', redirect: 'error', cache: 'no-store', headers: { Accept: 'application/json' }, signal: controller.signal });
        if (!response.ok) report = { status: 'error', error: 'http' };
        else {
          const value = await response.json();
          if (!value || typeof value !== 'object' || Array.isArray(value)) report = { status: 'error', error: 'invalid_response' };
          else {
            const verdict = typeof value.verdict === 'string' ? value.verdict.trim().toLowerCase()
              : value.malicious === true ? 'malicious' : value.malicious === false ? 'unknown' : '';
            report = ['malicious', 'phishing', 'safe', 'benign', 'unknown'].includes(verdict)
              ? { status: 'available', verdict } : { status: 'error', error: 'invalid_response' };
          }
        }
      } catch (_) { report = { status: 'error', error: 'network' }; }
      finally {
        clearTimeout(timer); reputationControllers.delete(controller);
        if (reputationInflight.get(key) === completion) reputationInflight.delete(key);
      }
      if (revision !== configurationRevision) return null;
      if (controller.signal.aborted) report = { status: 'error', error: 'network' };
      const ttl = report.status === 'error' ? 15000 : ['malicious', 'phishing'].includes(report.verdict) ? 600000 : report.verdict === 'unknown' ? 30000 : 300000;
      report = { ...report, endpointKey, hostname, checkedAt: Date.now(), expiresAt: Date.now() + ttl };
      reputationCache.delete(key);
      reputationCache.set(key, report);
      while (reputationCache.size > MAX_CACHE) reputationCache.delete(reputationCache.keys().next().value);
      persistReputation();
      return report;
    });
    reputationInflight.set(key, completion);
    return { initial: { status: 'pending' }, completion };
  }

  function withReputation(base, report) {
    const result = { ...base, reasons: [...base.reasons], evidence: [...base.evidence], metadata: { ...base.metadata },
      reputationStatus: report.status, reputationError: report.error || null };
    if (report.status !== 'available') return result;
    result.metadata.reputation = { verdict: report.verdict, checkedAt: report.checkedAt, expiresAt: report.expiresAt,
      source: 'user_configured_endpoint', scope: 'hostname_only' };
    if (!['malicious', 'phishing'].includes(report.verdict)) return result;
    result.score = Math.max(90, result.score);
    result.outcome = 'HIGH_RISK';
    result.metadata.outcome = 'HIGH_RISK';
    result.label = titles.HIGH_RISK;
    result.risk = { label: 'HIGH_RISK', title: titles.HIGH_RISK };
    result.warning = true;
    result.reasons = ['The configured reputation service reports this hostname as malicious.', ...(base.outcome === 'SAFE' ? [] : base.reasons)].slice(0, 5);
    result.evidence.push({ key: 'hostname_reputation', category: 'reputation', points: 90, reason: result.reasons[0] });
    return result;
  }

  async function scan(message, sender) {
    const workerStarted = monotonicNow();
    const tabId = sender.tab && sender.tab.id;
    const frameId = Number(sender.frameId) || 0;
    const identity = message.identity;
    if (!Number.isInteger(tabId) || !identity || typeof identity.documentToken !== 'string' || !identity.documentToken.length
        || identity.documentToken.length > 128 || !Number.isSafeInteger(identity.scanId) || identity.scanId < 1) return null;
    let url;
    let contextUrl;
    try {
      url = new URL(identity.url);
      contextUrl = url;
      if (!['http:', 'https:', 'file:'].includes(url.protocol)) {
        if (!((url.protocol === 'about:' && ['blank', 'srcdoc'].includes(url.pathname)) || url.protocol === 'blob:')) return null;
        contextUrl = new URL(identity.contextUrl);
        // MessageSender.origin is browser supplied, unlike document markup/baseURI.
        if (!['http:', 'https:'].includes(contextUrl.protocol) || !sender.origin || sender.origin !== contextUrl.origin) return null;
      }
      if (sender.url && sender.url !== identity.url && new URL(sender.url).origin !== url.origin) return null;
    } catch (_) { return null; }
    let state = tabs.get(tabId);
    if (!state) state = resetTab(tabId);
    if (frameId === 0 && state.committedDocumentId && sender.documentId && state.committedDocumentId !== sender.documentId) return null;
    if (state.frameDocuments.has(frameId) && sender.documentId && state.frameDocuments.get(frameId) !== sender.documentId) return null;
    if (state.expectedUrls.has(frameId) && state.expectedUrls.get(frameId) !== identity.url) return null;
    const previous = state.frames.get(frameId);
    if (previous) {
      if (previous.committedDocumentId && sender.documentId && previous.committedDocumentId !== sender.documentId) return null;
      if (previous.identity.documentToken === identity.documentToken && previous.identity.scanId >= identity.scanId) return null;
      if (previous.identity.documentToken !== identity.documentToken) {
        if (!sender.documentId || previous.documentId === sender.documentId) return null;
        if (frameId === 0) state = resetTab(tabId, identity.url, sender.documentId);
      }
    }
    // Replace the record before awaiting settings/network so an older request cannot win.
    const record = { identity: { documentToken: identity.documentToken, scanId: identity.scanId, url: identity.url,
      contextUrl: contextUrl.href }, documentId: sender.documentId, result: null };
    state.frames.set(frameId, record);
    state.requestedFrames.delete(frameId);
    state.expectedUrls.delete(frameId);
    if (frameId === 0) state.topUrl = identity.url;
    if (frameId === 0 && !previous) updateAction(tabId, null, true);
    const revision = configurationRevision;
    const [settings, frames] = await Promise.all([options(), getFrames(tabId)]);
    if (!current(tabId, frameId, record) || revision !== configurationRevision) return null;
    if (!frames) state.frameInventory = null;
    if (frames) {
      const active = frames.find((frame) => frame.frameId === frameId);
      if (!matchesFrame(active, record)) {
        state.frames.delete(frameId);
        publish(tabId);
        return null;
      }
      reconcileFrames(state, frames);
      requestMissingFrames(tabId, state);
    }
    const features = { ...(message.payload || {}), url: contextUrl.href };
    const baseResult = analyzePage(features, settings);
    const extractionMs = duration(message.performance && message.performance.extraction_ms);
    if (extractionMs !== null) baseResult.metadata.runtime_timing.extraction_ms = extractionMs;
    const securityTest = frameId === 0 && sender.url === identity.url ? officialSecurityTest(sender.url) : null;
    if (securityTest) {
      baseResult.securityTest = securityTest;
      baseResult.warning = true;
      baseResult.metadata.security_test_recognized = true;
    }
    const remote = await prepareReputation(contextUrl.hostname, settings, revision);
    if (!current(tabId, frameId, record) || revision !== configurationRevision) return null;
    baseResult.metadata.runtime_timing.worker_ms = duration(monotonicNow() - workerStarted);
    record.result = withReputation(baseResult, remote.initial);
    const result = publish(tabId);
    // Do not hold the response open while a remote service runs.
    if (remote.completion) remote.completion.then((report) => {
      if (!report || revision !== configurationRevision || !current(tabId, frameId, record)) return;
      record.result = withReputation(baseResult, report);
      publish(tabId);
    }).catch(() => {});
    return result;
  }

  api.runtime.onMessage.addListener((message, sender, respond) => {
    if (!message) return;
    if (message.type === 'REPORT_RENDER_METRICS') {
      const tabId = sender.tab && sender.tab.id;
      const state = tabs.get(tabId);
      const top = state && state.frames.get(0);
      const identity = message.identity;
      // MessageSender.url can retain the document's original URL after
      // pushState. Browser documentId plus same origin binds that SPA report.
      const senderMatches = top && (sender.url === top.identity.url || (top.documentId
        && sender.documentId === top.documentId && publicOrigin(sender.url) === publicOrigin(top.identity.url)));
      if (!top || !top.result || sender.frameId !== 0 || !identity
          || identity.documentToken !== top.identity.documentToken || identity.scanId !== top.identity.scanId
          || !senderMatches || (top.documentId && sender.documentId !== top.documentId)) {
        respond({ accepted: false }); return;
      }
      const values = {};
      for (const name of ['scan_to_result_ms', 'scan_to_warning_dom_ms', 'scheduling_delay_ms']) {
        const value = duration(message.performance && message.performance[name]);
        if (value !== null) values[name] = value;
      }
      if (!Object.prototype.hasOwnProperty.call(values, 'scan_to_result_ms')) { respond({ accepted: false }); return; }
      const result = aggregate(state);
      if (result.outcome !== 'HIGH_RISK' && !result.securityTest) delete values.scan_to_warning_dom_ms;
      state.runtimeTiming = { scanId: identity.scanId, values };
      publish(tabId, false);
      respond({ accepted: true }); return;
    }
    if (message.type === 'REQUEST_TAB_RESCAN' && Number.isInteger(message.tabId)) {
      // A popup can ask for a new scan only for the exact current document.
      // Checking browser inventory avoids sending an obsolete popup request to
      // a different site after navigation. Never report a requested scan as done.
      getFrames(message.tabId).then((frames) => {
        const top = frames && frames.find((frame) => frame.frameId === 0);
        if (!top || top.url !== message.url || !/^(?:https?|file):/i.test(top.url)) {
          respond({ requested: false }); return;
        }
        quietSend(message.tabId, { type: 'REQUEST_RESCAN', reason: 'user' }, {});
        respond({ requested: true });
      }).catch(() => respond({ requested: false }));
      return true;
    }
    if (message.type === 'ANALYZE_PAGE') {
      scan(message, sender).then((payload) => respond(payload ? { type: 'ANALYZE_RESULT', payload } : { ignored: true })).catch(() => respond({ ignored: true }));
      return true;
    }
    if (message.type === 'GET_TAB_RESULT' && Number.isInteger(message.tabId)) {
      const state = tabs.get(message.tabId);
      // URL supplied by the popup is checked in memory and never persisted.
      getFrames(message.tabId).then((frames) => {
        if (state && tabs.get(message.tabId) === state) {
          if (reconcileFrames(state, frames)) publish(message.tabId);
          requestMissingFrames(message.tabId, state);
        }
        const result = state && tabs.get(message.tabId) === state && state.topUrl === message.url ? aggregate(state) : null;
        updateAction(message.tabId, result, !result && !!state && /^(?:https?|file):/i.test(state.topUrl));
        respond({ result });
        if (!result) quietSend(message.tabId, { type: 'REQUEST_RESCAN' }, {});
      }).catch(() => respond({ result: null }));
      return true;
    }
  });

  if (api.tabs.onRemoved) api.tabs.onRemoved.addListener((tabId) => { tabs.delete(tabId); clearStored(tabId); updateAction(tabId); actionStates.delete(tabId); });
  if (api.tabs.onUpdated) api.tabs.onUpdated.addListener((tabId, change) => {
    if (change.status === 'loading') resetTab(tabId, change.url || '');
    // A restored cached page can finish loading after its pageshow scan. Ask all
    // surviving content scripts again so a late loading event cannot erase it.
    if (change.status === 'complete') quietSend(tabId, { type: 'REQUEST_RESCAN' }, {});
  });
  if (api.webNavigation) {
    api.webNavigation.onCommitted.addListener((event) => {
      if (event.frameId === 0) resetTab(event.tabId, event.url, event.documentId);
      else {
        const state = tabs.get(event.tabId);
        if (state) {
          state.frames.delete(event.frameId);
          if (event.documentId) state.frameDocuments.set(event.frameId, event.documentId);
          state.expectedUrls.set(event.frameId, event.url);
          publish(event.tabId);
        }
      }
    });
    const locationChanged = (event) => {
      const state = tabs.get(event.tabId);
      if (state) {
        state.frames.delete(event.frameId);
        state.expectedUrls.set(event.frameId, event.url);
        if (event.frameId === 0) { state.topUrl = event.url; clearStored(event.tabId); updateAction(event.tabId, null, true); }
        else publish(event.tabId);
      }
      else if (event.frameId === 0) updateAction(event.tabId, null, true);
      quietSend(event.tabId, { type: 'REQUEST_RESCAN' }, { frameId: event.frameId });
    };
    api.webNavigation.onHistoryStateUpdated.addListener(locationChanged);
    if (api.webNavigation.onReferenceFragmentUpdated) api.webNavigation.onReferenceFragmentUpdated.addListener(locationChanged);
    if (api.webNavigation.onErrorOccurred) api.webNavigation.onErrorOccurred.addListener((event) => {
      const state = tabs.get(event.tabId);
      if (!state) return;
      // Aborted navigations can leave the old document active. Reconcile browser
      // identity rather than deleting a valid result based on the failed URL.
      getFrames(event.tabId).then((frames) => {
        if (tabs.get(event.tabId) !== state) return;
        if (reconcileFrames(state, frames)) publish(event.tabId);
        quietSend(event.tabId, { type: 'REQUEST_RESCAN' }, {});
      }).catch(() => {});
    });
  }
  if (api.storage.onChanged) api.storage.onChanged.addListener((changes, area) => {
    if (area !== 'local' || !changes.phishguard_options) return;
    configurationRevision += 1;
    for (const controller of reputationControllers) controller.abort();
    reputationControllers.clear();
    reputationInflight.clear();
    const previous = changes.phishguard_options.oldValue || {};
    const next = changes.phishguard_options.newValue || {};
    if (Boolean(previous.reputationEnabled) !== Boolean(next.reputationEnabled) || previous.reputationEndpoint !== next.reputationEndpoint) {
      reputationCache.clear();
      sessionUpdate('remove', CACHE_KEY);
    }
    for (const tabId of tabs.keys()) quietSend(tabId, { type: 'REQUEST_RESCAN' }, {});
  });
  // Remove legacy persistent scan records (including query strings) on upgrade/start.
  api.storage.local.get(null, (data) => {
    if (!(data && data.phishguard_options && data.phishguard_options.reputationEnabled)) cacheReady.then(() => {
      if (configurationRevision === 0) { reputationCache.clear(); sessionUpdate('remove', CACHE_KEY); }
    });
    const keys = Object.keys(data || {}).filter((key) => /^tab_\d+$/.test(key));
    if (keys.length) api.storage.local.remove(keys);
    if (Array.isArray(data && data.phishguard_feedback)) {
      const sanitized = self.PhishGuard.sanitizeFeedback(data.phishguard_feedback);
      api.storage.local.set({ phishguard_feedback: sanitized });
    }
  });
})();
