const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { JSDOM } = require('jsdom');
const root = path.resolve(__dirname, '../..');
const tick = () => new Promise((resolve) => setImmediate(resolve));

function event() {
  const listeners = [];
  return { addListener: (fn) => listeners.push(fn), emit: (...args) => listeners.forEach((fn) => fn(...args)), listeners };
}

function worker(settings = {}, persistedSession = {}) {
  const local = { phishguard_options: settings, tab_99: { url: 'https://legacy.test/?private=old' }, phishguard_feedback: [{ tab: 'https://legacy.test/?secret' }] };
  const session = persistedSession;
  const sends = [];
  const requests = [];
  const scoredSettings = [];
  const action = { text: '', title: '', color: '' };
  let liveFrames = null;
  const storageArea = (data) => ({
    get: (keys, cb) => cb(keys === null ? { ...data } : Object.fromEntries(keys.map((key) => [key, data[key]]))),
    set: (values, cb) => { Object.assign(data, structuredClone(values)); if (cb) cb(); },
    remove: (keys) => { for (const key of Array.isArray(keys) ? keys : [keys]) delete data[key]; }
  });
  const chrome = {
    action: { setBadgeText: ({ text }) => { action.text = text; return Promise.resolve(); },
      setBadgeBackgroundColor: ({ color }) => { action.color = color; return Promise.resolve(); },
      setTitle: ({ title }) => { action.title = title; return Promise.resolve(); } },
    runtime: { onMessage: event() },
    storage: { local: storageArea(local), session: storageArea(session), onChanged: event() },
    tabs: { onUpdated: event(), onRemoved: event(), sendMessage: (tabId, message, options) => { sends.push(structuredClone({ tabId, message, options })); return Promise.resolve(); } },
    webNavigation: { onCommitted: event(), onHistoryStateUpdated: event(), onReferenceFragmentUpdated: event(), onErrorOccurred: event(), getAllFrames: (_details, cb) => cb(liveFrames) }
  };
  const context = vm.createContext({ URL, Map, Set, Promise, Number, Object, String, Array, Date, setTimeout, clearTimeout, AbortController,
    crypto: require('node:crypto').webcrypto, TextEncoder, Uint8Array,
    chrome, importScripts: (...files) => { assert.ok(!files.some((file) => /trained-.*data/.test(file)), 'unvalidated model artifacts must not load'); },
    fetch: (url, options) => new Promise((resolve) => requests.push({ url: String(url), options,
      resolve: (verdict) => resolve({ ok: true, json: async () => ({ verdict }) }),
      resolveBody: (body) => resolve({ ok: true, json: async () => body }) })) });
  context.self = context;
  context.PhishGuard = { browser: chrome, sanitizeFeedback: require('../../src/shared/feedback.js').sanitizeFeedback, scoreEvidence: (features, options) => {
    scoredSettings.push(options);
    return { score: features.testScore || 0, outcome: features.testOutcome || 'SAFE', reasons: ['Canonical evidence reason'], evidence: [], categories: {}, activeCategories: [], normalFirstPartyLogin: true };
  } };
  vm.runInContext(fs.readFileSync(path.join(root, 'src/background/service-worker.js'), 'utf8'), context);
  const send = (message, sender = {}) => new Promise((resolve) => chrome.runtime.onMessage.listeners[0](message, sender, resolve));
  const scan = (scanId, features = {}, details = {}) => {
    const frameId = details.frameId || 0;
    const url = details.url || 'https://college.test/login?token=PRIVATE#SECRET';
    return send({ type: 'ANALYZE_PAGE', identity: { documentToken: details.token || `token-${frameId}`, scanId, url, contextUrl: details.contextUrl }, payload: features },
      { tab: { id: details.tabId ?? 0 }, frameId, url, origin: details.origin, documentId: details.documentId || `doc-${frameId}` });
  };
  return { local, session, sends, requests, chrome, send, scan, scoredSettings, action, setFrames: (frames) => { liveFrames = frames; } };
}

async function testBrowserStatusAndTiming() {
  const app = worker();
  const url = 'https://college.test/login?token=PRIVATE#SECRET';
  app.setFrames([{ frameId: 0, url, documentId: 'doc-0' }]);
  await app.scan(1);
  assert.equal(app.action.text, '', 'ordinary complete inspection does not use a reassuring green safety badge');
  assert.match(app.action.title, /safety is not verified/);
  assert.equal(app.session.tab_0.inspectionScope.scriptDataFlow, 'not_verified');
  assert.equal(app.session.tab_0.coverage.complete, true, 'general static-inspection scope does not mark every document incomplete');
  await app.scan(2, { testScore: 35, testOutcome: 'CAUTION' });
  assert.equal(app.action.text, '!');
  assert.match(app.action.title, /Caution/);
  const cautionColor = app.action.color;
  await app.scan(3, { testScore: 80, testOutcome: 'HIGH_RISK' });
  assert.match(app.action.title, /High phishing risk/);
  assert.notEqual(app.action.color, cautionColor);
  assert.doesNotMatch(JSON.stringify(app.action), /PRIVATE|SECRET|college\.test/, 'browser-owned status excludes browsing identifiers');
  const render = { type: 'REPORT_RENDER_METRICS', identity: { documentToken: 'token-0', scanId: 3 },
    performance: { scan_to_result_ms: 10.125, scan_to_warning_dom_ms: 12, scheduling_delay_ms: 600,
      arbitrarySecret: 'NEVER_RETAIN', extraction_ms: -1 } };
  const sender = { tab: { id: 0 }, frameId: 0, documentId: 'doc-0', url };
  const sendsBefore = app.sends.length;
  assert.equal((await app.send(render, sender)).accepted, true);
  assert.equal(app.session.tab_0.runtimeTiming.scan_to_result_ms, 10.13);
  assert.equal(app.session.tab_0.runtimeTiming.scan_to_warning_dom_ms, 12);
  assert.equal(app.sends.length, sendsBefore, 'recording durations cannot echo results into a measurement loop');
  assert.ok(!JSON.stringify(app.session).includes('NEVER_RETAIN'));
  assert.equal((await app.send({ ...render, identity: { ...render.identity, scanId: 2 } }, sender)).accepted, false);
  assert.equal((await app.send(render, { ...sender, documentId: 'obsolete' })).accepted, false);
  assert.equal((await app.send(render, { ...sender, url: 'https://college.test/original' })).accepted, true,
    'browser sender URL can remain at the same document original address after SPA navigation');
  assert.equal((await app.send(render, { ...sender, url: 'https://unrelated.test/' })).accepted, false);
  assert.equal((await app.send(render, { ...sender, frameId: 2 })).accepted, false);
  assert.equal((await app.send({ ...render, performance: { scan_to_result_ms: Infinity } }, sender)).accepted, false);
  app.setFrames([{ frameId: 0, url, documentId: 'doc-0' }, { frameId: 4, url: 'data:text/html,opaque' }]);
  await app.scan(4);
  assert.equal(app.action.text, '?');
  assert.match(app.action.title, /Incomplete inspection/);
  assert.equal(app.session.tab_0.runtimeTiming, undefined, 'timing from an older scan cannot label a new result');
  app.chrome.webNavigation.onHistoryStateUpdated.emit({ tabId: 0, frameId: 0, url: 'https://college.test/new' });
  assert.equal(app.action.text, '...');
  assert.match(app.action.title, /No current verdict/);
  app.chrome.tabs.onUpdated.emit(0, { status: 'loading', url: 'chrome://extensions/' });
  assert.equal(app.action.text, '');
  assert.match(app.action.title, /No current page result/);
  app.chrome.tabs.onRemoved.emit(0);
  assert.equal(app.action.text, '');
  delete app.chrome.action;
  await app.scan(5, { testScore: 80, testOutcome: 'HIGH_RISK' });
  const remote = worker({ reputationEnabled: true, reputationEndpoint: 'https://reputation.test/check' });
  remote.setFrames([{ frameId: 0, url, documentId: 'doc-0' }]);
  await remote.scan(1);
  assert.equal(remote.action.text, '...');
  assert.match(remote.action.title, /reputation pending/);
  remote.requests[0].resolve('malicious');
  await tick(); await tick();
  assert.match(remote.action.title, /High phishing risk/);
  assert.equal(remote.session.tab_0.metadata.reputation.source, 'user_configured_endpoint');
  assert.equal(remote.session.tab_0.metadata.reputation.scope, 'hostname_only');
  assert.ok(remote.session.tab_0.metadata.reputation.expiresAt > remote.session.tab_0.metadata.reputation.checkedAt);
}

async function testWorker() {
  const officialTest = worker();
  const officialUrl = 'https://www.amtso.org/check-desktop-phishing-page/';
  const official = (await officialTest.scan(1, {}, { url: officialUrl })).payload;
  assert.equal(official.securityTest.id, 'amtso-phishing-feature-check');
  assert.equal(official.warning, true);
  assert.equal(official.score, 0, 'A test URL match must not fabricate phishing evidence');
  assert.equal(official.outcome, 'SAFE', 'The structural outcome remains separate from the feature check');
  assert.equal(official.metadata.security_test_recognized, true);
  for (const url of ['https://amtso.org/', 'https://amtso.org/check-desktop-phishing-page/other',
    'https://amtso.org.evil.test/check-desktop-phishing-page/', 'http://www.amtso.org/check-desktop-phishing-page/',
    'https://www.amtso.org:8443/check-desktop-phishing-page/']) {
    const ordinary = worker();
    assert.equal((await ordinary.scan(1, { url: officialUrl }, { url })).payload.securityTest, undefined, url);
  }
  const framedTest = worker();
  await framedTest.scan(1);
  assert.equal((await framedTest.scan(1, {}, { url: officialUrl, frameId: 2 })).payload.securityTest, undefined,
    'An embedded test URL cannot change the top-level page into an official test');
  const manualScan = worker();
  manualScan.setFrames([{ frameId: 0, url: 'https://current.test/login' }, { frameId: 2, url: 'https://embedded.test/' }]);
  assert.equal((await manualScan.send({ type: 'REQUEST_TAB_RESCAN', tabId: 1, url: 'https://old.test/' })).requested, false);
  assert.equal(manualScan.sends.length, 0, 'stale popup requests must not rescan a different document');
  assert.equal((await manualScan.send({ type: 'REQUEST_TAB_RESCAN', tabId: 1, url: 'https://current.test/login' })).requested, true);
  assert.equal(manualScan.sends.length, 1);
  assert.equal(manualScan.sends[0].message.type, 'REQUEST_RESCAN');
  assert.deepEqual(manualScan.sends[0].options, {}, 'user rescan reaches all document frames');
  manualScan.setFrames([{ frameId: 0, url: 'file:///C:/local/demo.html' }]);
  assert.equal((await manualScan.send({ type: 'REQUEST_TAB_RESCAN', tabId: 1, url: 'file:///C:/local/demo.html' })).requested, true);
  manualScan.setFrames([{ frameId: 0, url: 'chrome://extensions/' }]);
  assert.equal((await manualScan.send({ type: 'REQUEST_TAB_RESCAN', tabId: 1, url: 'chrome://extensions/' })).requested, false);
  manualScan.setFrames(null);
  assert.equal((await manualScan.send({ type: 'REQUEST_TAB_RESCAN', tabId: 1, url: 'https://current.test/login' })).requested, false);
  const app = worker({ reputationEnabled: true, reputationEndpoint: 'https://reputation.test/check', warningThreshold: 88 });
  assert.equal(app.local.tab_99, undefined, 'legacy persistent URLs removed');
  assert.deepEqual(app.local.phishguard_feedback, [], 'legacy full-URL feedback removed');
  let response = await app.scan(1, { testScore: 90, testOutcome: 'CAUTION' });
  assert.equal(response.payload.outcome, 'CAUTION');
  assert.equal(response.payload.warning, false, 'worker must use canonical outcome even for high numeric scores');
  assert.equal(response.payload.risk.label, 'CAUTION');
  assert.deepEqual(Array.from(response.payload.reasons), ['Canonical evidence reason']);
  assert.equal(app.scoredSettings[0].warningThreshold, 88, 'configured threshold reaches scoring policy');
  assert.equal(response.payload.metadata.trained_model_applied, false);
  assert.equal(app.requests.length, 1);
  assert.equal(new URL(app.requests[0].url).searchParams.get('hostname'), 'college.test');
  assert.ok(!app.requests[0].url.includes('PRIVATE'), 'reputation only sends hostname');

  await app.scan(2);
  assert.equal(app.requests.length, 1, 'same hostname shares its in-flight request');
  app.requests[0].resolve('unknown');
  await tick();
  assert.equal(app.session.tab_0.outcome, 'SAFE', 'shared report is applied only to the current scan');
  assert.ok(!JSON.stringify(app.session).includes('PRIVATE') && !JSON.stringify(app.session).includes('SECRET'), 'session storage must omit full paths/query/hash');
  assert.equal((await app.scan(1)).ignored, true, 'out of order scan is ignored');

  await app.scan(1, { testScore: 80, testOutcome: 'HIGH_RISK' }, { frameId: 4, url: 'https://embedded.test/phish' });
  assert.equal(app.session.tab_0.outcome, 'HIGH_RISK', 'risky embedded frame reaches the top document');
  assert.equal(app.session.tab_0.evidenceFrame.frameId, 4);
  assert.equal(app.sends.at(-1).options.frameId, 0);
  app.requests.at(-1).resolve('unknown');
  app.setFrames([{ frameId: 0 }]);
  await app.scan(3);
  app.requests.at(-1).resolve('unknown');
  assert.equal(app.session.tab_0.outcome, 'SAFE', 'removed iframe cannot leave its warning behind');
  assert.equal(app.session.tab_0.inspectedFrames, 1);

  app.chrome.webNavigation.onCommitted.emit({ tabId: 0, frameId: 0, url: 'https://new.test/', documentId: 'new-doc' });
  assert.equal((await app.scan(4)).ignored, true, 'old browser document is rejected after navigation');
  await app.scan(1, {}, { token: 'new-token', documentId: 'new-doc', url: 'https://new.test/' });
  const oldPending = app.requests.at(-1);
  app.chrome.webNavigation.onHistoryStateUpdated.emit({ tabId: 0, frameId: 0, url: 'https://new.test/account', documentId: 'new-doc' });
  assert.equal((await app.scan(99, {}, { token: 'new-token', documentId: 'new-doc', url: 'https://new.test/' })).ignored, true, 'queued pre-navigation scans cannot occupy new SPA identity');
  oldPending.resolve('malicious');
  await tick();
  assert.equal(app.session.tab_0, undefined, 'old SPA-location reputation is discarded');
  assert.equal(app.sends.at(-1).message.type, 'REQUEST_RESCAN', 'main-world SPA event requests content rescan');
  await app.scan(2, {}, { token: 'new-token', documentId: 'new-doc', url: 'https://new.test/account' });
  app.requests.at(-1).resolve('unknown');
  app.chrome.tabs.onRemoved.emit(0);
  assert.equal(app.session.tab_0, undefined, 'closed tabs are cleaned up');
  await tick();

  const independent = worker();
  await independent.scan(1, { testScore: 40, testOutcome: 'CAUTION' });
  await independent.scan(1, { testScore: 40, testOutcome: 'CAUTION' }, { frameId: 7, url: 'https://other.test/' });
  assert.equal(independent.session.tab_0.score, 40, 'unrelated frame scores must never be added together');
  assert.equal(independent.session.tab_0.outcome, 'CAUTION');
  independent.setFrames([{ frameId: 0, documentId: 'doc-0' }, { frameId: 7, documentId: 'replacement-doc' }]);
  assert.equal((await independent.scan(2, { testScore: 99, testOutcome: 'HIGH_RISK' }, { frameId: 7, url: 'https://other.test/' })).ignored, true, 'browser inventory rejects a destroyed document even when its frame ID is reused');

  const reported = worker({ reputationEnabled: true, reputationEndpoint: 'https://reputation.test/check' });
  await reported.scan(1);
  reported.requests[0].resolve('malicious');
  await tick();
  assert.equal(reported.session.tab_0.outcome, 'HIGH_RISK');
  assert.equal(reported.session.tab_0.warning, true);
  assert.equal(reported.session.tab_0.metadata.outcome, 'HIGH_RISK');
  assert.equal(reported.session.tab_0.reasons.length, 1, 'malicious reputation must not keep a normal-login reassurance');

  const optedOut = worker({ reputationEnabled: true, reputationEndpoint: 'https://reputation.test/check' });
  await optedOut.scan(1);
  optedOut.local.phishguard_options = { reputationEnabled: false };
  optedOut.chrome.storage.onChanged.emit({ phishguard_options: { newValue: optedOut.local.phishguard_options } }, 'local');
  assert.equal(optedOut.requests[0].options.signal.aborted, true, 'disabling reputation immediately aborts in-flight network requests');
  optedOut.requests[0].resolve('malicious');
  await tick();
  assert.equal(optedOut.session.tab_0.outcome, 'SAFE', 'a response arriving after opt-out must not change the verdict');
  await optedOut.scan(2);
  assert.equal(optedOut.requests.length, 1, 'rescanning after opt-out makes no new network request');

  const malformed = worker({ reputationEnabled: true, reputationEndpoint: 'https://reputation.test/check' });
  await malformed.scan(1);
  malformed.requests[0].resolveBody({ malicious: 'false' });
  await tick();
  assert.equal(malformed.session.tab_0.outcome, 'SAFE', 'a truthy string is not a malicious boolean verdict');

  const coverage = worker();
  const topUrl = 'https://college.test/login?token=PRIVATE#SECRET';
  coverage.setFrames([{ frameId: 0, documentId: 'doc-0', url: topUrl }, { frameId: 3, documentId: 'doc-3', url: 'about:srcdoc' }]);
  await coverage.scan(1);
  assert.equal(coverage.session.tab_0.coverage.uninspectedFrames, 1, 'inherited frames without content-script coverage are disclosed');
  assert.equal(coverage.session.tab_0.score, 0, 'limited coverage is not invented phishing evidence');
  coverage.setFrames([{ frameId: 0, documentId: 'doc-0', url: topUrl }, { frameId: 3, documentId: 'doc-3', url: 'https://embedded.test/' }]);
  await coverage.scan(1, { testOutcome: 'HIGH_RISK', testScore: 90 }, { frameId: 3, url: 'https://embedded.test/' });
  assert.equal(coverage.session.tab_0.outcome, 'HIGH_RISK');
  coverage.setFrames([{ frameId: 0, documentId: 'doc-0', url: topUrl }]);
  response = await coverage.send({ type: 'GET_TAB_RESULT', tabId: 0, url: topUrl });
  assert.equal(response.result.outcome, 'SAFE', 'opening the popup reconciles frames even if the removed frame was in an unobserved tree');
  assert.equal(response.result.coverage.uninspectedFrames, 0);
  coverage.chrome.webNavigation.onReferenceFragmentUpdated.emit({ tabId: 0, frameId: 0, url: `${topUrl}-updated`, documentId: 'doc-0' });
  assert.equal(coverage.session.tab_0, undefined, 'hash navigation invalidates an old URL result');
  assert.equal(coverage.sends.at(-1).message.type, 'REQUEST_RESCAN');
  coverage.setFrames([{ frameId: 0, documentId: 'doc-0', url: `${topUrl}-updated` }]);
  assert.equal((await coverage.scan(99)).ignored, true, 'queued old hash scans are rejected');
  await coverage.scan(2, {}, { url: `${topUrl}-updated` });
  coverage.chrome.webNavigation.onErrorOccurred.emit({ tabId: 0, frameId: 0, url: 'https://failed.test/' });
  await tick();
  assert.equal(coverage.session.tab_0.outcome, 'SAFE', 'an aborted navigation retains the still-active document result');
  coverage.chrome.tabs.onUpdated.emit(0, { status: 'loading' });
  coverage.chrome.tabs.onUpdated.emit(0, { status: 'complete' });
  assert.equal(coverage.sends.at(-1).message.type, 'REQUEST_RESCAN', 'completion recovers a cached page when a late loading event cleared its pageshow result');

  const changedUrl = worker();
  await changedUrl.scan(1);
  changedUrl.setFrames([{ frameId: 0, documentId: 'doc-0', url: 'https://college.test/other' }]);
  response = await changedUrl.send({ type: 'GET_TAB_RESULT', tabId: 0, url: topUrl });
  assert.equal(response.result, null, 'same document IDs cannot preserve a result for an old SPA URL when a navigation event was missed');
  assert.equal(changedUrl.session.tab_0, undefined);
  await changedUrl.scan(2, {}, { url: 'https://college.test/other' });
  changedUrl.setFrames([{ frameId: 0, documentId: 'doc-0', url: 'https://college.test/other', documentLifecycle: 'cached' }]);
  response = await changedUrl.send({ type: 'GET_TAB_RESULT', tabId: 0, url: 'https://college.test/other' });
  assert.equal(response.result, null, 'a browser-cached document is not reported as the active page');
}

async function testRecoveryAndReputation() {
  const topUrl = 'https://college.test/login?token=PRIVATE#SECRET';
  const frames = [{ frameId: 0, documentId: 'doc-0', url: topUrl }, { frameId: 7, documentId: 'doc-7', url: 'https://embedded.test/phish' }];
  const before = worker();
  before.setFrames(frames);
  await before.scan(1);
  await before.scan(1, { testScore: 90, testOutcome: 'HIGH_RISK' }, { frameId: 7, url: frames[1].url });
  assert.equal(before.session.tab_0.outcome, 'HIGH_RISK');
  const after = worker({}, before.session);
  after.setFrames(frames);
  await after.scan(2);
  const partial = (await after.send({ type: 'GET_TAB_RESULT', tabId: 0, url: topUrl })).result;
  assert.equal(partial.coverage.complete, false, 'cold top-only scan cannot claim full coverage');
  assert.equal(partial.coverage.pendingFrames, 1);
  assert.ok(after.sends.some((item) => item.message.type === 'REQUEST_RESCAN' && item.options.frameId === 7), 'missing live frame is asked to recover');
  await after.scan(2, { testScore: 90, testOutcome: 'HIGH_RISK' }, { frameId: 7, url: frames[1].url });
  assert.equal(after.session.tab_0.outcome, 'HIGH_RISK');
  assert.equal(after.session.tab_0.coverage.complete, true);

  const settings = { reputationEnabled: true, reputationEndpoint: 'https://reputation.test/check?apiKey=PRIVATE_PROVIDER_KEY' };
  const reported = worker(settings);
  await reported.scan(1);
  for (let scanId = 2; scanId <= 100; scanId += 1) await reported.scan(scanId);
  assert.equal(reported.requests.length, 1, '100 same-host scans share one request');
  reported.requests[0].resolve('malicious');
  await tick();
  assert.equal(reported.session.tab_0.outcome, 'HIGH_RISK');
  await reported.scan(101);
  assert.equal(reported.session.tab_0.outcome, 'HIGH_RISK', 'a fresh scan retains the current malicious reputation');
  assert.equal(reported.requests.length, 1, 'fresh TTL report is reused');
  assert.ok(!JSON.stringify(reported.session).includes('PRIVATE_PROVIDER_KEY'), 'endpoint secrets never enter session cache');
  const resumed = worker(settings, reported.session);
  await resumed.scan(102);
  assert.equal(resumed.session.tab_0.outcome, 'HIGH_RISK', 'hostname reputation survives worker restart within TTL');
  assert.equal(resumed.requests.length, 0);

  const invalid = worker({ reputationEnabled: true, reputationEndpoint: 'https://user:secret@reputation.test/check' });
  await invalid.scan(1);
  assert.equal(invalid.requests.length, 0);
  assert.equal(invalid.session.tab_0.reputationStatus, 'error');
  assert.equal(invalid.session.tab_0.reputationError, 'configuration');

  // A hostile inherited document cannot claim a different site's security origin.
  const inherited = worker();
  inherited.setFrames([{ frameId: 0, documentId: 'doc-0', url: topUrl }, { frameId: 9, documentId: 'doc-9', url: 'about:srcdoc' }]);
  await inherited.scan(1);
  assert.equal((await inherited.scan(1, {}, { frameId: 9, url: 'about:srcdoc', contextUrl: 'https://forged.test/', origin: 'https://college.test' })).ignored, true);
  await inherited.scan(1, { testScore: 90, testOutcome: 'HIGH_RISK' }, { frameId: 9, url: 'about:srcdoc', contextUrl: 'https://college.test/', origin: 'https://college.test' });
  assert.equal(inherited.session.tab_0.outcome, 'HIGH_RISK');
  assert.equal(inherited.session.tab_0.evidenceFrame.origin, 'https://college.test');
  assert.equal(inherited.session.tab_0.coverage.complete, true);

  // An old aborted generation must not delete the new same-host in-flight entry.
  const generation = worker(settings);
  await generation.scan(1);
  generation.chrome.storage.onChanged.emit({ phishguard_options: { newValue: settings } }, 'local');
  await generation.scan(2);
  generation.requests[0].resolve('malicious');
  await tick();
  await generation.scan(3);
  assert.equal(generation.requests.length, 2, 'old completion cannot remove a new generation request');
  generation.requests[1].resolve('unknown');
  await tick();
}

async function testContent() {
  const dom = new JSDOM('<title>College</title><form><input type="password"></form><iframe src="/help"></iframe>', { url: 'https://college.test/login', runScripts: 'outside-only' });
  await tick();
  const { window } = dom;
  const sends = [];
  const listeners = [];
  let nextTimer = 0;
  const timers = new Map();
  window.setTimeout = (fn) => { timers.set(++nextTimer, fn); return nextTimer; };
  window.clearTimeout = (id) => timers.delete(id);
  window.PhishGuard = {
    browser: { runtime: { sendMessage: (message) => { sends.push(message); return Promise.resolve(); }, onMessage: { addListener: (fn) => listeners.push(fn) } } },
    extractUrlFeatures: () => ({}), extractFormFeatures: () => ({}), extractDomFeatures: () => ({})
  };
  window.eval(fs.readFileSync(path.join(root, 'src/content/content-script.js'), 'utf8'));
  assert.equal(sends.length, 1);
  const flush = async () => { await tick(); const queued = [...timers.values()]; timers.clear(); queued.forEach((fn) => fn()); await tick(); };
  window.document.querySelector('form').setAttribute('action', 'https://external.test/collect');
  await flush();
  assert.equal(sends.length, 2, 'action edits trigger rescan');
  window.document.querySelector('input').setAttribute('type', 'email');
  await flush();
  assert.equal(sends.length, 3, 'credential type edits trigger rescan');
  window.document.querySelector('iframe').remove();
  await flush();
  assert.equal(sends.length, 4, 'frame removal triggers rescan');
  window.document.querySelector('title').firstChild.data = 'Updated identity';
  await flush();
  assert.equal(sends.length, 5, 'identity text changes trigger rescan');
  const result = { type: 'ANALYZE_RESULT', payload: { identity: sends.at(-1).identity, outcome: 'HIGH_RISK', score: 80, label: 'High phishing risk.', evidenceFrame: { frameId: 4 } } };
  listeners[0](result);
  await flush();
  assert.ok(window.document.getElementById('phishguard-warning-banner'));
  assert.match(window.document.getElementById('phishguard-warning-banner').textContent, /Pause before entering passwords/);
  assert.equal(window.document.getElementById('phishguard-warning-banner').querySelector('[data-phishguard-leave]').type, 'button');
  assert.equal(window.document.activeElement, window.document.body, 'warning does not steal keyboard focus');
  assert.equal(sends.length, 5, 'extension banner insertion/text does not trigger a scan loop');
  const banner = window.document.getElementById('phishguard-warning-banner');
  const close = banner.querySelector('[data-phishguard-close]');
  assert.equal(close.type, 'button');
  assert.equal(close.getAttribute('aria-label'), 'Close phishing warning');
  close.click();
  await flush();
  assert.equal(banner.isConnected, true, 'page-script clicks cannot dismiss the warning');
  banner.remove();
  await flush();
  assert.equal(banner.isConnected, true, 'an active warning is restored after page-owned DOM removal');
  banner.setAttribute('style', 'display:none!important');
  banner.setAttribute('hidden', '');
  banner.setAttribute('aria-hidden', 'true');
  banner.querySelector('[data-phishguard-title]').textContent = 'Everything is safe';
  banner.querySelector('[data-phishguard-leave]').disabled = true;
  await flush();
  assert.equal(banner.style.getPropertyValue('display'), 'block');
  assert.equal(banner.style.getPropertyPriority('display'), 'important');
  assert.equal(banner.hasAttribute('hidden'), false);
  assert.equal(banner.hasAttribute('aria-hidden'), false);
  assert.match(banner.textContent, /High phishing risk/);
  assert.equal(banner.querySelector('[data-phishguard-leave]').disabled, false, 'page cannot disable the warning action');
  assert.equal(sends.length, 5, 'warning repairs do not create analysis loops');
  const details = banner.querySelector('[data-phishguard-details]');
  details.open = true;
  details.dispatchEvent(new window.Event('toggle', { bubbles: true }));
  banner.querySelector('[data-phishguard-leave]').focus();
  await flush();
  assert.equal(details.open, true, 'ordinary warning repairs preserve the expanded evidence');
  assert.equal(sends.length, 5, 'warning focus and evidence disclosure do not trigger page rescans');
  listeners[0]({ ...result, payload: { ...result.payload, reasons: ['<img src=x onerror=alert(1)> Suspicious destination'] } });
  await flush();
  assert.equal(banner.querySelector('img'), null, 'indicator explanations are rendered as text');
  assert.match(banner.textContent, /<img src=x onerror=alert\(1\)>/);
  assert.equal(sends.length, 5, 'updating explanation text does not trigger page rescans');
  listeners[0]({ ...result, payload: { ...result.payload, identity: sends[0].identity, outcome: 'SAFE' } });
  assert.ok(window.document.getElementById('phishguard-warning-banner'), 'stale result cannot remove latest warning');
  listeners[0]({ ...result, payload: { ...result.payload, outcome: 'SAFE' } });
  await flush();
  assert.equal(window.document.getElementById('phishguard-warning-banner'), null);
  assert.equal(sends.length, 5, 'banner removal does not cause a scan loop');
  listeners[0]({ type: 'REQUEST_RESCAN' });
  await flush();
  assert.equal(sends.length, 6);
  const input = window.document.querySelector('input');
  input.setAttribute('type', 'text');
  await flush();
  const beforeAccessibleEdits = sends.length;
  input.setAttribute('placeholder', 'Password');
  await flush();
  assert.equal(sends.length, beforeAccessibleEdits + 1, 'turning an arbitrary text input into a password prompt through its placeholder triggers rescan');
  input.setAttribute('aria-label', 'Password');
  await flush();
  assert.equal(sends.length, beforeAccessibleEdits + 2, 'ARIA label edits trigger credential-context rescan');
  const label = window.document.createElement('span');
  label.id = 'credential-prompt';
  label.textContent = 'Password';
  window.document.body.appendChild(label);
  await flush();
  input.setAttribute('aria-labelledby', label.id);
  await flush();
  assert.equal(sends.length, beforeAccessibleEdits + 4, 'ARIA label reference edits trigger credential-context rescan');
  const image = window.document.createElement('img');
  image.alt = 'Member service';
  window.document.body.prepend(image);
  await flush();
  const beforeImageEdit = sends.length;
  image.alt = 'PayPal logo';
  await flush();
  assert.equal(sends.length, beforeImageEdit + 1, 'image identity label changes trigger a fresh scan');
  const beforeRestore = sends.length;
  window.dispatchEvent(new window.PageTransitionEvent('pagehide', { persisted: true }));
  input.setAttribute('placeholder', 'Updated while cached');
  await flush();
  assert.equal(sends.length, beforeRestore, 'cached documents stop analysis');
  window.dispatchEvent(new window.PageTransitionEvent('pageshow', { persisted: true }));
  assert.equal(sends.length, beforeRestore + 1, 'restored cached documents rescan with their surviving document token');
  assert.equal(sends.at(-1).identity.documentToken, sends[0].identity.documentToken);
  const testResult = { type: 'ANALYZE_RESULT', payload: { identity: sends.at(-1).identity,
    outcome: 'SAFE', score: 0, securityTest: { explanation: 'Harmless official feature check; built-in test entry.' } } };
  listeners[0](testResult);
  await flush();
  const testBanner = window.document.getElementById('phishguard-warning-banner');
  assert.match(testBanner.textContent, /Security test recognised/);
  assert.match(testBanner.textContent, /No credentials are needed/);
  assert.doesNotMatch(testBanner.textContent, /Potential phishing detected/);
  listeners[0]({ ...testResult, payload: { ...testResult.payload, securityTest: undefined } });
  await flush();
  assert.equal(window.document.getElementById('phishguard-warning-banner'), null);
  const analysis = sends.filter((message) => message.type === 'ANALYZE_PAGE').at(-1);
  assert.ok(Number.isFinite(analysis.performance.extraction_ms));
  const timedResult = { type: 'ANALYZE_RESULT', payload: { identity: analysis.identity,
    outcome: 'HIGH_RISK', score: 80, metadata: { runtime_timing: { policy_ms: 1 } } } };
  listeners[0](timedResult);
  const timingReport = sends.at(-1);
  assert.equal(timingReport.type, 'REPORT_RENDER_METRICS');
  assert.ok(timingReport.performance.scan_to_warning_dom_ms >= timingReport.performance.scan_to_result_ms);
  assert.equal(timingReport.identity.url, undefined, 'timing reports carry only document identity and numeric durations');
  const measuredCount = sends.length;
  listeners[0](timedResult);
  assert.equal(sends.length, measuredCount, 'duplicate result delivery cannot cause a timing-report loop');
  window.dispatchEvent(new window.PageTransitionEvent('pagehide'));
  dom.window.close();
}

async function testPopup() {
  const html = fs.readFileSync(path.join(root, 'src/popup/popup.html'), 'utf8');
  const dom = new JSDOM(html, { runScripts: 'outside-only' });
  await tick();
  const { window } = dom;
  const changed = event();
  const saved = {};
  let result = { score: 90, outcome: 'CAUTION', label: 'Use caution.', reasons: ['Canonical reason'], pageOrigin: 'https://college.test', inspectedFrames: 2 };
  const api = {
    runtime: { sendMessage: async () => ({ result }) },
    tabs: { onUpdated: event() },
    storage: { onChanged: changed, local: { get: (_keys, cb) => cb({}), set: (values, cb) => { Object.assign(saved, structuredClone(values)); if (cb) cb(); } } }
  };
  window.PhishGuard = { browser: api, getCurrentTab: async () => ({ id: 5, url: 'https://college.test/login?private=SECRET' }) };
  window.eval(fs.readFileSync(path.join(root, 'src/shared/browser-api.js'), 'utf8'));
  window.eval(fs.readFileSync(path.join(root, 'src/shared/feedback.js'), 'utf8'));
  window.PhishGuard.getCurrentTab = async () => ({ id: 5, url: 'https://college.test/login?private=SECRET' });
  window.eval(fs.readFileSync(path.join(root, 'src/popup/popup.js'), 'utf8'));
  window.document.dispatchEvent(new window.Event('DOMContentLoaded'));
  await tick();
  assert.equal(window.document.getElementById('riskBadge').textContent, 'Caution', 'popup uses outcome rather than reclassifying score');
  assert.ok(!window.document.body.textContent.includes('Model:'), 'product UI does not expose model implementation state');
  result = { ...result, score: 85, outcome: 'HIGH_RISK', label: 'High phishing risk.' };
  changed.emit({ tab_5: {} }, 'session');
  await tick();
  assert.equal(window.document.getElementById('riskBadge').textContent, 'High risk', 'popup refreshes while open');
  result = { ...result, coverage: { inventoryAvailable: true, uninspectedFrames: 2 } };
  changed.emit({ tab_5: {} }, 'session');
  await tick();
  assert.match(window.document.getElementById('coverageText').textContent, /2 embedded document\(s\) could not be inspected/);
  window.document.getElementById('expectedVerdict').value = 'SAFE';
  window.document.getElementById('reportBtn').click();
  await tick();
  assert.equal(saved.phishguard_feedback[0].expectedOutcome, 'SAFE');
  assert.equal(saved.phishguard_feedback[0].observedOutcome, 'HIGH_RISK');
  assert.ok(!JSON.stringify(saved).includes('SECRET') && !JSON.stringify(saved).includes('/login'), 'corrections contain origin only');
  const queries = [];
  window.PhishGuard.getCurrentTab = () => new Promise((resolve) => queries.push(resolve));
  changed.emit({ tab_5: {} }, 'session');
  changed.emit({ tab_5: {} }, 'session');
  queries[1]({ id: 6, url: 'https://new.test/' });
  await tick();
  queries[0]({ id: 5, url: 'https://college.test/' });
  await tick();
  changed.emit({ tab_6: {} }, 'session');
  assert.equal(queries.length, 3, 'an older active-tab lookup cannot replace the newest popup tab identity');
  queries[2](null);
  await tick();
  assert.equal(window.document.getElementById('riskBadge').textContent, 'Unknown', 'no active tab renders an explicit unknown state');
  assert.equal(window.document.getElementById('reportBtn').disabled, true);
  dom.window.close();
}

async function testShadowObservation() {
  const dom = new JSDOM('<div id="existing-host"></div>', { url: 'https://college.test/', runScripts: 'outside-only', pretendToBeVisual: true });
  await tick();
  const { window } = dom;
  const messages = [];
  const timers = new Map();
  const intervals = new Map();
  let timerId = 0;
  window.setTimeout = (fn) => { timers.set(++timerId, fn); return timerId; };
  window.clearTimeout = (id) => timers.delete(id);
  window.setInterval = (fn) => { intervals.set(++timerId, fn); return timerId; };
  window.clearInterval = (id) => intervals.delete(id);
  window.PhishGuard = {
    browser: { runtime: { sendMessage: (message) => { messages.push(message); return Promise.resolve(); }, onMessage: { addListener: () => {} } } },
    extractUrlFeatures: () => ({}), extractDomFeatures: () => ({})
  };
  window.eval(fs.readFileSync(path.join(root, 'src/content/form-features.js'), 'utf8'));
  window.eval(fs.readFileSync(path.join(root, 'src/content/content-script.js'), 'utf8'));
  const flush = async () => { await tick(); const queued = [...timers.values()]; timers.clear(); queued.forEach((fn) => fn()); await tick(); };
  assert.equal(messages.length, 1);
  const shadow = window.document.getElementById('existing-host').attachShadow({ mode: 'open' });
  shadow.innerHTML = '<form action="/session" method="post"><input type="password"></form>';
  await flush();
  assert.equal(messages.length, 1, 'attaching a shadow root to an existing host has no ordinary document mutation');
  for (const poll of intervals.values()) poll();
  await flush();
  assert.equal(messages.length, 2, 'visible root discovery detects a late attached root');
  assert.equal(messages.at(-1).payload.has_password_input, 1);
  shadow.querySelector('form').action = 'https://collector.test/collect';
  await flush();
  assert.equal(messages.length, 3, 'newly discovered shadow roots are observed for form mutations');
  assert.equal(messages.at(-1).payload.cross_domain_form_action, 1);
  const nestedHost = window.document.createElement('div');
  shadow.appendChild(nestedHost);
  const nested = nestedHost.attachShadow({ mode: 'open' });
  nested.innerHTML = '<input type="password">';
  await flush();
  const beforeNested = messages.length;
  nested.querySelector('input').setAttribute('type', 'text');
  await flush();
  assert.equal(messages.length, beforeNested + 1, 'nested open roots get their own mutation observer');
  window.document.getElementById('existing-host').remove();
  await flush();
  const beforeDetached = messages.length;
  shadow.querySelector('form').action = '/detached';
  await flush();
  assert.equal(messages.length, beforeDetached, 'detached shadow roots are released from observation');
  window.dispatchEvent(new window.PageTransitionEvent('pagehide', { persisted: true }));
  assert.equal(intervals.size, 0, 'root discovery is stopped for cached documents');
  dom.window.close();
}

async function testContentIdCollision() {
  const dom = new JSDOM('<div id="phishguard-warning-banner"><form><input type="password"></form></div>', { url: 'https://college.test/', runScripts: 'outside-only' });
  await tick();
  const { window } = dom;
  const pageNode = window.document.getElementById('phishguard-warning-banner');
  const messages = [];
  const listeners = [];
  const timers = new Map();
  let timerId = 0;
  window.setTimeout = (fn) => { timers.set(++timerId, fn); return timerId; };
  window.clearTimeout = (id) => timers.delete(id);
  window.PhishGuard = {
    browser: { runtime: { sendMessage: (message) => { messages.push(message); return Promise.resolve(); }, onMessage: { addListener: (fn) => listeners.push(fn) } } },
    extractUrlFeatures: () => ({}), extractFormFeatures: () => ({}), extractDomFeatures: () => ({})
  };
  window.eval(fs.readFileSync(path.join(root, 'src/content/content-script.js'), 'utf8'));
  pageNode.querySelector('form').setAttribute('action', 'https://collector.test/');
  await tick();
  const queued = [...timers.values()]; timers.clear(); queued.forEach((fn) => fn());
  await tick();
  assert.equal(messages.length, 2, 'a page-owned banner ID cannot suppress credential form rescans');
  const result = { type: 'ANALYZE_RESULT', payload: { identity: messages.at(-1).identity, outcome: 'HIGH_RISK', score: 80, label: 'High phishing risk.' } };
  listeners[0](result);
  assert.ok(pageNode.querySelector('form'), 'the warning must not replace page-owned content with a colliding ID');
  assert.ok(window.document.querySelector('[role="alert"]'), 'a separate warning is created');
  const injectedForm = window.document.createElement('form');
  injectedForm.innerHTML = '<input type="password">';
  window.document.querySelector('[role="alert"]').appendChild(injectedForm);
  await tick();
  const injectedTimers = [...timers.values()]; timers.clear(); injectedTimers.forEach((fn) => fn());
  await tick();
  assert.equal(messages.length, 3, 'moving page-owned forms inside the warning cannot evade DOM observation');
  listeners[0]({ ...result, payload: { ...result.payload, identity: messages.at(-1).identity, outcome: 'SAFE' } });
  assert.equal(pageNode.isConnected, true, 'clearing a warning must not remove a page-owned element');
  assert.equal(window.document.querySelector('[role="alert"]'), null);
  dom.window.close();
}

async function testOptions() {
  const dom = new JSDOM(fs.readFileSync(path.join(root, 'src/options/options.html'), 'utf8'), { runScripts: 'outside-only' });
  await tick();
  const { window } = dom;
  const saved = {};
  window.PhishGuard = { browser: { storage: { local: {
    get: (_keys, cb) => cb({}), set: (value, cb) => { Object.assign(saved, value); cb(); }, remove: (_key, cb) => cb()
  } } } };
  window.eval(fs.readFileSync(path.join(root, 'src/shared/browser-api.js'), 'utf8'));
  window.eval(fs.readFileSync(path.join(root, 'src/shared/feedback.js'), 'utf8'));
  window.eval(fs.readFileSync(path.join(root, 'src/options/options.js'), 'utf8'));
  window.document.dispatchEvent(new window.Event('DOMContentLoaded'));
  await tick();
  assert.equal(window.document.getElementById('domainAgeEnabled'), null, 'unsupported age control removed');
  window.document.getElementById('reputationEnabled').checked = true;
  window.document.getElementById('reputationEndpoint').value = 'http://remote.test/check';
  window.document.getElementById('saveOptions').click();
  await tick();
  assert.equal(saved.phishguard_options, undefined, 'insecure remote reputation endpoints are rejected');
  window.document.getElementById('reputationEndpoint').value = 'https://remote.test/check';
  window.document.getElementById('warningThreshold').value = '85';
  window.document.getElementById('saveOptions').click();
  assert.equal(saved.phishguard_options.warningThreshold, 85);
  assert.equal(saved.phishguard_options.reputationEnabled, true);
  dom.window.close();
}

(async () => { await testBrowserStatusAndTiming(); await testWorker(); await testRecoveryAndReputation(); await testContent(); await testContentIdCollision(); await testShadowObservation(); await testPopup(); await testOptions(); console.log('Runtime identity, trusted browser status, bounded timing, recovery, coordinated reputation, privacy, dynamic DOM/shadow roots, live popup and settings validation passed.'); })().catch((error) => { console.error(error); process.exitCode = 1; });
