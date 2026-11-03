const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { test } = require('node:test');
const { JSDOM } = require('jsdom');
const { sanitizeFeedback } = require('../../src/shared/feedback.js');
const root = path.resolve(__dirname, '../..');
const tick = () => new Promise((resolve) => setImmediate(resolve));

function storageMock(initial = {}) {
  const data = structuredClone(initial);
  const runtime = { sendMessage: async () => ({ result: null }) };
  const state = { data, runtime, fail: '', writes: 0 };
  function callback(method, cb, result, update) {
    if (state.fail === method) runtime.lastError = { message: 'Storage is unavailable' };
    else if (update) update();
    try { if (cb) cb(result); }
    finally { delete runtime.lastError; }
  }
  state.api = { runtime, tabs: { onUpdated: { addListener() {} } }, storage: { onChanged: { addListener() {} }, local: {
    get(keys, cb) { callback('get', cb, Object.fromEntries(keys.map((key) => [key, data[key]]))); },
    set(values, cb) { state.writes++; callback('set', cb, undefined, () => Object.assign(data, structuredClone(values))); },
    remove(key, cb) { callback('remove', cb, undefined, () => { delete data[key]; }); }
  } } };
  return state;
}

async function page(kind, state) {
  const dom = new JSDOM(fs.readFileSync(path.join(root, `src/${kind}/${kind}.html`), 'utf8'), { runScripts: 'outside-only' });
  await tick();
  const { window } = dom;
  window.PhishGuard = { browser: state.api };
  for (const file of ['shared/browser-api.js', 'shared/feedback.js']) window.eval(fs.readFileSync(path.join(root, 'src', file), 'utf8'));
  window.PhishGuard.getCurrentTab = async () => ({ id: 1, url: 'https://top.test/login?secret=NEVER_STORE' });
  window.eval(fs.readFileSync(path.join(root, `src/${kind}/${kind}.js`), 'utf8'));
  window.document.dispatchEvent(new window.Event('DOMContentLoaded'));
  await tick();
  return dom;
}

function entry(overrides = {}) {
  return { origin: 'https://top.test/login?secret=NEVER_STORE', evidenceOrigin: 'https://frame.test/phish?secret=NEVER_STORE',
    expectedOutcome: 'HIGH_RISK', observedOutcome: 'SAFE', score: 0, timestamp: 10, policyVersion: '0.2.0',
    context: { inspectedFrames: 2, coverageComplete: true, reputationStatus: 'disabled', activeCategories: ['identity'] }, ...overrides };
}

test('popup opens its packaged URL checker without sending the current address', async () => {
  const state = storageMock();
  const opened = [];
  state.runtime.getURL = path => 'chrome-extension://test-extension/' + path;
  state.api.tabs.create = async value => { opened.push(value); };
  const dom = await page('popup', state);
  dom.window.document.getElementById('urlCheckerBtn').click();
  await tick();
  assert.deepEqual(opened.map(x => ({ ...x })), [{ url: 'chrome-extension://test-extension/demo/url-checker.html' }]);
  dom.window.close();
});

test('official feature checks are labelled separately from evidence scores and excluded from corrections', async () => {
  const state = storageMock();
  state.runtime.sendMessage = async () => ({ result: { outcome: 'SAFE', score: 0, label: 'No strong phishing indicators found.',
    reasons: [], securityTest: { id: 'amtso-phishing-feature-check', explanation: 'Harmless official test URL; built-in test entry.' },
    coverage: { complete: true } } });
  const dom = await page('popup', state);
  const doc = dom.window.document;
  assert.equal(doc.getElementById('riskBadge').textContent, 'Security test');
  assert.equal(doc.getElementById('verdictTitle').textContent, 'Official test recognised');
  assert.equal(doc.getElementById('scoreText').textContent, '0/100 local rules; test URL matched');
  assert.equal(doc.getElementById('reportBtn').disabled, true);
  assert.equal(doc.getElementById('leaveBtn').hidden, false);
  dom.window.close();
});

test('feedback whitelists origins and coarse context, caps records, and never promotes labels to verified truth', () => {
  const values = sanitizeFeedback([entry({ extra: 'NEVER_STORE', context: { activeCategories: ['identity', 'identity', 'NEVER_STORE'], rawText: 'NEVER_STORE' } }),
    entry({ tab: 'https://legacy.test/private' }), entry({ origin: 'javascript:alert(1)' }), entry({ expectedOutcome: 'untrusted' })]);
  assert.equal(values.length, 1);
  assert.equal(values[0].origin, 'https://top.test');
  assert.equal(values[0].evidenceOrigin, 'https://frame.test');
  assert.equal(values[0].reviewed, false);
  assert.deepEqual(values[0].context.activeCategories, ['identity']);
  assert.ok(!JSON.stringify(values).includes('NEVER_STORE'));
  assert.equal(sanitizeFeedback(Array.from({ length: 200 }, () => entry())).length, 100);
  assert.deepEqual(sanitizeFeedback(null), []);
});

test('options reject embedded credentials, fragments, and insecure remote endpoints; permit HTTPS and localhost HTTP', async () => {
  const state = storageMock();
  const dom = await page('options', state);
  const doc = dom.window.document;
  doc.getElementById('reputationEnabled').checked = true;
  for (const endpoint of ['https://user:password@rep.test/check', 'https://rep.test/check#ignored', 'http://rep.test/check']) {
    doc.getElementById('reputationEndpoint').value = endpoint;
    doc.getElementById('saveOptions').click();
    await tick();
    assert.equal(state.data.phishguard_options, undefined);
    assert.match(doc.getElementById('status').textContent, /not saved/);
  }
  for (const endpoint of ['https://rep.test/check', 'http://localhost:8080/check', 'http://127.0.0.1/check', 'http://[::1]/check']) {
    doc.getElementById('reputationEndpoint').value = endpoint;
    doc.getElementById('saveOptions').click();
    await tick();
    assert.equal(state.data.phishguard_options.reputationEndpoint, endpoint);
    assert.match(doc.getElementById('status').textContent, /Settings saved/);
  }
  dom.window.close();
});

test('failed settings writes and correction removal never announce success', async () => {
  const state = storageMock({ phishguard_feedback: [entry()] });
  const dom = await page('options', state);
  const doc = dom.window.document;
  state.fail = 'set';
  doc.getElementById('saveOptions').click();
  await tick();
  assert.match(doc.getElementById('status').textContent, /Could not save/);
  state.fail = 'remove';
  doc.getElementById('clearData').click();
  await tick();
  assert.match(doc.getElementById('feedbackStatus').textContent, /Could not clear/);
  assert.equal(state.data.phishguard_feedback.length, 1);
  assert.equal(doc.getElementById('feedbackList').children.length, 1);
  state.fail = '';
  doc.getElementById('clearData').click();
  await tick();
  assert.equal(state.data.phishguard_feedback, undefined);
  assert.equal(doc.getElementById('feedbackList').children.length, 0);
  assert.match(doc.getElementById('feedbackStatus').textContent, /corrections cleared/);
  dom.window.close();
});

test('review must persist before export; export contains only reviewed sanitized candidates', async () => {
  const state = storageMock({ phishguard_feedback: [entry(), entry({ timestamp: 20, origin: 'https://second.test/private', reviewed: false })] });
  const dom = await page('options', state);
  const { window } = dom;
  const doc = window.document;
  assert.equal(doc.getElementById('exportFeedback').disabled, true);
  const checkbox = doc.querySelector('#feedbackList input');
  state.fail = 'set';
  checkbox.checked = true;
  checkbox.dispatchEvent(new window.Event('change'));
  await tick();
  assert.equal(checkbox.checked, false);
  assert.equal(doc.getElementById('exportFeedback').disabled, true);
  state.fail = '';
  checkbox.checked = true;
  checkbox.dispatchEvent(new window.Event('change'));
  await tick();
  assert.equal(state.data.phishguard_feedback[0].reviewed, true);
  assert.equal(doc.getElementById('exportFeedback').disabled, false);
  const blobs = [];
  const links = [];
  window.Blob = Blob;
  window.URL.createObjectURL = (blob) => { blobs.push(blob); return 'blob:local-test'; };
  window.URL.revokeObjectURL = () => {};
  window.HTMLAnchorElement.prototype.click = function () { links.push(this.download); };
  doc.getElementById('exportFeedback').click();
  await tick();
  const exported = JSON.parse(await blobs[0].text());
  assert.equal(exported.kind, 'phishguard_user_reviewed_candidates');
  assert.equal(exported.automaticLearning, false);
  assert.equal(exported.verifiedGroundTruth, false);
  assert.equal(exported.corrections.length, 1);
  assert.ok(!JSON.stringify(exported).includes('NEVER_STORE'));
  assert.ok(links[0].endsWith('.json'));
  dom.window.close();
});

test('popup uses incomplete/unknown display and discloses failed optional reputation without altering rule outcome', async () => {
  const state = storageMock();
  state.runtime.sendMessage = async () => ({ result: { pageOrigin: 'https://top.test', outcome: 'SAFE', score: 0,
    label: 'No strong phishing indicators found.', inspectedFrames: 1,
    coverage: { complete: false, inventoryAvailable: true, uninspectedFrames: 1, pendingFrames: 1 }, reputationStatus: 'error' } });
  const dom = await page('popup', state);
  assert.equal(dom.window.document.getElementById('riskBadge').textContent, 'Incomplete inspection');
  assert.match(dom.window.document.getElementById('reputationText').textContent, /checks failed/);
  assert.match(dom.window.document.getElementById('coverageText').textContent, /Waiting for 1 document/);
  dom.window.close();
});

test('mixed remote high-risk and failed embedded lookup keeps the warning and describes partial remote coverage', async () => {
  const state = storageMock();
  state.runtime.sendMessage = async () => ({ result: { pageOrigin: 'https://top.test', outcome: 'HIGH_RISK', score: 90,
    label: 'High phishing risk.', inspectedFrames: 2,
    reasons: ['The configured reputation service reports this hostname as malicious.'],
    metadata: { rule_score: 0, reputation: { verdict: 'malicious' } },
    coverage: { complete: true, inventoryAvailable: true, uninspectedFrames: 0, pendingFrames: 0 },
    reputationStatus: 'error', reputationCoverage: { disabled: 0, pending: 0, available: 1, error: 1 } } });
  const dom = await page('popup', state);
  const doc = dom.window.document;
  assert.equal(doc.getElementById('riskBadge').textContent, 'High risk');
  assert.equal(doc.getElementById('scoreText').textContent, '90/100 risk index');
  assert.match(doc.getElementById('reputationText').textContent, /coverage is incomplete/);
  assert.match(doc.getElementById('reputationText').textContent, /1 completed, 0 pending, 1 failed/);
  assert.doesNotMatch(doc.getElementById('reputationText').textContent, /only local|No remote verdict/);
  assert.match(doc.getElementById('reasonList').textContent, /reports this hostname as malicious/);
  dom.window.close();
});

test('popup confirms storage completion, reports read/write failures and retains privacy-safe frame evidence', async () => {
  const state = storageMock();
  state.runtime.sendMessage = async () => ({ result: { pageOrigin: 'https://top.test/login?secret=NEVER_STORE', outcome: 'SAFE', score: 10,
    label: 'No strong phishing indicators found.', evidenceFrame: { frameId: 3, origin: 'https://frame.test/collect?secret=NEVER_STORE' },
    metadata: { policy_version: '0.2.0', active_evidence_categories: ['identity'] }, inspectedFrames: 2,
    coverage: { complete: true, inventoryAvailable: true, uninspectedFrames: 0 }, reputationStatus: 'disabled' } });
  const dom = await page('popup', state);
  const doc = dom.window.document;
  doc.getElementById('expectedVerdict').value = 'HIGH_RISK';
  for (const failure of ['get', 'set']) {
    state.fail = failure;
    doc.getElementById('reportBtn').click();
    await tick();
    assert.match(doc.getElementById('feedbackStatus').textContent, /Could not save/);
    assert.equal(state.data.phishguard_feedback, undefined);
  }
  state.fail = '';
  doc.getElementById('reportBtn').click();
  await tick();
  assert.match(doc.getElementById('feedbackStatus').textContent, /Correction saved/);
  const saved = state.data.phishguard_feedback[0];
  assert.equal(saved.topOrigin, 'https://top.test');
  assert.equal(saved.evidenceOrigin, 'https://frame.test');
  assert.equal(saved.evidenceFrameId, 3);
  assert.equal(saved.context.coverageComplete, true);
  assert.equal(saved.reviewed, false);
  assert.ok(!JSON.stringify(saved).includes('NEVER_STORE'));
  dom.window.close();
});

test('browser namespace Promise storage rejections are surfaced', async () => {
  const dom = new JSDOM('', { runScripts: 'outside-only' });
  dom.window.browser = { storage: { local: { set: async () => { throw new Error('Quota exceeded'); } } } };
  dom.window.eval(fs.readFileSync(path.join(root, 'src/shared/browser-api.js'), 'utf8'));
  await assert.rejects(dom.window.PhishGuard.storageCall('local', 'set', {}), /Quota exceeded/);
  dom.window.close();
});

test('popup shows origins without URL secrets, provides next steps, and requests rescans without claiming completion', async () => {
  const state = storageMock();
  const messages = [];
  let openedSettings = false;
  const result = { pageOrigin: 'https://top.test', outcome: 'HIGH_RISK', score: 80,
    label: 'High phishing risk.', evidenceFrame: { frameId: 3, origin: 'https://frame.test/collect?secret=NEVER_STORE' },
    identity: { documentToken: 'page-1', scanId: 1 }, reputationStatus: 'disabled',
    coverage: { complete: true, inventoryAvailable: true }, reasons: ['Two contextual indicators found.'] };
  state.runtime.sendMessage = async (message) => {
    messages.push(message);
    return message.type === 'REQUEST_TAB_RESCAN' ? { requested: true } : { result };
  };
  state.runtime.openOptionsPage = async () => { openedSettings = true; };
  const dom = await page('popup', state);
  const doc = dom.window.document;
  assert.equal(doc.getElementById('siteOrigin').textContent, 'https://top.test');
  assert.match(doc.getElementById('evidenceOrigin').textContent, /https:\/\/frame.test$/);
  assert.doesNotMatch(doc.body.textContent, /NEVER_STORE/);
  assert.match(doc.getElementById('nextStep').textContent, /Pause before entering passwords/);
  doc.getElementById('rescanBtn').click();
  await tick();
  assert.equal(messages.find((message) => message.type === 'REQUEST_TAB_RESCAN').tabId, 1);
  assert.match(doc.getElementById('scanStatus').textContent, /Rescan requested/);
  assert.doesNotMatch(doc.getElementById('scanStatus').textContent, /checked again/);
  doc.getElementById('settingsBtn').click();
  await tick();
  assert.equal(openedSettings, true);
  state.runtime.sendMessage = async () => ({ requested: false });
  doc.getElementById('rescanBtn').click();
  await tick();
  assert.match(doc.getElementById('scanStatus').textContent, /Could not request/);
  assert.equal(doc.getElementById('rescanBtn').disabled, false);
  dom.window.close();
});

test('popup departure follows the high-risk outcome and checks the active tab again', async () => {
  const state = storageMock();
  let result = { outcome: 'HIGH_RISK', score: 80, label: 'High phishing risk.', reasons: ['Identity and destination mismatch.'], coverage: { complete: true } };
  state.runtime.sendMessage = async () => ({ result });
  const departed = [];
  state.api.tabs.update = async (id, options) => { departed.push({ id, options }); };
  const dom = await page('popup', state);
  const doc = dom.window.document;
  const closeWindow = dom.window.close.bind(dom.window);
  dom.window.close = () => {};
  assert.equal(doc.getElementById('verdictTitle').textContent, 'Possible phishing');
  assert.equal(doc.querySelector('.popup').dataset.state, 'danger');
  assert.equal(doc.getElementById('riskFill').style.width, '80%');
  assert.equal(doc.getElementById('leaveBtn').hidden, false);
  dom.window.PhishGuard.getCurrentTab = async () => ({ id: 2, url: 'https://different.test/' });
  doc.getElementById('leaveBtn').click();
  await tick();
  assert.equal(departed.length, 0, 'a stale popup must not navigate another active page');
  doc.getElementById('leaveBtn').click();
  await tick();
  assert.equal(departed.length, 1);
  assert.equal(departed[0].id, 2);
  assert.equal(departed[0].options.url, 'about:blank');
  closeWindow();
});

test('malformed popup results cannot display a low-risk verdict', async () => {
  for (const result of [{ outcome: 'SAFE', score: NaN }, { outcome: 'SAFE', score: 101 }, { outcome: 'other', score: 0 }]) {
    const state = storageMock();
    state.runtime.sendMessage = async () => ({ result });
    const dom = await page('popup', state);
    assert.equal(dom.window.document.getElementById('riskBadge').textContent, 'Unknown');
    assert.equal(dom.window.document.getElementById('leaveBtn').hidden, true);
    dom.window.close();
  }
});
