/* Read-only probes of shipped UI/worker code. No external network requests. */
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const { JSDOM } = require('jsdom');

const project = path.resolve(__dirname, '../..');
const extension = path.join(project, 'extension');
const unitDirectory = path.join(extension, 'tests/unit');

// Reuse the existing worker's browser mock, excluding its test runner.
const testSource = fs.readFileSync(path.join(unitDirectory, 'runtime-integration.test.js'), 'utf8');
const harness = {
  require, __dirname: unitDirectory, console, URL, Map, Set, Promise, Number,
  Object, String, Array, Date, setTimeout, clearTimeout, setImmediate,
  AbortController, structuredClone
};
vm.runInNewContext(testSource.slice(0, testSource.lastIndexOf('(async () =>'))
  + '\nglobalThis.auditWorker = worker;', harness);

(async () => {
  const results = { auditDate: '2026-10-25', networkRequestsSent: 0, probes: [] };
  const app = harness.auditWorker({ reputationEnabled: true, reputationEndpoint: 'https://rep.test/check' });
  for (let scanId = 1; scanId <= 100; scanId++) await app.scan(scanId);
  const pending = app.requests.filter(request => !request.options.signal.aborted).length;
  assert.equal(app.requests.length, 100);
  assert.equal(pending, 100);
  results.probes.push({
    case: '100 scans of the same unchanged hostname',
    mockedRequestsCreated: app.requests.length,
    obsoleteRequestsStillUnaborted: pending - 1,
    totalUnaborted: pending
  });
  for (const request of app.requests) request.resolve('unknown');

  const dom = new JSDOM(fs.readFileSync(path.join(extension, 'src/options/options.html'), 'utf8'), {
    runScripts: 'outside-only'
  });
  await new Promise(resolve => setImmediate(resolve));
  const window = dom.window;
  const saved = {};
  let failure = null;
  const api = { runtime: {}, storage: { local: {
    get: (_keys, callback) => callback({}),
    set: (values, callback) => {
      if (failure) api.runtime.lastError = { message: failure };
      else Object.assign(saved, structuredClone(values));
      callback();
      delete api.runtime.lastError;
    },
    remove: (_keys, callback) => {
      if (failure) api.runtime.lastError = { message: failure };
      callback();
      delete api.runtime.lastError;
    }
  } } };
  window.PhishGuard = { browser: api };
  window.eval(fs.readFileSync(path.join(extension, 'src/options/options.js'), 'utf8'));
  window.document.dispatchEvent(new window.Event('DOMContentLoaded'));
  window.document.getElementById('reputationEnabled').checked = true;
  const endpoint = 'https://username:password@rep.test/check';
  window.document.getElementById('reputationEndpoint').value = endpoint;
  window.document.getElementById('saveOptions').click();
  assert.equal(saved.phishguard_options.reputationEndpoint, endpoint);
  let constructionError;
  try { new Request(endpoint); } catch (error) { constructionError = error.message; }
  assert.ok(constructionError);
  results.probes.push({
    case: 'Embedded-credential endpoint accepted by options but rejected by Fetch',
    endpointAcceptedAndSaved: true,
    requestConstructionError: constructionError,
    displayedStatus: window.document.getElementById('status').textContent
  });

  failure = 'simulated storage write failure';
  window.document.getElementById('saveOptions').click();
  const failedSaveStatus = window.document.getElementById('status').textContent;
  window.document.getElementById('clearData').click();
  const failedClearStatus = window.document.getElementById('status').textContent;
  assert.match(failedSaveStatus, /Settings saved/);
  assert.match(failedClearStatus, /corrections cleared/);
  results.probes.push({
    case: 'Storage failure falsely reported as success',
    failedSaveStatus,
    failedClearStatus
  });
  dom.window.close();

  const output = path.join(__dirname, 'tester-ui-results-2026-10-25.json');
  fs.writeFileSync(output, JSON.stringify(results, null, 2) + '\n');
  console.log(JSON.stringify(results, null, 2));
})().catch(error => { console.error(error); process.exitCode = 1; });
