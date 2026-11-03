const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');
function setup({ active = false, result } = {}) {
  const calls = [];
  const context = { setTimeout, clearTimeout, URL, Date, PhishGuard: { URLChecker: { normalize: address => new URL(address) } } };
  context.window = context;
  vm.createContext(context);
  vm.runInContext(fs.readFileSync(path.resolve(__dirname, '../../demo/page-check.js'), 'utf8'), context);
  const api = { tabs: {
    create: async value => { calls.push(['create', value.url, value.active]); return { id: 42 }; },
    get: async id => { calls.push(['get', id]); return { id, active, status: 'complete', url: 'https://final.test/login' }; },
    remove: async id => { calls.push(['remove', id]); }
  }, runtime: { sendMessage: async message => { calls.push(['message', message.url, message.tabId]); return { result }; } } };
  return { inspect: context.PhishGuard.inspectLoadedURL, api, calls };
}
test('loaded-page inspection uses the real current document verdict and closes only its inactive owned tab', async () => {
  const result = { outcome: 'HIGH_RISK', score: 88, pageOrigin: 'https://final.test', reasons: ['Actual form evidence'] };
  const app = setup({ result });
  assert.equal(await app.inspect('https://initial.test/', app.api, { settleMs: 0 }), result);
  assert.deepEqual(app.calls.filter(call => call[0] === 'create'), [['create', 'https://initial.test/', false]]);
  assert.deepEqual(app.calls.filter(call => call[0] === 'message'), [['message', 'https://final.test/login', 42]]);
  assert.deepEqual(app.calls.filter(call => call[0] === 'remove'), [['remove', 42]]);
  const selected = setup({ active: true, result });
  await selected.inspect('https://initial.test/', selected.api, { settleMs: 0 });
  assert.equal(selected.calls.some(call => call[0] === 'remove'), false, 'A tab selected by the user must remain open');
});
test('missing, stale and malformed page results never become a low-risk verdict; cancellation cleans up', async () => {
  for (const result of [null, { outcome: 'SAFE', score: 0, pageOrigin: 'https://stale.test' },
    { outcome: 'SAFE', score: null, pageOrigin: 'https://final.test' }]) {
    const app = setup({ result });
    await assert.rejects(app.inspect('https://initial.test/', app.api, { settleMs: 0, pollMs: 1, timeoutMs: 15 }));
    assert(app.calls.some(call => call[0] === 'remove'));
  }
  const cancelled = setup();
  await assert.rejects(cancelled.inspect('https://initial.test/', cancelled.api, { cancelled: () => true }), /newer check/);
  assert(cancelled.calls.some(call => call[0] === 'remove'));
});
