(function (global) {
  'use strict';
  // Runs only after an explicit action in the packaged extension checker.
  // Reuses the real worker result; it never fetches HTML from a server or
  // invents missing form features from the pasted address.
  async function inspect(address, api, options = {}) {
    const url = global.PhishGuard.URLChecker.normalize(address).href;
    const started = Date.now();
    const timeout = options.timeoutMs ?? 15000;
    const settle = options.settleMs ?? 2000;
    const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
    async function bounded(promise, budget = Math.max(1, timeout - (Date.now() - started))) {
      let timer;
      try { return await Promise.race([promise, new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('Page inspection timed out. No verdict is available.')), budget); })]); }
      finally { clearTimeout(timer); }
    }
    let ownedId = null;
    let completeSince = null;
    let completeUrl = null;
    try {
      const created = await bounded(api.tabs.create({ url, active: false }));
      if (!Number.isInteger(created?.id)) throw new Error('Could not open a page for inspection.');
      ownedId = created.id;
      while (Date.now() - started < timeout) {
        if (options.cancelled?.()) throw new Error('A newer check replaced this inspection.');
        const tab = await bounded(api.tabs.get(ownedId));
        let effective;
        try { effective = global.PhishGuard.URLChecker.normalize(tab.url || tab.pendingUrl || url); }
        catch (_) { await sleep(options.pollMs ?? 250); continue; }
        if (tab.status !== 'complete' || completeUrl !== effective.href) {
          completeSince = tab.status === 'complete' ? Date.now() : null;
          completeUrl = effective.href;
        } else if (completeSince === null) completeSince = Date.now();
        const response = await bounded(api.runtime.sendMessage({ type: 'GET_TAB_RESULT', tabId: ownedId, url: effective.href }));
        const result = response?.result;
        if (completeSince !== null && Date.now() - completeSince >= settle && result
            && ['SAFE', 'CAUTION', 'HIGH_RISK'].includes(result.outcome)
            && Number.isFinite(result.score) && result.score >= 0 && result.score <= 100
            && result.pageOrigin === effective.origin) {
          return result;
        }
        await sleep(options.pollMs ?? 250);
      }
      throw new Error('The page could not be inspected. A browser block, loading failure or restricted document may prevent a result.');
    } finally {
      if (ownedId !== null) {
        try {
          const tab = await bounded(api.tabs.get(ownedId), 1000);
          // Never close another tab or a scan tab the user deliberately selected.
          if (!tab.active) await bounded(api.tabs.remove(ownedId), 1000);
        } catch (_) { /* Already closed or no longer available. */ }
      }
    }
  }
  global.PhishGuard.inspectLoadedURL = inspect;
})(typeof window !== 'undefined' ? window : globalThis);
