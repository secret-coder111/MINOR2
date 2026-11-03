var phishGuardGlobal = typeof window !== 'undefined' ? window : self;

phishGuardGlobal.PhishGuard = phishGuardGlobal.PhishGuard || {};

phishGuardGlobal.PhishGuard.browser = (function () {
  if (typeof browser !== 'undefined') {
    return browser;
  }
  if (typeof chrome !== 'undefined') {
    return chrome;
  }
  return phishGuardGlobal.PhishGuard.browser || null;
})();

// Storage callbacks may run with runtime.lastError instead of throwing. Keep
// that error inside the callback, where Chromium makes it available, and also
// support the Promise-only browser namespace.
phishGuardGlobal.PhishGuard.storageCall = function (area, method, ...args) {
  const api = phishGuardGlobal.PhishGuard.browser;
  return new Promise((resolve, reject) => {
    try {
      const storage = api && api.storage && api.storage[area];
      if (!storage || typeof storage[method] !== 'function') throw new Error('Storage unavailable');
      const callback = (value) => {
        const error = api.runtime && api.runtime.lastError;
        if (error) reject(new Error(error.message || 'Storage operation failed'));
        else resolve(value);
      };
      const promiseOnly = typeof browser !== 'undefined' && browser === api;
      const pending = promiseOnly ? storage[method](...args) : storage[method](...args, callback);
      if (pending && typeof pending.then === 'function') pending.then(resolve, reject);
      else if (promiseOnly) resolve(pending);
    } catch (error) { reject(error); }
  });
};

phishGuardGlobal.PhishGuard.getCurrentTab = function () {
  return new Promise((resolve, reject) => {
    if (!phishGuardGlobal.PhishGuard.browser) {
      reject(new Error('No browser API available'));
      return;
    }

    const api = phishGuardGlobal.PhishGuard.browser;
    if (api.tabs && api.tabs.query) {
      api.tabs.query({ active: true, currentWindow: true }, function (tabs) {
        if (api.runtime.lastError) {
          reject(new Error(api.runtime.lastError.message));
          return;
        }
        resolve(tabs && tabs[0] ? tabs[0] : null);
      });
      return;
    }

    resolve(null);
  });
};

phishGuardGlobal.PhishGuard.safeText = function (value) {
  if (value === null || typeof value === 'undefined') {
    return '';
  }
  return String(value).replace(/[<>]/g, '').trim();
};
