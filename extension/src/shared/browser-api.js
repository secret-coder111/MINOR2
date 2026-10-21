var phishGuardGlobal = typeof window !== 'undefined' ? window : self;

phishGuardGlobal.PhishGuard = phishGuardGlobal.PhishGuard || {};

phishGuardGlobal.PhishGuard.browser = (function () {
  if (typeof browser !== 'undefined') {
    return browser;
  }
  if (typeof chrome !== 'undefined') {
    return chrome;
  }
  return null;
})();

phishGuardGlobal.PhishGuard.getCurrentTab = function () {
  return new Promise((resolve, reject) => {
    if (!phishGuardGlobal.PhishGuard.browser) {
      reject(new Error('No browser API available'));
      return;
    }

    const api = phishGuardGlobal.PhishGuard.browser;
    if (api.tabs && api.tabs.query) {
      api.tabs.query({ active: true, currentWindow: true }, function (tabs) {
        if (chrome.runtime.lastError) {
          reject(new Error(chrome.runtime.lastError.message));
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
