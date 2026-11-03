(function (global) {
  'use strict';
  global.PhishGuard = global.PhishGuard || {};
  // Keep browser document identity separate from the security origin inherited
  // by about:blank/srcdoc and blob documents. Never use an HTML <base> as proof
  // of origin, and never invent an owner for an opaque sandbox/data document.
  global.PhishGuard.getPageContext = function () {
    const documentUrl = String(global.location && global.location.href || '');
    try {
      const actual = new URL(documentUrl);
      if (['http:', 'https:', 'file:'].includes(actual.protocol)) {
        return { documentUrl, url: documentUrl, origin: actual.origin, inherited: false, supported: true, opaque: false };
      }
      const eligible = (actual.protocol === 'about:' && ['blank', 'srcdoc'].includes(actual.pathname)) || actual.protocol === 'blob:';
      const origin = actual.protocol === 'blob:' ? actual.origin : String(global.origin || '');
      const inherited = new URL(origin);
      if (eligible && ['http:', 'https:'].includes(inherited.protocol) && inherited.origin === origin) {
        return { documentUrl, url: `${origin}/`, origin, inherited: true, supported: true, opaque: false };
      }
    } catch (_) { /* Opaque documents have no independently attributable site. */ }
    return { documentUrl, url: '', origin: '', inherited: true, supported: false, opaque: true };
  };
})(typeof window !== 'undefined' ? window : globalThis);
