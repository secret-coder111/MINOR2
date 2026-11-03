(function (global) {
  'use strict';
  const outcomes = new Set(['SAFE', 'CAUTION', 'HIGH_RISK']);
  const reputationStates = new Set(['disabled', 'pending', 'available', 'error', 'unknown']);
  const categories = new Set(['identity', 'destination', 'transport', 'address', 'page']);
  const count = (value) => Number.isInteger(value) && value >= 0 ? Math.min(value, 10000) : 0;
  function originOnly(value) {
    try {
      const url = new URL(value);
      return ['http:', 'https:'].includes(url.protocol) ? url.origin : '';
    } catch (_) { return ''; }
  }

  // Feedback is untrusted user annotation, never a scoring rule or a verified
  // training label. Whitelist all persisted/exported data; never retain URLs,
  // reasons, page text, credentials, or arbitrary properties from older records.
  function sanitizeFeedback(entries) {
    if (!Array.isArray(entries)) return [];
    return entries.filter((entry) => entry && !entry.tab && outcomes.has(entry.expectedOutcome)
      && outcomes.has(entry.observedOutcome) && originOnly(entry.topOrigin || entry.origin))
      .slice(0, 100).map((entry) => {
        const topOrigin = originOnly(entry.topOrigin || entry.origin);
        const context = entry.context || {};
        return {
          schemaVersion: 1,
          origin: topOrigin,
          topOrigin,
          evidenceOrigin: originOnly(entry.evidenceOrigin) || topOrigin,
          evidenceFrameId: count(entry.evidenceFrameId),
          timestamp: Number.isFinite(entry.timestamp) && entry.timestamp > 0 ? entry.timestamp : 0,
          expectedOutcome: entry.expectedOutcome,
          observedOutcome: entry.observedOutcome,
          score: Number.isFinite(entry.score) ? Math.round(Math.max(0, Math.min(100, entry.score))) : 0,
          policyVersion: typeof entry.policyVersion === 'string' && /^[a-zA-Z0-9_.-]{1,40}$/.test(entry.policyVersion) ? entry.policyVersion : 'unknown',
          reviewed: entry.reviewed === true,
          context: {
            inspectedFrames: count(context.inspectedFrames),
            uninspectedFrames: count(context.uninspectedFrames),
            pendingFrames: count(context.pendingFrames),
            coverageComplete: context.coverageComplete === true,
            reputationStatus: reputationStates.has(context.reputationStatus) ? context.reputationStatus : 'unknown',
            activeCategories: Array.isArray(context.activeCategories) ? [...new Set(context.activeCategories.filter((item) => categories.has(item)))] : []
          }
        };
      });
  }

  global.PhishGuard = global.PhishGuard || {};
  Object.assign(global.PhishGuard, { sanitizeFeedback, feedbackOrigin: originOnly });
  if (typeof module !== 'undefined' && module.exports) module.exports = { sanitizeFeedback, feedbackOrigin: originOnly };
})(typeof window !== 'undefined' ? window : globalThis);
