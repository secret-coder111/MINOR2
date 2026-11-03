(function (global) {
  // Legacy models have not been calibrated for this feature extraction version.
  global.PHISH_GUARD_MODEL_RELEASE = Object.freeze({
    mode: 'rules-only',
    policy_version: '0.4.0',
    feature_schema_version: '0.2.0',
    deployment_eligible: false,
    reason: 'Legacy URL models lack compatible extraction and independent deployment calibration.'
  });
})(typeof globalThis !== 'undefined' ? globalThis : self);
