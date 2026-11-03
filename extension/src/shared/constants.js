var phishGuardGlobal = typeof window !== 'undefined' ? window : self;
phishGuardGlobal.PHISH_GUARD_CONSTANTS = {
  // These terms are descriptive URL features, never independent phishing evidence.
  SUSPICIOUS_KEYWORDS: ['login', 'verify', 'secure', 'account', 'update', 'wallet',
    'bank', 'signin', 'payment', 'confirm']
};
