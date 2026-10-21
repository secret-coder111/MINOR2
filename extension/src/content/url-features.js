window.PhishGuard = window.PhishGuard || {};

window.PhishGuard.extractUrlFeatures = function () {
  const href = window.location.href || '';
  const hostname = window.location.hostname || '';
  const protocol = window.location.protocol || '';
  const port = window.location.port || '';
  const title = document.title || '';

  const normalizedHost = hostname.toLowerCase();
  const suspiciousTerms = (window.PHISH_GUARD_CONSTANTS || {}).SUSPICIOUS_KEYWORDS || [];

  const keywordMatches = suspiciousTerms.filter((term) => {
    return href.toLowerCase().includes(term) || hostname.toLowerCase().includes(term);
  });

  const digits = (hostname.match(/\d/g) || []).length + (href.match(/\d/g) || []).length;
  const dotCount = (hostname.match(/\./g) || []).length + (href.match(/\./g) || []).length;
  const suspiciousCharCount = (hostname.match(/[@%]/g) || []).length + (href.match(/[@%]/g) || []).length + (hostname.match(/[-]{2,}/g) || []).length + (href.match(/[-]{2,}/g) || []).length;

  const hasPunycode = /xn--/i.test(hostname) || /[\u0080-\uFFFF]/.test(hostname);
  const hasIpAddress = /^\d{1,3}(?:\.\d{1,3}){3}$/.test(hostname) || /^\[[0-9a-fA-F:]+\]$/.test(hostname);
  const isLoopbackHost = hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '[::1]';
  const usesHttp = protocol === 'http:' && !isLoopbackHost;
  const hasUsualPort = !!port && !['80', '443'].includes(port) && !isLoopbackHost;
  const sharedHostingDomains = [
    'vercel.app', 'netlify.app', 'pages.dev', 'web.app', 'firebaseapp.com',
    'github.io', 'blogspot.com', 'glitch.me', 'onrender.com'
  ];
  const suspiciousHosting = sharedHostingDomains.some((domain) => normalizedHost.endsWith(`.${domain}`));
  const redirectCount = (() => {
    try {
      const navigation = performance.getEntriesByType('navigation')[0];
      return navigation && Number.isFinite(navigation.redirectCount) ? navigation.redirectCount : 0;
    } catch (error) {
      return 0;
    }
  })();

  const subdomainCount = normalizedHost && normalizedHost.split('.').length > 2
    ? Math.max(0, normalizedHost.split('.').length - 2)
    : 0;

  const entropy = (() => {
    const chars = hostname.replace(/\./g, '').split('');
    if (!chars.length) return 0;
    const counts = {};
    chars.forEach((ch) => {
      counts[ch] = (counts[ch] || 0) + 1;
    });
    let sum = 0;
    Object.values(counts).forEach((count) => {
      const p = count / chars.length;
      sum -= p * Math.log2(p);
    });
    return Number(sum.toFixed(2));
  })();

  const brands = ['google', 'microsoft', 'apple', 'paypal', 'amazon', 'icici', 'hdfc', 'sbi', 'axis'];
  const brandDomains = {
    google: ['google.com', 'google.co.in', 'google.co.uk'],
    microsoft: ['microsoft.com', 'live.com', 'office.com', 'microsoftonline.com'],
    apple: ['apple.com', 'icloud.com'],
    paypal: ['paypal.com'],
    amazon: [
      'amazon.com', 'amazon.in', 'amazon.co.uk', 'amazon.ca', 'amazon.com.au',
      'amazon.de', 'amazon.fr', 'amazon.it', 'amazon.es', 'amazon.co.jp',
      'amazon.com.mx', 'amazon.nl', 'amazon.sg', 'amazon.ae', 'amazon.sa'
    ],
    icici: ['icicibank.com'],
    hdfc: ['hdfcbank.com'],
    sbi: ['sbi.co.in', 'onlinesbi.sbi'],
    axis: ['axisbank.com']
  };

  const isOfficialBrandDomain = (brand, host) => {
    return (brandDomains[brand] || []).some((domain) => {
      return host === domain || host.endsWith(`.${domain}`);
    });
  };

  const matchedBrand = brands.find((brand) => {
    const text = (title + ' ' + href).toLowerCase();
    return text.includes(brand);
  });

  const officialBrandDomain = Boolean(
    matchedBrand && isOfficialBrandDomain(matchedBrand, normalizedHost)
  );

  const brandDomainMismatch = Number(Boolean(matchedBrand) && !officialBrandDomain);

  const titleMismatch = (() => {
    const hostBase = normalizedHost.split('.')[0] || '';
    const titleWords = (title || '').toLowerCase().replace(/[^a-z0-9\s]/g, ' ').split(/\s+/).filter(Boolean);

    if (isLoopbackHost) return 0;
    if (!titleWords.length || !hostBase) return 0;

    const hostAlias = hostBase.replace(/^(www|login|secure|signin|account|verify|update)$/g, '');

    if (!hostAlias) return 0;
    return titleWords.includes(hostAlias) ? 0 : 1;
  })();

  return {
    hostname: normalizedHost,
    is_official_brand_domain: officialBrandDomain ? 1 : 0,
    url_length: href.length,
    hostname_length: hostname.length,
    subdomain_count: subdomainCount,
    dot_count: dotCount,
    digit_count: digits,
    suspicious_char_count: suspiciousCharCount,
    has_ip_address: hasIpAddress ? 1 : 0,
    uses_http: usesHttp ? 1 : 0,
    has_punycode: hasPunycode ? 1 : 0,
    suspicious_keyword_count: keywordMatches.length,
    hostname_entropy: entropy,
    brand_domain_mismatch: brandDomainMismatch,
    brand_name_in_url: Number(brands.some((brand) => href.toLowerCase().includes(brand))),
    page_title_mismatch: titleMismatch,
    has_unusual_port: hasUsualPort ? 1 : 0,
    suspicious_hosting: suspiciousHosting ? 1 : 0,
    redirect_count: redirectCount,
    domain_registration_age_days: 0
  };
};
