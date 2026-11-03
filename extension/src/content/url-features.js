window.PhishGuard = window.PhishGuard || {};

// These ownership mappings describe an identity claim; they never exempt a page from other checks.
window.PhishGuard.getBrandInfo = (() => {
  let reviewedAliases;
  return function (pageUrl, title) {
  const brandDomains = {
    // Reviewed against https://www.google.com/supported_domains on 2026-10-25.
    // Exact suffix boundaries below describe ownership, never a safety exemption.
    google: (`google.com google.ad google.ae google.com.af google.com.ag google.al google.am google.co.ao
      google.com.ar google.as google.at google.com.au google.az google.ba google.com.bd google.be google.bf
      google.bg google.com.bh google.bi google.bj google.com.bn google.com.bo google.com.br google.bs google.bt
      google.co.bw google.by google.com.bz google.ca google.cd google.cf google.cg google.ch google.ci google.co.ck
      google.cl google.cm google.cn google.com.co google.co.cr google.com.cu google.cv google.com.cy google.cz
      google.de google.dj google.dk google.dm google.com.do google.dz google.com.ec google.ee google.com.eg
      google.es google.com.et google.fi google.com.fj google.fm google.fr google.ga google.ge google.gg
      google.com.gh google.com.gi google.gl google.gm google.gr google.com.gt google.gy google.com.hk google.hn
      google.hr google.ht google.hu google.co.id google.ie google.co.il google.im google.co.in google.iq google.is
      google.it google.je google.com.jm google.jo google.co.jp google.co.ke google.com.kh google.ki google.kg
      google.co.kr google.com.kw google.kz google.la google.com.lb google.li google.lk google.co.ls google.lt
      google.lu google.lv google.com.ly google.co.ma google.md google.me google.mg google.mk google.ml
      google.com.mm google.mn google.com.mt google.mu google.mv google.mw google.com.mx google.com.my
      google.co.mz google.com.na google.com.ng google.com.ni google.ne google.nl google.no google.com.np
      google.nr google.nu google.co.nz google.com.om google.com.pa google.com.pe google.com.pg google.com.ph
      google.com.pk google.pl google.pn google.com.pr google.ps google.pt google.com.py google.com.qa google.ro
      google.ru google.rw google.com.sa google.com.sb google.sc google.se google.com.sg google.sh google.si
      google.sk google.com.sl google.sn google.so google.sm google.sr google.st google.com.sv google.td google.tg
      google.co.th google.com.tj google.tl google.tm google.tn google.to google.com.tr google.tt google.com.tw
      google.co.tz google.com.ua google.co.ug google.co.uk google.com.uy google.co.uz google.com.vc google.co.ve
      google.co.vi google.com.vn google.vu google.ws google.rs google.co.za google.co.zm google.co.zw google.cat`).split(/\s+/),
    microsoft: ['microsoft.com', 'live.com', 'office.com', 'microsoftonline.com'],
    apple: ['apple.com', 'icloud.com'],
    paypal: ['paypal.com'],
    amazon: [
      'amazon.com', 'amazon.in', 'amazon.co.uk', 'amazon.ca', 'amazon.com.au',
      'amazon.de', 'amazon.fr', 'amazon.it', 'amazon.es', 'amazon.co.jp',
      'amazon.com.mx', 'amazon.nl', 'amazon.sg', 'amazon.ae', 'amazon.sa'
    ],
    // Bank migrations reviewed on 2026-10-25 via their existing official sites:
    // icicibank.com -> icici.bank.in, axisbank.com -> axis.bank.in,
    // bank.sbi/redirect/ -> sbi.bank.in, hdfc.bank.in/important-messages/all-new-website.
    icici: ['icicibank.com', 'icici.bank.in'],
    hdfc: ['hdfcbank.com', 'hdfc.bank.in'],
    sbi: ['sbi.co.in', 'onlinesbi.sbi', 'bank.sbi', 'sbi.bank.in'],
    axis: ['axisbank.com', 'axis.bank.in']
  };
  let hostname = '';
  try { hostname = new URL(pageUrl).hostname.toLowerCase().replace(/\.$/, ''); } catch (error) {}
  const titleText = String(title || '').toLowerCase();
  const titleBrands = [];
  const claimedBrands = [];
  const hostBrands = [];
  Object.keys(brandDomains).forEach((brand) => {
    const titlePattern = new RegExp('(?:^|[^a-z0-9])' + brand + '(?=$|[^a-z0-9])', 'g');
    const matches = Array.from(titleText.matchAll(titlePattern));
    if (matches.length) {
      titleBrands.push(brand);
      // A federated provider mention does not by itself claim ownership of this page.
      const identityMention = matches.some((match) => {
        const providerPrefix = titleText.slice(0, match.index + match[0].length - brand.length);
        return !/\b(?:sign\s*in|log\s*in|continue|connect|register|authenticate)\s+(?:with|via|using)\s+(?:(?:a|an|the|your|my)\s+)?$/i.test(providerPrefix);
      });
      if (identityMention) {
        claimedBrands.push(brand);
      }
    }
    if (new RegExp('(?:^|[-.])' + brand + '(?=$|[-.])', 'i').test(hostname)) {
      hostBrands.push(brand);
      if (!claimedBrands.includes(brand)) claimedBrands.push(brand);
    }
  });
  const ownsHost = (brand) => (brandDomains[brand] || []).some((domain) => hostname === domain || hostname.endsWith('.' + domain));
  const officialBrands = Object.keys(brandDomains).filter(ownsHost);
  // Deliberately finite: exactly one reviewed visual substitution, never edit
  // distance or a general IDN/punycode penalty. Build ASCII IDNA aliases once.
  // This covers paypa1/micros0ft and a single Cyrillic homograph character;
  // other spellings remain outside this detector's stated coverage.
  if (!reviewedAliases) {
    const substitutions = { a: ['4', '\u0430'], c: ['\u0441'], e: ['3', '\u0435'],
      i: ['1', '\u0456'], l: ['1', '\u04cf'], o: ['0', '\u043e'],
      p: ['\u0440'], x: ['\u0445'], y: ['\u0443'] };
    reviewedAliases = {};
    Object.entries(brandDomains).forEach(([brand, domains]) => {
      const aliases = new Set();
      new Set([brand, ...domains.map((domain) => domain.split('.')[0])]).forEach((label) => {
        Array.from(label).forEach((letter, index) => (substitutions[letter] || []).forEach((replacement) => {
          const alias = label.slice(0, index) + replacement + label.slice(index + 1);
          try { aliases.add(new URL('https://' + alias + '.invalid').hostname.split('.')[0]); } catch (error) {}
        }));
      });
      reviewedAliases[brand] = aliases;
    });
  }
  const utils = window.PhishGuard.domainUtils;
  // PRIVATE PSL entries matter: paypa1.github.io is one tenant, while an
  // unrelated paypa1 subdomain below some-other-tenant.github.io is not.
  const registrable = utils ? utils.getRegistrableDomain(hostname) : '';
  const registrableLabel = registrable ? registrable.split('.')[0] : '';
  const addressDeceptionBrands = Object.keys(brandDomains).filter((brand) => !ownsHost(brand)
    && (reviewedAliases[brand].has(registrableLabel)
      || brandDomains[brand].some((domain) => hostname.startsWith(domain + '.')
        || hostname.includes('.' + domain + '.'))));
  // A platform's owned identity cannot cancel an unrelated identity claim.
  const mismatchedBrands = claimedBrands.filter((brand) => !ownsHost(brand));
  const mismatch = mismatchedBrands.length > 0;
  return {
    matchedBrands: Array.from(new Set([...titleBrands, ...hostBrands])),
    titleBrands,
    claimedBrands,
    mismatchedBrands,
    officialBrands,
    addressDeceptionBrands,
    brandAddressDeception: addressDeceptionBrands.length > 0,
    officialBrandDomain: officialBrands.length > 0,
    brandDomainMismatch: mismatch,
    brandIdentityClaim: claimedBrands.length > 0,
    brandNameInUrl: hostBrands.length > 0
  };
  };
})();

window.PhishGuard.extractUrlFeatures = function (address) {
  // An explicit address supports offline URL checks without borrowing the
  // checker page's title, navigation history or document context.
  const explicit = typeof address === 'string';
  const context = !explicit && window.PhishGuard.getPageContext ? window.PhishGuard.getPageContext() : null;
  let page = explicit ? new URL(address) : window.location;
  try { if (context && context.url) page = new URL(context.url); } catch (error) {}
  const href = page.href || '';
  const hostname = page.hostname || '';
  const protocol = page.protocol || '';
  const port = page.port || '';
  const normalizedHost = hostname.toLowerCase().replace(/\.$/, '');
  const utils = window.PhishGuard.domainUtils;
  const suspiciousTerms = (window.PHISH_GUARD_CONSTANTS || {}).SUSPICIOUS_KEYWORDS || [];
  const keywordMatches = suspiciousTerms.filter((term) => href.toLowerCase().includes(term.toLowerCase()));
  // Count once: the hostname is already part of the URL.
  const digits = (href.match(/\d/g) || []).length;
  const dotCount = (href.match(/\./g) || []).length;
  const suspiciousCharCount = (href.match(/[@%]/g) || []).length + (href.match(/[-]{2,}/g) || []).length;
  const hasPunycode = /xn--/i.test(hostname) || /[\u0080-\uFFFF]/.test(hostname);
  const hasIpAddress = utils ? utils.isIpAddress(hostname) : /^\d{1,3}(?:\.\d{1,3}){3}$/.test(hostname) || /^\[[0-9a-f:]+\]$/i.test(hostname);
  const isLoopbackHost = utils ? utils.isLoopback(hostname) : ['localhost', '127.0.0.1', '[::1]'].includes(hostname);
  const sharedHostingDomains = [
    'vercel.app', 'netlify.app', 'pages.dev', 'web.app', 'firebaseapp.com',
    'github.io', 'blogspot.com', 'glitch.me', 'onrender.com'
  ];
  const suspiciousHosting = sharedHostingDomains.some((domain) => normalizedHost.endsWith('.' + domain));
  let redirectCount = 0;
  try {
    const navigation = !explicit && performance.getEntriesByType('navigation')[0];
    if (navigation && Number.isFinite(navigation.redirectCount)) redirectCount = navigation.redirectCount;
  } catch (error) {}
  const registrable = utils ? utils.getRegistrableDomain(normalizedHost) : normalizedHost;
  const subdomainCount = !hasIpAddress && registrable && normalizedHost !== registrable
    ? Math.max(0, normalizedHost.split('.').length - registrable.split('.').length) : 0;
  const chars = hostname.replace(/\./g, '').split('');
  const counts = {};
  chars.forEach((ch) => { counts[ch] = (counts[ch] || 0) + 1; });
  let entropy = 0;
  Object.values(counts).forEach((count) => {
    const p = count / chars.length;
    entropy -= p * Math.log2(p);
  });
  const brand = window.PhishGuard.getBrandInfo(href, explicit ? '' : document.title || '');
  return {
    hostname: normalizedHost,
    is_official_brand_domain: Number(brand.officialBrandDomain),
    brand_identity_claim: Number(brand.brandIdentityClaim),
    brand_address_deception: Number(brand.brandAddressDeception),
    url_length: href.length,
    hostname_length: hostname.length,
    subdomain_count: subdomainCount,
    dot_count: dotCount,
    digit_count: digits,
    suspicious_char_count: suspiciousCharCount,
    has_ip_address: Number(hasIpAddress),
    uses_http: Number(protocol === 'http:' && !isLoopbackHost),
    has_punycode: Number(hasPunycode),
    suspicious_keyword_count: keywordMatches.length,
    hostname_entropy: Number(entropy.toFixed(2)),
    brand_domain_mismatch: Number(brand.brandDomainMismatch),
    brand_name_in_url: Number(brand.brandNameInUrl),
    page_title_mismatch: Number(brand.brandDomainMismatch),
    has_unusual_port: Number(Boolean(port) && !['80', '443'].includes(port) && !isLoopbackHost),
    suspicious_hosting: Number(suspiciousHosting),
    redirect_count: redirectCount,
    domain_registration_age_days: 0
  };
};
