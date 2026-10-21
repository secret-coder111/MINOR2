const { JSDOM } = require('jsdom');
const fs = require('fs');
const path = require('path');

const base = path.join(process.cwd(), 'extension');
const files = [
  'src/shared/feature-schema.js',
  'src/shared/constants.js',
  'src/shared/browser-api.js',
  'src/shared/risk-score.js',
  'src/content/url-features.js',
  'src/content/dom-features.js',
  'src/content/form-features.js',
  'src/content/explanation-mapping.js'
];
const pageUrls = {
  'legitimate-demo.html': 'https://www.contoso.com/login',
  'phishing-demo.html': 'https://paypal-security-update.example.net/verify'
};

for (const pageName of ['legitimate-demo.html', 'phishing-demo.html']) {
  const html = fs.readFileSync(path.join(base, 'demo', pageName), 'utf8');
  const dom = new JSDOM(html, { url: pageUrls[pageName] });
  const { window } = dom;
  global.window = window;
  global.document = window.document;
  global.location = window.location;
  global.navigator = window.navigator;

  files.forEach((file) => {
    const scriptText = fs.readFileSync(path.join(base, file), 'utf8');
    window.eval(scriptText);
  });

  const brandText = ((document.body && (document.body.innerText || document.body.textContent)) || '').toLowerCase();
  const titleText = (document.title || '').toLowerCase();

  const featureObject = {
    ...window.PhishGuard.extractUrlFeatures(),
    ...window.PhishGuard.extractFormFeatures(),
    ...window.PhishGuard.extractDomFeatures(),
    brand_name_in_url: /google|microsoft|apple|paypal|amazon|bank|icici|hdfc|sbi|axis/i.test(window.location.href) ? 1 : 0,
    brand_name_in_title: /google|microsoft|apple|paypal|amazon|bank|icici|hdfc|sbi|axis/i.test(titleText) ? 1 : 0,
    brand_name_in_visible_text: /google|microsoft|apple|paypal|amazon|bank|icici|hdfc|sbi|axis/i.test(brandText) ? 1 : 0,
    model_version: 'v0.1.0'
  };

  const score = window.PhishGuard.scoreFeatures(featureObject);
  console.log(JSON.stringify({
    page: pageName,
    score,
    label: window.PhishGuard.getRiskLevel(score),
    password: featureObject.has_password_input,
    crossDomain: featureObject.cross_domain_form_action,
    http: featureObject.uses_http,
    url: window.location.href
  }, null, 2));
}
