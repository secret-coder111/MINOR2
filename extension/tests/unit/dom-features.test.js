const assert = require('node:assert/strict');
const extract = require('./extract-fixture.cjs');

const result = extract(`
  <title>Example Login</title>
  <div hidden>PayPal hidden text</div>
  <div style="display: none">Google hidden text</div>
  <div>Welcome to the account</div>
  <iframe hidden></iframe>
  <iframe style="display: none"></iframe>
  <meta http-equiv="ReFrEsH" content="0;url=https://example.test">
  <script>eval(atob("encoded"))</script>
`, 'https://example.test/login');
assert.equal(result.brand_name_in_visible_text, 0);
assert.equal(result.hidden_iframe_count, 2);
assert.equal(result.meta_refresh_count, 1);
assert(result.obfuscated_script_score >= 0.5);
assert.equal(result.frontpage_is_landing_page, 0);
assert.equal(result.frontpage_has_credential_form, 0);

const frames = extract(`
  <iframe src="/help"></iframe><iframe width="300" height="150"></iframe>
  <iframe width="0"></iframe><iframe height="0px"></iframe>
  <iframe style="width:0px"></iframe><iframe style="opacity:0"></iframe>
  <div hidden><iframe></iframe></div><style>.gone { display: none }</style><iframe class="gone"></iframe>
`, 'https://example.test/');
assert.equal(frames.hidden_iframe_count, 6, 'missing dimensions and default rendered dimensions are not hidden');
const frontpage = extract(`
  <title>PayPal Sign In</title>
  <form method="post"><input type="password"></form>
  <iframe hidden></iframe>
  <meta http-equiv="refresh" content="0;url=https://example.test">
  <script>eval(atob("encoded"))</script>
`, 'https://paypal-security.example/');
assert.equal(frontpage.frontpage_is_landing_page, 1);
assert.equal(frontpage.frontpage_has_credential_form, 1);
assert.equal(frontpage.frontpage_suspicious_signal_count, 3, 'only weak structural observations contribute');
const ordinaryRoot = extract(`
  <title>Google</title><p>Google sign in</p>
  <form action="/session" method="post"><input type="password"></form>
  <iframe src="/help"></iframe><input type="hidden"><input type="hidden"><input type="hidden">
  <script>document.querySelector("input").addEventListener("input", () => {});</script>
`, 'https://accounts.google.com/');
assert.equal(ordinaryRoot.hidden_iframe_count, 0);
assert.equal(ordinaryRoot.frontpage_suspicious_signal_count, 0, 'ordinary root logins and branding are not suspicious signals');
assert.equal(ordinaryRoot.credential_submission_script, 0);
assert.equal(ordinaryRoot.hidden_field_count, 3, 'CSRF fields remain a neutral count');
const pineapple = extract('<title>Pineapple Club</title><p>Pineapple club members</p>', 'https://college.example/');
assert.equal(pineapple.brand_name_in_title, 0);
assert.equal(pineapple.brand_name_in_visible_text, 0);
const basedScripts = extract('<base href="https://cdn.example.org/"><script src="app.js"></script><script>eval("hello")</script>', 'https://college.example/');
assert.equal(basedScripts.external_script_count, 1);
assert.equal(basedScripts.obfuscated_script_score, 0.25);
const dataBlocks = extract('<script type="application/ld+json">{"example":"eval(atob(data))"}</script>' +
  '<script type="text/plain" src="https://cdn.example.org/data"></script>', 'https://college.example/');
assert.equal(dataBlocks.obfuscated_script_score, 0, 'non-executable data blocks are not obfuscated JavaScript');
assert.equal(dataBlocks.external_script_count, 0);
const privateText = extract('<textarea>PayPal</textarea><select><option>Google</option></select>' +
  '<div contenteditable><p>Microsoft</p></div>', 'https://college.example/', (window) => {
  Object.defineProperty(window.document.body, 'innerText', { get() { throw new Error('Whole-body text may include user input'); } });
  for (const node of window.document.querySelectorAll('textarea, option, [contenteditable] p')) {
    Object.defineProperty(node.firstChild, 'nodeValue', { get() { throw new Error('Private control/editor text was read'); } });
  }
});
assert.equal(privateText.brand_name_in_visible_text, 0, 'controls and inherited editors never contribute brand text');
const shadowBrand = extract('<div id="component">Google undistributed content</div>', 'https://college.example/', (window) => {
  window.document.getElementById('component').attachShadow({ mode: 'open' }).innerHTML = '<p>PayPal</p><iframe hidden></iframe>';
});
assert.equal(shadowBrand.brand_name_in_visible_text, 1, 'visible open-shadow text participates in brand metadata');
assert.equal(shadowBrand.hidden_iframe_count, 1);
const shadowOrdinary = extract('<div id="component">Google undistributed content</div>', 'https://college.example/', (window) => {
  window.document.getElementById('component').attachShadow({ mode: 'open' }).innerHTML = '<p>Member portal</p>';
});
assert.equal(shadowOrdinary.brand_name_in_visible_text, 0, 'undistributed light-DOM text is not visible branding');
const restoredText = extract('<div style="visibility:hidden">Google<span style="visibility:visible">Member portal</span></div>', 'https://college.example/');
assert.equal(restoredText.brand_name_in_visible_text, 0, 'CSS hidden text does not establish visible branding');

console.log('DOM feature extraction regression tests passed.');
