const assert = require('assert');
const fs = require('fs');
const vm = require('vm');

const context = { self: {}, globalThis: {} };
context.globalThis = context.self;
vm.createContext(context);
vm.runInContext(
  fs.readFileSync('extension/src/shared/trained-char-model-data.js', 'utf8'),
  context
);
vm.runInContext(
  fs.readFileSync('extension/src/shared/char-model.js', 'utf8'),
  context
);

const predictor = context.self.PhishGuard.predictCharacterModel;
const phishing = predictor('https://paypal-security-update.example.net/verify');
const legitimate = predictor('https://google.com');

assert(phishing && phishing.probability > 0.99);
assert(legitimate && legitimate.probability < 0.99);
assert.strictEqual(phishing.modelVersion, 'char-url-tfidf-feeds-v0.2.0');
console.log('Character model browser inference validation passed.');
