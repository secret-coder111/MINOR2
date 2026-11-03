const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const input = JSON.parse(fs.readFileSync(0, 'utf8'));
const root = path.resolve(__dirname, '../..');
const context = { self: null };
context.self = context;
vm.createContext(context);
['extension/src/shared/feature-schema.js', 'extension/src/shared/trained-model.js'].forEach(name => {
  vm.runInContext(fs.readFileSync(path.join(root, name), 'utf8'), context);
});
vm.runInContext(fs.readFileSync(input.modelPath, 'utf8'), context);
process.stdout.write(JSON.stringify(input.features.map(row => context.PhishGuard.predictTrainedModel(row))));
