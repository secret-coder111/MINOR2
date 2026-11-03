// Offline bridge used to compare the browser predictor with sklearn.
const fs = require('node:fs');
const vm = require('node:vm');
const root = require('node:path').resolve(__dirname, '..');
let input = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', chunk => { input += chunk; });
process.stdin.on('end', () => {
  const context = { URL, console, document: { title: 'An unrelated page' }, location: new URL('https://checker.example/') };
  context.window = context; context.self = context;
  vm.createContext(context);
  for (const name of ['url-core.js', 'url-model.js', 'url-analysis.js']) vm.runInContext(fs.readFileSync(`${root}/extension/demo/${name}`, 'utf8'), context);
  process.stdout.write(JSON.stringify(JSON.parse(input).map(url => {
    const result = context.PhishGuard.URLChecker.analyze(url);
    return { probability: result.probability, features: result.features, url: result.url, band: result.band };
  })));
});
