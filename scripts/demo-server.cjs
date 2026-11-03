// Serve only the controlled fixtures, on the loopback interface. No dependencies.
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const root = path.resolve(__dirname, '../extension/demo');
const contentTypes = { '.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8', '.js': 'text/javascript; charset=utf-8' };
const files = new Set(['index.html', 'legitimate-demo.html', 'caution-demo.html', 'phishing-demo.html', 'dynamic-demo.html', 'public-examples.html', 'public-examples.js', 'demo.css', 'demo.js', 'journey.js', 'journey.css', 'professor-guide.html']);
for (const name of ['url-checker.html', 'url-checker.css', 'url-checker.js', 'url-analysis.js', 'url-core.js', 'url-model.js', 'page-check.js']) files.add(name);
const server = http.createServer((request, response) => {
  if (request.method !== 'GET' && request.method !== 'HEAD') {
    response.writeHead(405, { Allow: 'GET, HEAD' });
    response.end('Demo server does not accept form submissions.');
    return;
  }
  // A fixed file allowlist prevents encoded traversal and serving project data.
  let pathname;
  try { pathname = new URL(request.url, 'http://127.0.0.1').pathname; }
  catch (_) { response.writeHead(400); response.end('Invalid request URL.'); return; }
  const name = pathname === '/' ? 'index.html' : pathname.slice(1);
  if (!files.has(name)) { response.writeHead(404); response.end('Fixture not found.'); return; }
  fs.readFile(path.join(root, name), (error, data) => {
    if (error) { response.writeHead(500); response.end('Cannot read demo fixture.'); return; }
    response.writeHead(200, { 'Content-Type': contentTypes[path.extname(name)], 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' });
    response.end(request.method === 'HEAD' ? undefined : data);
  });
});
server.on('error', (error) => {
  console.error(error.code === 'EADDRINUSE' ? 'Port 8080 is busy. Stop the other demo server and retry.' : error.message);
  process.exitCode = 1;
});
server.listen(8080, '127.0.0.1', () => console.log('PhishGuard demo: http://127.0.0.1:8080/ (Ctrl+C to stop)'));
