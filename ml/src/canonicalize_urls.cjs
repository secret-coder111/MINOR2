// Offline WHATWG URL bridge. stdin/stdout only; never opens a URL or network socket.
const fs = require('node:fs');
const values = JSON.parse(fs.readFileSync(0, 'utf8'));
process.stdout.write(JSON.stringify(values.map(value => {
  let text = String(value || '').trim();
  if (!text || /[\u0000-\u001f]/.test(text)) return '';
  if (!text.includes('://')) text = 'https://' + text;
  try {
    const url = new URL(text);
    return ['http:', 'https:'].includes(url.protocol) && url.hostname ? url.href : '';
  } catch (_) { return ''; }
})));
