// ============================================================================
//  ATTACKER SITE  —  a different origin from the victim app.
//  Serves one page, attack.html, which auto-submits a forged POST to the
//  victim. Served on 127.0.0.1 while the victim is on localhost so the request
//  is genuinely CROSS-SITE (different site => SameSite rules apply).
// ============================================================================
const http = require('http');
const fs   = require('fs');
const path = require('path');

const PORT = 8080;
const html = fs.readFileSync(path.join(__dirname, 'attack.html'));

http.createServer((req, res) => {
  res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
  res.end(html);
}).listen(PORT, () => {
  console.log(`\n  Attacker site (HTTP) running at  http://127.0.0.1:${PORT}\n`);
});
