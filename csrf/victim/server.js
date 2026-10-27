// ============================================================================
//  VICTIM APPLICATION  —  "Victim Bank"
//  CSRF category · Variant 2: POST-based forged action (auto-submitting form)
//
//  Pure Node.js — no npm install needed. Runs over HTTPS so the session cookie
//  can be SameSite=None; Secure, which is what lets the browser attach it to
//  the attacker's cross-site POST (see certs/gen-cert.sh for the full reason).
//
//  One environment flag switches between the vulnerable and defended build:
//      CSRF_PROTECTION=off  -> vulnerable   (default)  ->  npm run victim
//      CSRF_PROTECTION=on   -> token defence active     ->  npm run victim:secure
// ============================================================================
const fs     = require('fs');
const path   = require('path');
const https  = require('https');
const crypto = require('crypto');

const PORT      = 3443;
const PROTECTED = (process.env.CSRF_PROTECTION || 'off').toLowerCase() === 'on';

// The cookie's SameSite policy. 'None' (with Secure) lets the browser send the
// cookie cross-site, which is required for the classic attack to reproduce.
// Change to 'Lax' to watch SameSite alone block the forged POST.
const COOKIE_SAMESITE = 'None';

// --- tiny in-memory "database" + session store ------------------------------
const db = { user: { username: 'victim', password: 'password123', email: 'victim@example.com' } };
const sessions = new Map();           // sid -> { user, csrfToken }

// --- helpers ----------------------------------------------------------------
function parseCookies(req) {
  const out = {};
  (req.headers.cookie || '').split(';').forEach(p => {
    const i = p.indexOf('=');
    if (i > -1) out[p.slice(0, i).trim()] = decodeURIComponent(p.slice(i + 1).trim());
  });
  return out;
}
function getSession(req) {
  const sid = parseCookies(req).sid;
  return (sid && sessions.has(sid)) ? { sid, data: sessions.get(sid) } : null;
}
function readBody(req) {
  return new Promise(resolve => {
    let b = '';
    req.on('data', c => { b += c; if (b.length > 1e6) req.destroy(); });
    req.on('end', () => {
      const params = {};
      new URLSearchParams(b).forEach((v, k) => { params[k] = v; });
      resolve(params);
    });
  });
}
function send(res, status, html, headers = {}) {
  res.writeHead(status, Object.assign({ 'Content-Type': 'text/html; charset=utf-8' }, headers));
  res.end(html);
}
const redirect = (res, loc, headers = {}) => send(res, 302, '', Object.assign({ Location: loc }, headers));

const badge = () => `<span class="badge ${PROTECTED ? 'on' : 'off'}">PROTECTION ${PROTECTED ? 'ON' : 'OFF'}</span>`;
const page = (body) => `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Victim Bank</title>
<style>
 body{font-family:system-ui,Arial,sans-serif;max-width:640px;margin:40px auto;padding:0 16px;color:#1f2733}
 h2{margin:0 0 4px} .card{border:1px solid #d7dbe0;border-radius:10px;padding:18px 20px;margin:16px 0}
 label{font-size:13px;color:#6b7280} input{padding:9px;border:1px solid #cbd2d9;border-radius:6px;width:100%;box-sizing:border-box;margin:4px 0 12px}
 button{padding:9px 18px;border:0;border-radius:6px;background:#33415c;color:#fff;cursor:pointer;font-size:14px}
 .email{font-weight:700} a{color:#33415c}
 .badge{font-size:11px;font-weight:700;letter-spacing:.5px;padding:3px 9px;border-radius:999px}
 .on{background:#e6f4ea;color:#1a7f37} .off{background:#fde8e8;color:#b42318}
</style></head><body>${body}</body></html>`;

// --- request handler --------------------------------------------------------
const handler = async (req, res) => {
  const url = req.url.split('?')[0];
  const sess = getSession(req);

  if (url === '/') return redirect(res, sess ? '/account' : '/login');

  if (url === '/login' && req.method === 'GET') {
    return send(res, 200, page(`
      <h2>Victim Bank</h2><p>Sign in &nbsp; ${badge()}</p>
      <div class="card"><form method="POST" action="/login">
        <label>Username</label><input name="username" value="victim">
        <label>Password</label><input type="password" name="password" value="password123">
        <button type="submit">Log in</button>
      </form></div>
      <p style="color:#6b7280;font-size:13px">Demo credentials are pre-filled.</p>`));
  }

  if (url === '/login' && req.method === 'POST') {
    const b = await readBody(req);
    if (b.username === db.user.username && b.password === db.user.password) {
      const sid = crypto.randomBytes(24).toString('hex');
      sessions.set(sid, { user: b.username });
      // SameSite=None; Secure => browser will send this cookie cross-site.
      return redirect(res, '/account', {
        'Set-Cookie': `sid=${sid}; HttpOnly; Secure; SameSite=${COOKIE_SAMESITE}; Path=/`
      });
    }
    return send(res, 200, page('<p>Invalid credentials. <a href="/login">Try again</a></p>'));
  }

  if (url === '/account' && req.method === 'GET') {
    if (!sess) return redirect(res, '/login');
    let tokenField = '';
    if (PROTECTED) {
      // MITIGATION: bind an unguessable token to the session (issued once).
      if (!sess.data.csrfToken) sess.data.csrfToken = crypto.randomBytes(32).toString('hex');
      tokenField = `<input type="hidden" name="csrf_token" value="${sess.data.csrfToken}">`;
    }
    return send(res, 200, page(`
      <h2>Your account</h2><p>${badge()} &nbsp; <a href="/logout">log out</a></p>
      <div class="card">
        <p>Signed in as <b>${sess.data.user}</b></p>
        <p>Current email: <span class="email" id="current-email">${db.user.email}</span></p>
      </div>
      <div class="card">
        <h3 style="margin-top:0">Change email</h3>
        <form method="POST" action="/change-email">
          ${tokenField}
          <label>New email</label><input name="email" value="${db.user.email}">
          <button type="submit">Update email</button>
        </form>
      </div>`));
  }

  // ==========================================================================
  //  (a) THE VULNERABLE CODE PATH — the state-changing action under attack
  // ==========================================================================
  if (url === '/change-email' && req.method === 'POST') {
    if (!sess) return redirect(res, '/login');
    const b = await readBody(req);

    if (PROTECTED) {
      // (d) MITIGATION — synchronizer-token check. The genuine form carries a
      // token the attacker's page cannot read (same-origin policy) or guess.
      if (!b.csrf_token || b.csrf_token !== sess.data.csrfToken) {
        return send(res, 403, page(`
          <h2 style="color:#b42318">403 — request blocked</h2>
          <p>CSRF token missing or invalid. The forged request was rejected.</p>
          <p><a href="/account">Back to account</a></p>`));
      }
    }

    // (c) ROOT CAUSE: with protection off, the request is authorised by the
    // session cookie ALONE. There is no proof it came from the real form, so a
    // forged cross-site POST is accepted and the state changes.
    db.user.email = b.email;

    return send(res, 200, page(`
      <h2>Email updated</h2>
      <div class="card"><p>Email is now: <span class="email">${db.user.email}</span></p></div>
      <p>${badge()} &nbsp; <a href="/account">Back to account</a></p>`));
  }

  if (url === '/logout') {
    if (sess) sessions.delete(sess.sid);
    return redirect(res, '/login', { 'Set-Cookie': 'sid=; Max-Age=0; Path=/' });
  }

  send(res, 404, page('<p>Not found</p>'));
};

// --- start HTTPS server ------------------------------------------------------
const credsDir = path.join(__dirname, '..', 'certs');
let creds;
try {
  creds = {
    key:  fs.readFileSync(path.join(credsDir, 'key.pem')),
    cert: fs.readFileSync(path.join(credsDir, 'cert.pem')),
  };
} catch (e) {
  console.error('\n  Missing TLS certificate. Run  `npm run cert`  (or bash certs/gen-cert.sh) first.\n');
  process.exit(1);
}

https.createServer(creds, handler).listen(PORT, () => {
  console.log(`\n  Victim app (HTTPS) running at  https://localhost:${PORT}`);
  console.log(`  CSRF_PROTECTION = ${PROTECTED ? 'ON  (token defence active)' : 'OFF (vulnerable)'}\n`);
});
