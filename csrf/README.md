# CSRF — POST-based Forged Action (Auto-Submitting Form)

**Course:** Cyber Security (IT-30001) · Web Server Security
**Category:** Cross-Site Request Forgery (CSRF)
**Variant:** Variant 2 — POST-based forged action (auto-submitting form)
**Author:** *(your name · roll no.)*

A minimal, self-contained demo that **exploits** a CSRF vulnerability and then
**blocks the same exploit** with an anti-CSRF (synchronizer) token.

- **Victim app** — "Victim Bank", an HTTPS site with a logged-in *change-email* action (`victim/`).
- **Attacker site** — a separate origin serving one page that auto-submits a forged POST (`attacker/`).

Pure Node.js — **no `npm install` required**.

---

## How to run

Node.js ≥ 16. Two terminals.

```bash
# one-time: TLS cert for the victim app (already included in this folder;
# regenerate on macOS/Linux/Git-Bash with:)
npm run cert

# Terminal 1 — VULNERABLE victim app   (HTTPS, port 3443)
npm run victim

# Terminal 2 — attacker site           (HTTP, port 8080)
npm run attacker

# to demo the fix: stop Terminal 1, then run the DEFENDED build
npm run victim:secure
```

| Service | URL |
|---------|-----|
| Victim app | `https://localhost:3443` |
| Attacker page | `http://127.0.0.1:8080` |

Use **`localhost`** for the victim and **`127.0.0.1`** for the attacker so the
forged request is genuinely *cross-site*. Accept the one-time self-signed
certificate warning on the victim app.

> **Windows:** `npm run victim`, `victim:secure`, and `attacker` all work in
> PowerShell. `npm run cert` needs Git Bash + OpenSSL; a ready cert is already
> included in `certs/`, so you can skip it.

---

## Demonstration (what to show / screenshot)

**Part 1 — exploit succeeds** (`npm run victim`)
1. Log in at `https://localhost:3443`; note current email `victim@example.com`.
2. In the same browser, open `http://127.0.0.1:8080`.
3. The page auto-submits instantly → "Email updated — attacker@evil.com".
4. `/account` now shows **attacker@evil.com** — the victim clicked nothing. **← screenshot.**

**Part 2 — mitigation blocks it** (`npm run victim:secure`)
5. Log in again (email resets on restart) and revisit the attacker page.
6. The forged POST is rejected with **`403 — CSRF token missing or invalid`**; email unchanged. **← screenshot.**
7. The real form still works (it carries a valid token).

---

## The four required points (Table 2)

### (a) Vulnerable implementation
`victim/server.js` → the `POST /change-email` handler. With protection off it
updates the stored email straight from the request body, authorised by the
session cookie alone:

```js
db.user.email = b.email;   // state change; no proof the request came from our form
```

### (b) Working exploit
`attacker/attack.html` — a hidden form plus one line of JavaScript that submits
it on load, so no victim interaction is needed:

```html
<form id="forged" action="https://localhost:3443/change-email" method="POST">
  <input type="hidden" name="email" value="attacker@evil.com">
</form>
<script>document.getElementById('forged').submit();</script>
```

The victim is logged in to `localhost:3443`, so the browser attaches their
session cookie to this cross-site POST and the server accepts it as genuine.

### (c) Root cause
The state-changing request is accepted on the **session cookie alone**. The
browser attaches that cookie to any request to the victim site, including one
triggered by the attacker's page, and the server has no unpredictable,
per-session value proving the request originated from the real form.

### (d) Mitigation implemented — synchronizer (anti-CSRF) token
*(active when `CSRF_PROTECTION=on`)*

```js
// issued once per session, stored server-side
if (!sess.data.csrfToken) sess.data.csrfToken = crypto.randomBytes(32).toString('hex');

// verified on POST /change-email
if (!b.csrf_token || b.csrf_token !== sess.data.csrfToken) {
  return res.status(403) ...   // forged request blocked
}
```

The attacker's page can't **read** the token (same-origin policy) and can't
**guess** 256 bits of randomness, so the forged POST lacks a valid token → 403.

### (e) Other mitigations (theory)
- **SameSite cookies (`Lax` / `Strict`)** — the browser stops sending the cookie
  on cross-site requests. This is the modern default, which is why this demo
  sets the cookie to `SameSite=None` (set `COOKIE_SAMESITE = 'Lax'` in
  `victim/server.js` to watch SameSite alone defeat the attack).
- **Re-authentication for sensitive actions** — require the password / OTP first.
- **Avoid state-changing GET requests** — keep writes on POST, closing the GET variant.
- **Validate the `Origin` / `Referer` header** — reject foreign-origin writes.

> **Note:** `HttpOnly` does **not** prevent CSRF — it only hides the cookie from
> JavaScript; the browser still attaches it to the request.

---

## GET vs POST variant (context)

| | GET (Variant 1) | POST — mine (Variant 2) |
|--|-----------------|--------------------------|
| Payload | in the URL | forged in the request body |
| Trigger | `<img>`, link, redirect — no JS | auto-submitting `<form>` + 1 line of JS |
| When possible | only if the app allows a state change over GET | the realistic case for a well-built app |

Both succeed only because the browser auto-attaches the session cookie to the
cross-site request; neither attacker needs to read the response.

---

## Why HTTPS + a self-signed certificate?

The exploit needs the browser to send the session cookie on a cross-site POST.
Modern browsers default cookies to `SameSite=Lax`, which blocks that. So the
cookie is set to `SameSite=None` — which requires `Secure`, which requires
HTTPS, which on `localhost` requires a self-signed cert.
**SameSite=None → needs Secure → needs HTTPS → needs a cert.**

---

## Key points expected (viva readiness)

- **Define CSRF:** forcing a logged-in victim's browser to send a state-changing request they didn't intend; the site trusts the auto-attached session cookie.
- **Three conditions:** a state-changing action, cookie-based sessions, and no unguessable anti-CSRF token.
- **Why it worked despite SameSite defaults:** the cookie is `SameSite=None` (needs Secure → HTTPS → the self-signed cert).
- **Why cross-site / why `localhost` vs `127.0.0.1`:** the browser treats them as different sites, so the request is genuinely cross-site without editing the hosts file.
- **Why the token defeats it:** the attacker can't read it (same-origin policy) or guess 256 bits, so the forged POST has no valid token → 403.
- **CSRF is a *write* attack** — the attacker causes an action but never reads the response (unlike XSS).
- **HttpOnly does not stop CSRF** (common trick question).
- **Token placement:** hidden form field compared to the session's copy server-side; storing it in a second cookie instead is the "double-submit cookie" pattern.

## Layout

```
csrf/
├── victim/
│   ├── server.js     # HTTPS app; vulnerable + token-protected (CSRF_PROTECTION toggle)
│   └── secure.js     # cross-platform launcher for the defended build
├── attacker/
│   ├── attack.html   # auto-submitting forged POST form
│   └── server.js     # static server for the attacker page
├── certs/gen-cert.sh # self-signed localhost cert generator
├── package.json      # run scripts (no dependencies)
└── README.md
```