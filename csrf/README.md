# CSRF — POST-based Forged Action (Auto-Submitting Form)

**Course:** Cyber Security (IT-30001) · Web Server Security
**Category:** Cross-Site Request Forgery (CSRF)
**Variant:** Variant 2 — POST-based forged action (auto-submitting form)
**Author:** *(Aditya tiwari . IIT2024255)*

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
