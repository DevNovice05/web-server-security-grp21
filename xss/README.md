# XSS – Stored (V1) and Reflected (V2)

**Implemented by:** Rehan Farishta (IIT2024267) – Group 21
**Variant owned:** V1 – Stored XSS (Reflected XSS also included)

## Run
```
pip install -r requirements.txt
python app.py        # open http://localhost:5000
```

| Variant | Vulnerable route | Secure route |
|---|---|---|
| Stored XSS | `/xss/vuln/guestbook` | `/xss/secure/guestbook` |
| Reflected XSS | `/xss/vuln/search?q=` | `/xss/secure/search?q=` |

**Payload:** `<script>alert('XSS: '+document.cookie)</script>` (alternative: `<img src=x onerror="alert('XSS')">`)

- **(a) Vulnerable code:** `xss_vuln_guestbook()` in `app.py` – `f"<li><b>{c['author']}</b>: {c['body']}</li>"` puts the stored comment into HTML unencoded.
- **(b) Exploit:** post the payload as a comment → the alert fires (showing the non-HttpOnly cookie) for every visitor of the guestbook.
- **(c) Root cause:** user input is rendered as HTML without output encoding, so the browser runs it as a script.
- **(d) Mitigation implemented:** context-aware HTML output encoding – `escape(c['body'])` in `xss_secure_guestbook()`. The same stored payload is shown as plain text (see `screenshots/xss_3_blocked_secure.png`).
- **(e) Other mitigations (theory):** framework auto-escaping (Jinja2/React), an HTML sanitiser such as DOMPurify for rich text, Content Security Policy (`script-src 'self'`) to block inline/foreign scripts, HttpOnly cookies so scripts cannot read the session cookie, and safe DOM sinks (`textContent` instead of `innerHTML`).
