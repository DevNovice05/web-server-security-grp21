"""
Stored & Reflected XSS demo - Group 21 (Rehan Farishta, IIT2024267)
Web Server Security Assignment - IIIT Allahabad, Cyber Security (IT-30001)
-------------------------------------------------------------------------
A deliberately vulnerable Flask application for LOCAL classroom demonstration only.
Every variant has TWO routes:
    /<category>/vuln/...    -> the vulnerable implementation   (marked  # VULNERABLE)
    /<category>/secure/...  -> the same feature with ONE fix   (marked  # SECURE / MITIGATION)

Run:   pip install -r requirements.txt
       python app.py            -> open http://localhost:5000
Never deploy this on a public server.
"""

import os
import sqlite3

from flask import Flask, request, redirect, render_template_string, g
from markupsafe import Markup, escape

app = Flask(__name__)
app.secret_key = "demo-secret-key-change-me"
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "lab.db")


# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = sqlite3.connect(DB_PATH)
    db.executescript("""
        DROP TABLE IF EXISTS comments;
        CREATE TABLE comments (id INTEGER PRIMARY KEY, author TEXT, body TEXT);

        INSERT INTO comments (author, body) VALUES
            ('alice', 'Great site!'), ('bob', 'Nice products.');
    """)
    db.commit()
    db.close()


# ---------------------------------------------------------------------------
# Tiny layout helper (all pages share it)
# ---------------------------------------------------------------------------
LAYOUT = """<!doctype html><html><head><meta charset="utf-8">
<title>{{ title }} - WebSec Lab</title>
<style>
 body{font-family:system-ui,Segoe UI,Arial;margin:0;background:#f5f6f8;color:#1d2330}
 header{background:#1d2330;color:#fff;padding:12px 24px}
 header a{color:#9cc3ff;margin-right:14px;text-decoration:none}
 main{max-width:900px;margin:24px auto;background:#fff;padding:24px 28px;border-radius:10px;
      box-shadow:0 1px 4px rgba(0,0,0,.08)}
 .vuln{border-left:6px solid #d93025}.secure{border-left:6px solid #188038}
 .tag{display:inline-block;padding:2px 10px;border-radius:12px;font-size:13px;color:#fff}
 .tag.v{background:#d93025}.tag.s{background:#188038}
 pre,code{background:#f0f2f5;padding:2px 6px;border-radius:4px}
 pre{padding:12px;overflow:auto;white-space:pre-wrap}
 input[type=text],input[type=password],input[type=email],textarea{padding:8px;width:340px;
      border:1px solid #c3c8d0;border-radius:6px}
 button{padding:8px 16px;border:0;border-radius:6px;background:#2f6fde;color:#fff;cursor:pointer}
 table{border-collapse:collapse}td,th{border:1px solid #d0d4da;padding:6px 10px}
 .ok{color:#188038;font-weight:600}.err{color:#d93025;font-weight:600}
</style></head><body>
<header><b>XSS Lab</b> &nbsp; <a href="/">Home</a> <a href="/reset">Reset DB</a></header>
<main class="{{ cls }}">
{% if cls == 'vuln' %}<span class="tag v">VULNERABLE</span>{% elif cls == 'secure' %}<span class="tag s">SECURE</span>{% endif %}
<h2>{{ title }}</h2>
{{ body }}
</main></body></html>"""


def page(title, body, cls=""):
    # body is trusted HTML built by this program; untrusted parts are escaped (or deliberately
    # not escaped in the VULNERABLE routes) before being put into it.
    return render_template_string(LAYOUT, title=title, body=Markup(body), cls=cls)


@app.route("/")
def index():
    body = """<table><tr><th>Variant</th><th>Vulnerable</th><th>Secure</th></tr>
    <tr><td>V1 Stored XSS (guestbook)</td><td><a href="/xss/vuln/guestbook">vulnerable</a></td>
        <td><a href="/xss/secure/guestbook">secure</a></td></tr>
    <tr><td>V2 Reflected XSS (search)</td><td><a href="/xss/vuln/search">vulnerable</a></td>
        <td><a href="/xss/secure/search">secure</a></td></tr></table>
    <p>Payload: <code>&lt;script&gt;alert('XSS: '+document.cookie)&lt;/script&gt;</code></p>"""
    # Non-HttpOnly cookie so the XSS demo can show that document.cookie is readable.
    resp = app.make_response(page("Cross-Site Scripting Lab", body))
    resp.set_cookie("demo_session", "alice-session-token-12345", httponly=False)
    return resp


@app.route("/reset")
def reset():
    init_db()
    return page("Reset", "<p class='ok'>Database reset to its original state.</p>")


# ===========================================================================
# 3. CROSS-SITE SCRIPTING (XSS)
# ===========================================================================
GUESTBOOK_FORM = """<form method="post">
 <p>Name<br><input type="text" name="author"></p>
 <p>Comment<br><textarea name="body" rows="3"></textarea></p>
 <button>Post comment</button></form><hr>"""


def save_comment():
    db = get_db()
    db.execute("INSERT INTO comments (author, body) VALUES (?, ?)",
               (request.form.get("author", "anon"), request.form.get("body", "")))
    db.commit()


# ---- Variant 1: Stored XSS --------------------------------------------------
@app.route("/xss/vuln/guestbook", methods=["GET", "POST"])
def xss_vuln_guestbook():
    if request.method == "POST":
        save_comment()
        return redirect(request.path)
    comments = get_db().execute("SELECT author, body FROM comments").fetchall()
    # VULNERABLE: stored comments are inserted into the HTML without any encoding,
    # so a stored <script> or onerror= handler runs for every visitor.
    items = "".join(f"<li><b>{c['author']}</b>: {c['body']}</li>" for c in comments)
    return page("XSS V1 - Guestbook (stored XSS)", GUESTBOOK_FORM + f"<ul>{items}</ul>", "vuln")


@app.route("/xss/secure/guestbook", methods=["GET", "POST"])
def xss_secure_guestbook():
    if request.method == "POST":
        save_comment()
        return redirect(request.path)
    comments = get_db().execute("SELECT author, body FROM comments").fetchall()
    # SECURE (MITIGATION): context-aware HTML output encoding. escape() turns
    # < > " ' & into &lt; &gt; &quot; &#39; &amp; so the browser shows text, never runs it.
    items = "".join(f"<li><b>{escape(c['author'])}</b>: {escape(c['body'])}</li>" for c in comments)
    return page("XSS V1 - Guestbook (output encoded)", GUESTBOOK_FORM + f"<ul>{items}</ul>", "secure")


# ---- Variant 2: Reflected XSS -------------------------------------------------
XSS_SEARCH_FORM = """<form method="get"><input type="text" name="q" placeholder="search the site">
 <button>Search</button></form>"""


@app.route("/xss/vuln/search")
def xss_vuln_search():
    q = request.args.get("q", "")
    body = XSS_SEARCH_FORM
    if q:
        # VULNERABLE: the query parameter is reflected straight back into the page.
        body += f"<p>No results found for: {q}</p>"
    return page("XSS V2 - Site search (reflected XSS)", body, "vuln")


@app.route("/xss/secure/search")
def xss_secure_search():
    q = request.args.get("q", "")
    body = XSS_SEARCH_FORM
    if q:
        # SECURE (MITIGATION): HTML-encode the reflected value.
        body += f"<p>No results found for: {escape(q)}</p>"
    return page("XSS V2 - Site search (output encoded)", body, "secure")



if __name__ == "__main__":
    if not os.path.exists(DB_PATH):
        init_db()
    # localhost only - never expose this deliberately vulnerable app to a network.
    app.run(host="127.0.0.1", port=5000, debug=False)
