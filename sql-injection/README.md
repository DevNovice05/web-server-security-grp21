# SQL Injection — Authentication Bypass (Variant 1)

Cyber Security (IT-30001) — Web Server Security Assignment
Stack: **Node.js + Express + EJS + sqlite3**

## 1. Setup & run

```bash
npm install
node server.js
```

Open **http://127.0.0.1:3000/**. The database (`users.db`) is dropped and
re-seeded every time the server starts, so you can repeat the demo as many
times as you like for the video.
The server listens on localhost only. If port 3000 is already in use, start
it on another local port with `PORT=3001 node server.js` and open
**http://127.0.0.1:3001/**.

Seeded accounts:

| username | password              | role  |
|----------|------------------------|-------|
| admin    | S3cureAdminPass!2026   | admin |
| alice    | alicepw123             | user  |
| bob      | bobpw456                | user  |

## 2. (a) Vulnerable implementation

File: `server.js`, route `POST /login-vulnerable`

```js
const query =
  "SELECT id, username, role FROM users WHERE username = '" +
  username + "' AND password = '" + password + "'";
db.get(query, ...);
```

User input is concatenated directly into the SQL string.

## 3. (b) Working exploit

Go to **Vulnerable login** (`/login-vulnerable`) and submit:

- Username: `' OR '1'='1' -- `
- Password: `anything`

The resulting query becomes:

```sql
SELECT id, username, role FROM users
WHERE username = '' OR '1'='1' -- ' AND password = 'anything'
```

`'1'='1'` is always true and `--` comments out the rest of the line
(including the password check), so the query returns the first row in the
table — logging the attacker in as `admin` **without knowing the admin
password**. The page shows `LOGIN SUCCESS as 'admin' (role=admin)` and
echoes the exact query executed, for the screen recording.
The vulnerable login page also has a **Fill demo payload** button. Submit the
same values manually on the secure login page to compare the result. The app
demonstrates a database lookup; it does not create a persistent login session.

## 4. (c) Root cause

User-supplied input is concatenated directly into the SQL query string, so
attacker-controlled characters (quotes, `OR`, `--`) are interpreted as SQL
syntax rather than treated as inert data — the database cannot tell the
difference between "code" and "data" in the final string.

## 5. (d) Mitigation implemented

File: `server.js`, route `POST /login-secure` — **parameterised query**:

```js
const query = "SELECT id, username, role FROM users WHERE username = ? AND password = ?";
db.get(query, [username, password], ...);
```

The `?` placeholders are bound separately from the SQL text by the sqlite3
driver, so the input can never change the structure of the query, no matter
what characters it contains.

**Proof of fix:** go to **Secure login** (`/login-secure`) and submit the
exact same payload (`' OR '1'='1' -- ` / `anything`). Result:
`LOGIN FAILED` — screenshot this for submission.

## 6. (e) Other mitigations (theory, not implemented)

Besides parameterised queries, the lecture slides also discuss:

- **Input validation with allow-lists** — restrict the username field to an
  expected character set (e.g. alphanumeric only) and reject anything
  containing quotes, SQL keywords, or comment sequences before it ever
  reaches the query layer. This is a second line of defence, not a
  replacement for parameterisation.
- **Least-privilege database accounts** — the application's DB user should
  only have the minimum rights needed (e.g. `SELECT`/limited `INSERT` on
  specific tables), not `DROP`/`ALTER`/admin rights, so that even a
  successful injection cannot damage or exfiltrate the whole database.
- **Safe error handling** — generic error messages to the client (e.g.
  "Invalid credentials") instead of raw database error text, which would
  otherwise leak schema details (table/column names, DB engine) that help
  an attacker refine further injection attempts.

Together these work because each targets a different point in the chain:
allow-listing stops malicious input early, parameterisation stops it from
being interpreted as code if it gets through, least privilege limits the
blast radius if an injection still succeeds, and safe errors deny the
attacker feedback needed to iterate.

## 7. Ownership declaration (Table 3)

| Member name | Roll number | Category       | Variant implemented                  |
|-------------|--------------|-----------------|----------------------------------------|
| *(fill in)* | *(fill in)*  | SQL injection   | Variant 1 — Authentication bypass      |
| *(fill in)* | *(fill in)*  | *(teammate)*    | *(teammate's category/variant)*        |
| *(fill in)* | *(fill in)*  | *(teammate)*    | *(teammate's category/variant)*        |
| *(fill in)* | *(fill in)*  | *(teammate)*    | *(teammate's category/variant)*        |

## 8. Project structure

```
sql-injection/
├── server.js        # Express app: vulnerable + secure routes
├── views/
│   ├── index.ejs     # landing page with links + payload hint
│   └── login.ejs      # shared login form (used by both routes)
├── package.json
└── README.md
```
