/**
 * SQL Injection - Authentication Bypass (Variant 1)
 * Cyber Security (IT-30001) Assignment - Web Server Security
 *
 * Two login routes for demo purposes:
 *   /login-vulnerable  -> builds SQL by string concatenation (INSECURE, intentional)
 *   /login-secure      -> uses parameterised queries / placeholders (the implemented mitigation)
 *
 * Run:
 *   npm install
 *   node server.js
 * Then open http://127.0.0.1:3000/
 */

const express = require("express");
const sqlite3 = require("sqlite3").verbose();
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;
const DB_PATH = path.join(__dirname, "users.db");

app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));
app.use(express.urlencoded({ extended: true }));

// ---------------------------------------------------------------------------
// Database setup — fresh seed on every server start (handy for repeated demo takes)
// ---------------------------------------------------------------------------
const db = new sqlite3.Database(DB_PATH);

function initDb(callback) {
  db.serialize(() => {
    db.run("DROP TABLE IF EXISTS users");
    db.run(`
      CREATE TABLE users (
        id       INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role     TEXT NOT NULL DEFAULT 'user'
      )
    `);
    const stmt = db.prepare(
      "INSERT INTO users (username, password, role) VALUES (?, ?, ?)"
    );
    // Seed data - the admin account's password is NOT known to the attacker.
    // The exploit logs in as admin without ever knowing it.
    stmt.run("admin", "S3cureAdminPass!2026", "admin");
    stmt.run("alice", "alicepw123", "user");
    stmt.run("bob", "bobpw456", "user");
    stmt.finalize(() => {
      console.log("[+] Database initialised at", DB_PATH);
      if (callback) callback();
    });
  });
}

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------
app.get("/", (req, res) => {
  res.render("index");
});

// ---- (a) VULNERABLE IMPLEMENTATION -----------------------------------------
// Root cause: the username/password supplied by the user are concatenated
// directly into the SQL string, so attacker-controlled characters
// (quotes, OR, --) are interpreted as SQL syntax instead of inert data.
app.get("/login-vulnerable", (req, res) => {
  res.render("login", {
    mode: "VULNERABLE",
    endpoint: "/login-vulnerable",
    result: null,
    query_shown: null,
  });
});

app.post("/login-vulnerable", (req, res) => {
  const username = req.body.username || "";
  const password = req.body.password || "";

  // <<< VULNERABLE LINE: string concatenation into SQL >>>
  const query =
    "SELECT id, username, role FROM users WHERE username = '" +
    username +
    "' AND password = '" +
    password +
    "'";

  db.get(query, [], (err, row) => {
    let result;
    if (err) {
      result = "DB error: " + err.message;
    } else if (row) {
      result = `LOGIN SUCCESS as '${row.username}' (role=${row.role})`;
    } else {
      result = "LOGIN FAILED";
    }
    res.render("login", {
      mode: "VULNERABLE",
      endpoint: "/login-vulnerable",
      result,
      query_shown: query,
    });
  });
});

// ---- (d) MITIGATION IMPLEMENTED: parameterised query -----------------------
app.get("/login-secure", (req, res) => {
  res.render("login", {
    mode: "SECURE (parameterised query)",
    endpoint: "/login-secure",
    result: null,
    query_shown: null,
  });
});

app.post("/login-secure", (req, res) => {
  const username = req.body.username || "";
  const password = req.body.password || "";

  // <<< FIXED LINE: parameterised query, input is always treated as data >>>
  const query =
    "SELECT id, username, role FROM users WHERE username = ? AND password = ?";

  db.get(query, [username, password], (err, row) => {
    let result;
    if (err) {
      result = "DB error: " + err.message;
    } else if (row) {
      result = `LOGIN SUCCESS as '${row.username}' (role=${row.role})`;
    } else {
      result = "LOGIN FAILED";
    }
    res.render("login", {
      mode: "SECURE (parameterised query)",
      endpoint: "/login-secure",
      result,
      query_shown: `${query}   -- params=(${JSON.stringify(
        username
      )}, ${JSON.stringify(password)})`,
    });
  });
});

// ---------------------------------------------------------------------------
initDb(() => {
  app.listen(PORT, "127.0.0.1", () => {
    console.log(`[+] Server running at http://127.0.0.1:${PORT}`);
  });
});
