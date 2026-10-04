/**
 * Secure User Authentication System — server.js
 * Task-01, ProDigy InfoTech
 *
 * Demonstrates the standard mechanisms the brief asks for:
 *  - Password hashing (Node's built-in, salted scrypt + timing-safe compare)
 *  - Session-based login (express-session, HttpOnly cookies, session
 *    regeneration on login to prevent session fixation)
 *  - Protected routes (requireAuth middleware)
 *  - Role-based access control (requireRole middleware; first registered
 *    user becomes "admin", everyone after that is "user")
 *  - Basic brute-force protection (per-username lockout after 5 failed
 *    login attempts)
 *
 * Users are persisted to a JSON file so accounts survive a restart. This
 * keeps the project dependency-free (no database) for easy local setup —
 * see the README for what to swap in for real production use.
 */
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const express = require("express");
const session = require("express-session");

const DATA_DIR = path.join(__dirname, "data");
const USERS_FILE = path.join(DATA_DIR, "users.json");
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

function loadUsers() {
  try { return JSON.parse(fs.readFileSync(USERS_FILE, "utf8")); } catch { return {}; }
}
function saveUsers(users) {
  fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
}
let users = loadUsers(); // { [username]: { email, salt, hash, role, createdAt } }

// ---- Password hashing: salted scrypt (Node built-in, no extra dependency) ----
function hashPassword(password, salt = crypto.randomBytes(16).toString("hex")) {
  const hash = crypto.scryptSync(password, salt, 64).toString("hex");
  return { salt, hash };
}
function verifyPassword(password, salt, hash) {
  const candidate = crypto.scryptSync(password, salt, 64).toString("hex");
  const a = Buffer.from(candidate), b = Buffer.from(hash);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

// ---- Basic brute-force protection (in-memory, per-username) ----
const loginAttempts = new Map(); // username -> { fails, lockUntil }
const MAX_ATTEMPTS = 5, LOCK_MS = 60 * 1000;

// ---- Validation ----
function validateRegistration({ username, email, password }) {
  if (!username || !/^[a-zA-Z0-9_]{3,20}$/.test(username)) {
    return "Username must be 3-20 characters: letters, numbers, or underscore.";
  }
  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return "Enter a valid email address.";
  }
  if (!password || password.length < 8 || !/[A-Za-z]/.test(password) || !/[0-9]/.test(password)) {
    return "Password must be at least 8 characters and include a letter and a number.";
  }
  return null;
}

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

app.use(session({
  name: "sid",
  secret: process.env.SESSION_SECRET || "dev-secret-change-this-in-production",
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,          // not readable from client-side JS — mitigates XSS token theft
    sameSite: "lax",         // baseline CSRF mitigation
    secure: process.env.NODE_ENV === "production", // requires HTTPS in production
    maxAge: 1000 * 60 * 60 * 2 // 2 hours
  }
}));

// ---- Middleware ----
function requireAuth(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: "Not authenticated. Please log in." });
  next();
}
function requireRole(role) {
  return (req, res, next) => {
    if (req.session.role !== role) return res.status(403).json({ error: "You don't have permission to view this." });
    next();
  };
}

// ---- Routes: registration & login ----
app.post("/api/register", (req, res) => {
  const { username, email, password } = req.body || {};
  const validationError = validateRegistration({ username, email, password });
  if (validationError) return res.status(400).json({ error: validationError });
  if (users[username]) return res.status(409).json({ error: "That username is already taken." });
  if (Object.values(users).some(u => u.email === email)) {
    return res.status(409).json({ error: "That email is already registered." });
  }

  const { salt, hash } = hashPassword(password);
  // Demo-friendly RBAC: the very first account created becomes admin;
  // everyone after that is a standard user. Real systems should never let
  // a client request assign its own privileged role.
  const role = Object.keys(users).length === 0 ? "admin" : "user";
  users[username] = { email, salt, hash, role, createdAt: Date.now() };
  saveUsers(users);

  req.session.regenerate(() => {
    req.session.userId = username;
    req.session.role = role;
    res.json({ username, email, role });
  });
});

app.post("/api/login", (req, res) => {
  const { username, password } = req.body || {};
  const record = users[username];

  const attempt = loginAttempts.get(username) || { fails: 0, lockUntil: 0 };
  if (attempt.lockUntil > Date.now()) {
    const secs = Math.ceil((attempt.lockUntil - Date.now()) / 1000);
    return res.status(429).json({ error: `Too many failed attempts. Try again in ${secs}s.` });
  }

  // Same generic error whether the username exists or the password is
  // wrong — don't leak which one failed.
  const valid = record && verifyPassword(password || "", record.salt, record.hash);
  if (!valid) {
    attempt.fails += 1;
    if (attempt.fails >= MAX_ATTEMPTS) { attempt.lockUntil = Date.now() + LOCK_MS; attempt.fails = 0; }
    loginAttempts.set(username, attempt);
    return res.status(401).json({ error: "Incorrect username or password." });
  }

  loginAttempts.delete(username);
  // Regenerate the session on login to prevent session-fixation attacks.
  req.session.regenerate(() => {
    req.session.userId = username;
    req.session.role = record.role;
    res.json({ username, email: record.email, role: record.role });
  });
});

app.post("/api/logout", (req, res) => {
  req.session.destroy(() => {
    res.clearCookie("sid");
    res.json({ ok: true });
  });
});

app.get("/api/me", requireAuth, (req, res) => {
  const record = users[req.session.userId];
  res.json({ username: req.session.userId, email: record.email, role: req.session.role });
});

// ---- Protected routes ----
app.get("/api/dashboard", requireAuth, (req, res) => {
  const record = users[req.session.userId];
  res.json({
    message: `Welcome back, ${req.session.userId}.`,
    role: req.session.role,
    memberSince: new Date(record.createdAt).toLocaleDateString()
  });
});

// Admin-only route: role-based access control in action.
app.get("/api/admin/users", requireAuth, requireRole("admin"), (req, res) => {
  const list = Object.entries(users).map(([username, u]) => ({
    username, email: u.email, role: u.role, createdAt: u.createdAt
  }));
  res.json({ users: list });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Auth server running at http://localhost:${PORT}`);
});
