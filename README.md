# SecureAuth — Secure User Authentication System

Task-01 · ProDigy InfoTech Web Development Internship

A user authentication system with registration, secure login, protected
routes, and role-based access control — built with Node.js/Express. Like
real authentication, this needs a server (client-side-only "auth" can
always be bypassed by editing local storage), so it ships as a small
Node.js project rather than a static HTML file.

## Requirements

- [Node.js](https://nodejs.org) 16 or later (includes npm).
- Internet access the **first** time you run `npm install`, to download
  Express and express-session. Nothing else needs the internet afterwards.

## How to run

```bash
cd secure-auth-system
npm install
npm start
```

Then open **http://localhost:3000** in your browser.

- The **first account you register becomes an admin** automatically
  (a common, safe demo pattern — see the note in "Role-based access
  control" below). Every account after that is a standard user.
- Register a second account in a private/incognito window to see a
  regular user's view, and the admin-only page rejecting it.

To use a different port: `PORT=4000 npm start`.

## What it demonstrates

### Registration & login
- `/api/register` validates username (3–20 chars, letters/numbers/`_`),
  email format, and password strength (8+ characters with a letter and a
  number) — all re-checked **server-side**, since client-side validation
  alone is never trustworthy.
- `/api/login` checks credentials and returns the same generic "Incorrect
  username or password" error whether the username doesn't exist or the
  password is wrong, so a login attempt can't be used to discover which
  usernames are registered.

### Password hashing
Passwords are never stored, logged, or compared in plain text. Each one is
hashed with a random salt using Node's built-in `crypto.scrypt` (a
memory-hard, standard password-hashing algorithm), and compared with
`crypto.timingSafeEqual` to avoid leaking timing information. Only the
salt and hash are persisted, in `data/users.json`.

### Session management
- Sessions are handled by `express-session` with an `HttpOnly`,
  `SameSite=Lax` cookie, so the session token isn't readable from
  client-side JavaScript (a baseline defense against XSS-driven session
  theft) and carries some baseline CSRF protection.
- `req.session.regenerate()` is called on both register and login, which
  issues a fresh session ID — this prevents session-fixation attacks.
- Sessions expire after 2 hours and are fully destroyed on logout
  (`/api/logout`), clearing the cookie.

### Protected routes
- `/api/dashboard` and `/api/me` are wrapped in a `requireAuth`
  middleware: no valid session, no data — the server returns `401`.
  `dashboard.html` calls this on load and redirects to the login page if
  it's rejected, so the "protected route" is enforced on the server, not
  just hidden in the UI.

### Role-based access control (RBAC)
- Each user has a `role` of `admin` or `user`.
- `/api/admin/users` is wrapped in `requireRole("admin")` and returns
  `403` for anyone else. `admin.html` shows this rejection in the UI if a
  non-admin somehow opens the page.
- **Design note:** registration never lets the client choose its own
  role — that would let anyone grant themselves admin. Instead, the first
  account ever created is auto-promoted to admin. A real production system
  would instead manage roles through a separate admin action or a seeding
  script, never a public sign-up field.

### Brute-force protection
Failed login attempts are tracked per username in memory; after 5 failures
that username is locked out for 60 seconds, regardless of whether the
correct password is eventually tried.

## Honest limitations (what a production system would add)

- **User store**: a JSON file is fine for a demo/assignment but isn't
  concurrency-safe or scalable — swap in a real database (PostgreSQL,
  MongoDB, etc.).
- **Session store**: `express-session`'s default `MemoryStore` is
  explicitly not for production (it leaks memory and doesn't survive a
  restart or multiple server instances) — use `connect-redis`,
  `connect-mongo`, or similar.
- **Transport security**: cookies are only marked `secure` (HTTPS-only)
  when `NODE_ENV=production` and this app doesn't set up HTTPS itself —
  deploy it behind a reverse proxy (e.g. Nginx) or platform that
  terminates TLS.
- **CSRF**: `SameSite=Lax` cookies give baseline protection, but a
  security-critical production app should add explicit CSRF tokens for
  state-changing requests.
- **Password reset, email verification, and 2FA** are out of scope here
  but would be the next additions for a real product.

## Project structure

```
secure-auth-system/
├── server.js          # Express app: auth routes, sessions, RBAC middleware
├── package.json
├── data/              # users.json (created at runtime)
└── public/
    ├── index.html     # login / registration
    ├── dashboard.html # protected route (any logged-in user)
    ├── admin.html     # protected + role-gated route (admin only)
    └── style.css
```
