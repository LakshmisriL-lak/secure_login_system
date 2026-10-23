# 🔐 Secure Login System

A secure login web app built with **Flask + SQLite**: registration, login, hashed passwords, input validation, SQL-injection protection, session management with logout, and optional two-factor authentication (2FA).

## ✨ Features

| Requirement | Implementation |
|---|---|
| Password hashing | **Argon2id** (`argon2-cffi`) with a unique random salt per user; hashes auto-upgrade if settings change |
| Input validation | Server-side checks: username `^[A-Za-z0-9_]{3,30}$`, valid email, password 10-128 chars with upper, lower, digit and symbol |
| SQL injection protection | **Parameterized queries only** (`WHERE username = ?`). Input is never concatenated into SQL |
| Session management | `HttpOnly` + `SameSite=Lax` cookies, 30-minute expiry, fresh session on login, logout via POST + CSRF token |
| 2FA (optional) | TOTP (RFC 6238): QR-code setup, 6-digit codes, works with Google Authenticator / Authy |
| Extras | CSRF protection, lockout after 5 failed logins (15 min), generic error messages, timing equalisation, security headers (CSP, nosniff, no-frame) |
| UI | Responsive split-screen design, dark mode, show/hide password, password-strength meter, animated "securing session" screen after login, dashboard |

## 📁 Project structure
```
secure_login/
├── app.py              # Flask backend (routes, security logic)
├── requirements.txt    # dependencies
├── static/
│   ├── style.css       # styling (light + dark mode)
│   └── app.js          # password toggle + strength meter
├── templates/          # base, auth, login, register, two_factor, setup_2fa, dashboard
├── docs/index.html     # clickable UI preview (for GitHub Pages)
├── .vscode/launch.json # press F5 in VS Code to run
├── .gitignore
└── README.md
```

## 🚀 How to run

**Requirements:** Python 3.9+ ([python.org](https://www.python.org/downloads/))

**1. Open a terminal in the project folder**
```bash
cd secure_login
```

**2. Create and activate a virtual environment**
```bash
# Windows (PowerShell / CMD)
python -m venv venv
venv\Scripts\activate

# macOS / Linux
python3 -m venv venv
source venv/bin/activate
```

**3. Install dependencies**
```bash
pip install -r requirements.txt
```

**4. Set a secret key** (signs session cookies)
```bash
# Windows PowerShell
$env:SECRET_KEY = python -c "import secrets;print(secrets.token_hex(32))"

# macOS / Linux
export SECRET_KEY="$(python3 -c 'import secrets;print(secrets.token_hex(32))')"
```
> Without it the app generates a temporary key and everyone is logged out on restart. Fine for testing.

**5. Start the app**
```bash
python app.py
```
Open **http://127.0.0.1:5000** in your browser. The database (`users.db`) is created automatically.

## 💻 Run in VS Code
1. Install [VS Code](https://code.visualstudio.com/) and the **Python** extension.
2. **File → Open Folder…** → choose `secure_login`.
3. Open the terminal (**Ctrl + `**) and run steps 2-3 from "How to run" above (create venv, `pip install -r requirements.txt`).
4. Press `Ctrl+Shift+P` → **Python: Select Interpreter** → pick the `venv` one.
5. Press **F5** (uses `.vscode/launch.json`) or run `python app.py` in the terminal.
6. Open http://127.0.0.1:5000 (Ctrl + click the link in the terminal).

## 🐙 Publish on GitHub
```bash
git init
git add .
git commit -m "Secure login system"
git branch -M main
git remote add origin https://github.com/<your-username>/secure-login-system.git
git push -u origin main
```
(Create the empty repository on github.com first. `.gitignore` keeps `venv/` and `users.db` out of the repo.)

**Live UI preview:** `docs/index.html` is a clickable preview of the interface. In the repo go to **Settings → Pages → Branch: main, folder: /docs** to get a public link. It is a design preview only; the real app runs with Flask.

## 🧪 How to use / test it
1. Click **Create one** → register (example: `alice_01`, `alice@example.com`, `Secure@1234`).
2. Log in with the same username and password → animated lock screen → dashboard.
3. Dashboard → **Enable 2FA** → scan the QR with Google Authenticator → enter the 6-digit code.
4. Log out, then log in again: password first, then the 2FA code.
5. **Attack test:** try the username `admin' OR '1'='1' --` on the login page. It is rejected and no one gets logged in.
6. Enter a wrong password 5 times: the account locks for 15 minutes.

## 🧠 How it works

**Registration:** inputs are validated, the password is hashed with Argon2id (salt stored inside the hash), and only the hash is saved. The plain password is never stored.

**Why hashing protects users:** hashing is one-way. If the database leaks, attackers get strings like `$argon2id$...`, not passwords. Salts make identical passwords produce different hashes, and Argon2 is deliberately slow, so brute-forcing is expensive.

**Login:** the password is verified against the stored hash. Failures show one generic message so attackers cannot tell if a username exists. A new session is created on success (prevents session fixation).

**SQL injection:**
```python
# Vulnerable (never do this)
db.execute("SELECT * FROM users WHERE username = '" + username + "'")
# Safe (used here)
db.execute("SELECT * FROM users WHERE username = ?", (username,))
```
With a parameter the database treats input purely as data, so `admin' OR '1'='1' --` is just an unknown username. Validation adds a second layer.

**Sessions:** a signed cookie (`HttpOnly`, `SameSite=Lax`, and `Secure` over HTTPS) holds the session, which expires after 30 minutes. Logout clears it and is a POST with a CSRF token so other sites cannot force a logout.

**2FA (TOTP):** the server stores a random secret shared with the authenticator app via QR code. Both sides compute a 6-digit code from the secret and the current 30-second window. Codes from adjacent windows are accepted to allow for clock drift.

## 🌐 Deployment notes
- Serve over **HTTPS** (e.g. gunicorn behind nginx) and set `HTTPS=1` so cookies get the `Secure` flag.
- Always set a fixed `SECRET_KEY`. Never commit it to GitHub.
- Hosting options for Flask: Render, Railway, PythonAnywhere. (GitHub Pages cannot run Flask.)

## 🔭 Possible improvements
IP-based rate limiting (Flask-Limiter), email verification, password reset, 2FA backup codes, encrypting stored TOTP secrets, audit logging.
