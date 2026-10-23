"""Secure login system: Flask + SQLite + Argon2 + sessions + optional TOTP 2FA."""
import base64, io, os, re, secrets, sqlite3
from datetime import datetime, timedelta, timezone
from functools import wraps

import pyotp, qrcode
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from flask import (Flask, abort, flash, g, redirect, render_template,
                   request, session, url_for)

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY") or secrets.token_hex(32),  # set SECRET_KEY in prod
    SESSION_COOKIE_HTTPONLY=True,       # JS cannot read the cookie
    SESSION_COOKIE_SAMESITE="Lax",      # basic CSRF defence
    SESSION_COOKIE_SECURE=os.environ.get("HTTPS", "0") == "1",  # set HTTPS=1 behind TLS
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
)
DB = os.environ.get("DB_PATH", "users.db")
ph = PasswordHasher()                   # Argon2id with safe defaults
DUMMY_HASH = ph.hash("dummy-password")  # equalises timing for unknown usernames
MAX_ATTEMPTS, LOCK_MINUTES = 5, 15

USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,30}$")
EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,255}\.[^@\s]{2,}$")


# ---------- database (parameterised queries only: no SQL injection) ----------
def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(_):
    d = g.pop("db", None)
    if d:
        d.close()

def init_db():
    with sqlite3.connect(DB) as c:
        c.execute("""CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL COLLATE NOCASE,
            email TEXT UNIQUE NOT NULL COLLATE NOCASE,
            password_hash TEXT NOT NULL,
            totp_secret TEXT,
            totp_enabled INTEGER NOT NULL DEFAULT 0,
            failed_attempts INTEGER NOT NULL DEFAULT 0,
            locked_until TEXT,
            created_at TEXT NOT NULL)""")


# ---------- helpers ----------
def now():
    return datetime.now(timezone.utc)

def csrf_token():
    if "_csrf" not in session:
        session["_csrf"] = secrets.token_urlsafe(32)
    return session["_csrf"]
app.jinja_env.globals["csrf_token"] = csrf_token

@app.before_request
def csrf_protect():
    if request.method == "POST":
        sent = request.form.get("_csrf", "")
        if not secrets.compare_digest(sent, session.get("_csrf", "")):
            abort(400, "Invalid CSRF token")

@app.after_request
def security_headers(r):
    r.headers["X-Content-Type-Options"] = "nosniff"
    r.headers["X-Frame-Options"] = "DENY"
    r.headers["Referrer-Policy"] = "no-referrer"
    r.headers["Cache-Control"] = "no-store"
    r.headers["Content-Security-Policy"] = "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'"
    return r

def login_required(f):
    @wraps(f)
    def wrapper(*a, **kw):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return f(*a, **kw)
    return wrapper

def current_user():
    return db().execute("SELECT * FROM users WHERE id = ?", (session["user_id"],)).fetchone()

def validate_registration(username, email, password, confirm):
    errs = []
    if not USERNAME_RE.match(username):
        errs.append("Username must be 3-30 characters: letters, numbers, underscore.")
    if not EMAIL_RE.match(email):
        errs.append("Enter a valid email address.")
    if len(password) < 10 or len(password) > 128:
        errs.append("Password must be 10-128 characters.")
    elif not (re.search(r"[a-z]", password) and re.search(r"[A-Z]", password)
              and re.search(r"\d", password) and re.search(r"[^A-Za-z0-9]", password)):
        errs.append("Password needs upper, lower, a digit and a symbol.")
    if password != confirm:
        errs.append("Passwords do not match.")
    return errs

def start_session(user_id):
    session.clear()                 # new session on login: prevents session fixation
    session.permanent = True
    session["user_id"] = user_id
    session["login_at"] = now().isoformat()
    session["just_in"] = True       # shows the "securing session" splash once


# ---------- routes ----------
@app.route("/")
def index():
    return redirect(url_for("dashboard" if "user_id" in session else "login"))

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        u = request.form.get("username", "").strip()
        e = request.form.get("email", "").strip()
        p = request.form.get("password", "")
        errs = validate_registration(u, e, p, request.form.get("confirm", ""))
        if not errs:
            try:
                db().execute(
                    "INSERT INTO users (username, email, password_hash, created_at) VALUES (?,?,?,?)",
                    (u, e, ph.hash(p), now().isoformat()))
                db().commit()
                flash("Account created. Please log in.", "ok")
                return redirect(url_for("login"))
            except sqlite3.IntegrityError:
                errs.append("That username or email is already taken.")
        for m in errs:
            flash(m, "err")
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        u = request.form.get("username", "").strip()
        p = request.form.get("password", "")
        generic = "Invalid username or password."   # never reveal which part was wrong
        user = db().execute("SELECT * FROM users WHERE username = ?", (u,)).fetchone()

        if user and user["locked_until"] and datetime.fromisoformat(user["locked_until"]) > now():
            flash("Account temporarily locked. Try again later.", "err")
            return render_template("login.html"), 429

        try:
            ph.verify(user["password_hash"] if user else DUMMY_HASH, p)
            ok = user is not None
        except VerifyMismatchError:
            ok = False

        if not ok:
            if user:
                attempts = user["failed_attempts"] + 1
                locked = (now() + timedelta(minutes=LOCK_MINUTES)).isoformat() if attempts >= MAX_ATTEMPTS else None
                db().execute("UPDATE users SET failed_attempts=?, locked_until=? WHERE id=?",
                             (0 if locked else attempts, locked, user["id"]))
                db().commit()
            flash(generic, "err")
            return render_template("login.html"), 401

        db().execute("UPDATE users SET failed_attempts=0, locked_until=NULL WHERE id=?", (user["id"],))
        if ph.check_needs_rehash(user["password_hash"]):
            db().execute("UPDATE users SET password_hash=? WHERE id=?", (ph.hash(p), user["id"]))
        db().commit()

        if user["totp_enabled"]:
            session.clear()
            session["pre_2fa_user"] = user["id"]
            session["pre_2fa_expires"] = (now() + timedelta(minutes=5)).isoformat()
            return redirect(url_for("two_factor"))
        start_session(user["id"])
        return redirect(url_for("dashboard"))
    return render_template("login.html")

@app.route("/2fa", methods=["GET", "POST"])
def two_factor():
    uid = session.get("pre_2fa_user")
    exp = session.get("pre_2fa_expires")
    if not uid or not exp or datetime.fromisoformat(exp) < now():
        session.clear()
        return redirect(url_for("login"))
    if request.method == "POST":
        user = db().execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()
        code = re.sub(r"\s", "", request.form.get("code", ""))
        if user and pyotp.TOTP(user["totp_secret"]).verify(code, valid_window=1):
            start_session(uid)
            return redirect(url_for("dashboard"))
        flash("Invalid authentication code.", "err")
    return render_template("two_factor.html")

@app.route("/dashboard")
@login_required
def dashboard():
    t = datetime.fromisoformat(session.get("login_at", now().isoformat()))
    return render_template("dashboard.html", user=current_user(),
                           welcome=session.pop("just_in", False),
                           login_at=t.strftime("%d %b %Y, %H:%M UTC"))

@app.route("/2fa/setup", methods=["GET", "POST"])
@login_required
def setup_2fa():
    user = current_user()
    if user["totp_enabled"]:
        flash("2FA is already enabled.", "ok")
        return redirect(url_for("dashboard"))
    secret = session.get("pending_totp") or pyotp.random_base32()
    session["pending_totp"] = secret
    if request.method == "POST":
        if pyotp.TOTP(secret).verify(request.form.get("code", "").strip(), valid_window=1):
            db().execute("UPDATE users SET totp_secret=?, totp_enabled=1 WHERE id=?", (secret, user["id"]))
            db().commit()
            session.pop("pending_totp", None)
            flash("Two-factor authentication enabled.", "ok")
            return redirect(url_for("dashboard"))
        flash("Code did not match. Try again.", "err")
    uri = pyotp.TOTP(secret).provisioning_uri(name=user["email"], issuer_name="SecureLogin")
    buf = io.BytesIO()
    qrcode.make(uri).save(buf, format="PNG")
    qr = base64.b64encode(buf.getvalue()).decode()
    return render_template("setup_2fa.html", qr=qr, secret=secret)

@app.route("/logout", methods=["POST"])   # POST + CSRF so other sites can't log you out
def logout():
    session.clear()
    flash("You have been logged out.", "ok")
    return redirect(url_for("login"))


init_db()
if __name__ == "__main__":
    app.run(debug=False)
