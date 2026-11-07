"""
Secure Login Panel (Flask + SQLite)

Security features:
  - Passwords stored as salted hashes (never plain text)
  - Parameterised SQL queries (protects against SQL injection)
  - Account lockout after repeated failed logins
  - CSRF tokens on every form
  - Generic error messages (no username enumeration)
  - Strong password policy and username validation
  - HttpOnly + SameSite cookies, session timeout
  - Security headers (CSP, X-Frame-Options, etc.)
  - Audit log of login events
"""
import os
import re
import secrets
import sqlite3
import time

from flask import Flask, g, redirect, render_template_string, request, session, url_for, abort
from werkzeug.security import check_password_hash, generate_password_hash

DB_PATH = os.environ.get("LOGIN_DB", "users.db")
MAX_ATTEMPTS = 5          # failed logins before lockout
LOCK_SECONDS = 300        # lockout window (5 minutes)
USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,30}$")
DUMMY_HASH = generate_password_hash("dummy-password-for-timing")

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY") or secrets.token_hex(32),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=1800,   # 30 minutes
)

PAGE = """
<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{ title }}</title>
<style>
 body{font-family:Arial,sans-serif;background:#0b3d2e;margin:0;display:flex;
      min-height:100vh;align-items:center;justify-content:center}
 .card{background:#fff;padding:28px;border-radius:12px;width:90%;max-width:360px;
       box-shadow:0 8px 24px rgba(0,0,0,.3)}
 h1{color:#0b3d2e;font-size:22px;margin-top:0}
 label{display:block;margin:12px 0 4px;font-size:14px}
 input{width:100%;padding:10px;border:1px solid #bbb;border-radius:6px;box-sizing:border-box}
 button{margin-top:16px;width:100%;padding:11px;background:#0b3d2e;color:#fff;
        border:0;border-radius:6px;font-size:15px}
 .err{color:#b00020;font-size:14px;margin:8px 0}
 .ok{color:#0b6b3a;font-size:14px;margin:8px 0}
 a{color:#0b3d2e}
</style></head><body><div class="card">
<h1>{{ title }}</h1>
{% for m in errors %}<div class="err">{{ m }}</div>{% endfor %}
{% if notice %}<div class="ok">{{ notice }}</div>{% endif %}
{{ body|safe }}
</div></body></html>
"""

FORM = """
<form method="post" autocomplete="off">
 <input type="hidden" name="csrf" value="{{ token }}">
 <label>Username</label><input name="username" required maxlength="30">
 <label>Password</label><input name="password" type="password" required maxlength="128">
 <button type="submit">{{ button }}</button>
</form>
<p style="font-size:14px">{{ link|safe }}</p>
"""


# ---------- database ----------
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
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS failed_logins(
            username TEXT NOT NULL, ip TEXT, ts INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS audit_log(
            ts INTEGER NOT NULL, username TEXT, ip TEXT, event TEXT NOT NULL);
        """
    )
    db.commit()
    db.close()


def audit(username, event):
    get_db().execute(
        "INSERT INTO audit_log(ts, username, ip, event) VALUES (?,?,?,?)",
        (int(time.time()), username, request.remote_addr, event),
    )
    get_db().commit()


# ---------- helpers ----------
def password_problems(pw):
    problems = []
    if len(pw) < 10:
        problems.append("Password must be at least 10 characters.")
    if not re.search(r"[a-z]", pw):
        problems.append("Password needs a lowercase letter.")
    if not re.search(r"[A-Z]", pw):
        problems.append("Password needs an uppercase letter.")
    if not re.search(r"\d", pw):
        problems.append("Password needs a digit.")
    return problems


def csrf_token():
    if "csrf" not in session:
        session["csrf"] = secrets.token_hex(16)
    return session["csrf"]


def check_csrf():
    sent = request.form.get("csrf", "")
    if not secrets.compare_digest(sent, session.get("csrf", "")):
        abort(400)


def is_locked(username):
    cutoff = int(time.time()) - LOCK_SECONDS
    row = get_db().execute(
        "SELECT COUNT(*) AS c FROM failed_logins WHERE username=? AND ts>?",
        (username, cutoff),
    ).fetchone()
    return row["c"] >= MAX_ATTEMPTS


def render(title, body_template, errors=(), notice=None, **ctx):
    body = render_template_string(body_template, token=csrf_token(), **ctx)
    return render_template_string(PAGE, title=title, body=body, errors=errors, notice=notice)


@app.after_request
def security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self' 'unsafe-inline'"
    resp.headers["Cache-Control"] = "no-store"
    return resp


# ---------- routes ----------
@app.route("/")
def index():
    return redirect(url_for("dashboard" if "user" in session else "login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    errors = []
    if request.method == "POST":
        check_csrf()
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if not USERNAME_RE.match(username):
            errors.append("Username must be 3-30 letters, digits or underscores.")
        errors += password_problems(password)
        if not errors:
            try:
                get_db().execute(
                    "INSERT INTO users(username, password_hash, created_at) VALUES (?,?,?)",
                    (username, generate_password_hash(password), int(time.time())),
                )
                get_db().commit()
                audit(username, "register")
                return redirect(url_for("login", registered=1))
            except sqlite3.IntegrityError:
                errors.append("That username is not available.")
    return render("Create account", FORM, errors=errors, button="Register",
                  link='Already registered? <a href="/login">Log in</a>')


@app.route("/login", methods=["GET", "POST"])
def login():
    errors = []
    notice = "Account created. Please log in." if request.args.get("registered") else None
    if request.method == "POST":
        check_csrf()
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        generic = "Invalid username or password."

        if is_locked(username):
            audit(username, "blocked_locked")
            errors.append("Too many failed attempts. Try again in a few minutes.")
        else:
            row = get_db().execute(
                "SELECT * FROM users WHERE username=?", (username,)
            ).fetchone()
            # always run a hash check so timing does not reveal valid usernames
            valid = check_password_hash(row["password_hash"] if row else DUMMY_HASH, password)
            if row and valid:
                get_db().execute("DELETE FROM failed_logins WHERE username=?", (username,))
                get_db().commit()
                session.clear()
                session["user"] = username
                session["csrf"] = secrets.token_hex(16)
                session.permanent = True
                audit(username, "login_success")
                return redirect(url_for("dashboard"))
            get_db().execute(
                "INSERT INTO failed_logins(username, ip, ts) VALUES (?,?,?)",
                (username, request.remote_addr, int(time.time())),
            )
            get_db().commit()
            audit(username, "login_failed")
            errors.append(generic)
    return render("Secure Login", FORM, errors=errors, notice=notice, button="Log in",
                  link='New here? <a href="/register">Create an account</a>')


@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect(url_for("login"))
    body = """
    <p>Welcome, <b>{{ user }}</b>. You are signed in securely.</p>
    <form method="post" action="/logout">
      <input type="hidden" name="csrf" value="{{ token }}">
      <button type="submit">Log out</button>
    </form>"""
    return render("Dashboard", body, user=session["user"])


@app.route("/logout", methods=["POST"])
def logout():
    check_csrf()
    session.clear()
    return redirect(url_for("login"))


init_db()

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
