# Secure Login Panel (Flask + SQLite)

A small web login system built to demonstrate core authentication and network-security practices. Academic project, International Islamic University Chittagong (IIUC).

## Features

| Security measure | How it is done |
|---|---|
| Password storage | Salted hashes (Werkzeug), never plain text |
| SQL injection protection | Parameterised queries only |
| Brute-force protection | Account lockout after 5 failed attempts (5 minutes) |
| CSRF protection | Per-session token checked on every POST |
| Username enumeration | Generic error message and a dummy hash check for unknown users |
| Password policy | At least 10 characters with upper, lower and a digit |
| Session safety | HttpOnly and SameSite cookies, 30-minute timeout, session reset on login |
| Security headers | CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, no-store |
| Audit trail | Registrations, successful and failed logins, blocked attempts are logged |

## Run it

```bash
pip install -r requirements.txt
python app.py
```

Open `http://127.0.0.1:5000`, register an account, then log in.

For anything beyond local testing, set a fixed secret key first:

```bash
export SECRET_KEY="a-long-random-string"
```

## Tests

```bash
python test_app.py
```

Or with pytest: `pip install pytest && pytest`. The tests cover weak passwords, login, generic errors, SQL injection input, lockout and protected pages.

## Project structure

```
app.py            Application, routes and security logic
test_app.py       Automated tests
requirements.txt  Dependencies
```

## Limitations and next steps

- Runs on Flask's development server; production use needs HTTPS and a proper WSGI server
- Lockout is per username; adding per-IP limits would be stronger
- Possible additions: two-factor authentication, password reset, email verification
