import os
import re
import tempfile

os.environ["LOGIN_DB"] = os.path.join(tempfile.mkdtemp(), "test.db")

import app as login_app  # noqa: E402

client = login_app.app.test_client()


def token(path):
    html = client.get(path).get_data(as_text=True)
    return re.search(r'name="csrf" value="([^"]+)"', html).group(1)


def post(path, **data):
    data["csrf"] = token(path)
    return client.post(path, data=data, follow_redirects=True)


def test_weak_password_rejected():
    r = post("/register", username="alice_1", password="short")
    assert "at least 10 characters" in r.get_data(as_text=True)


def test_register_and_login():
    post("/register", username="bob_user", password="StrongPass123")
    r = post("/login", username="bob_user", password="StrongPass123")
    assert "Welcome" in r.get_data(as_text=True)
    client.post("/logout", data={"csrf": token("/dashboard")})


def test_wrong_password_is_generic():
    r = post("/login", username="nobody", password="whatever123A")
    assert "Invalid username or password." in r.get_data(as_text=True)


def test_sql_injection_is_harmless():
    r = post("/login", username="' OR '1'='1", password="x")
    assert "Welcome" not in r.get_data(as_text=True)


def test_lockout_after_repeated_failures():
    post("/register", username="carol_x", password="StrongPass123")
    for _ in range(login_app.MAX_ATTEMPTS):
        post("/login", username="carol_x", password="wrongwrong1A")
    r = post("/login", username="carol_x", password="StrongPass123")
    assert "Too many failed attempts" in r.get_data(as_text=True)


def test_dashboard_requires_login():
    fresh = login_app.app.test_client()
    r = fresh.get("/dashboard")
    assert r.status_code == 302 and "/login" in r.headers["Location"]
