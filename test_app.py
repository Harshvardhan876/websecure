"""App-level checks: CSRF, security headers, login and scan ownership. Run: python test_app.py

Uses a throwaway SQLite file, never Turso or instance/websecure.db.
"""
import os
import re
import tempfile
from types import SimpleNamespace

os.environ["TURSO_DATABASE_URL"] = ""
os.environ["TURSO_AUTH_TOKEN"] = ""
os.environ["SQLITE_PATH"] = os.path.join(tempfile.mkdtemp(), "test.db")

import scanner  # noqa: E402
from app import app  # noqa: E402
from db import db  # noqa: E402
from models import save_scan_result  # noqa: E402

TOKEN = re.compile(r'name="csrf_token" value="([^"]+)"')


def token(client, path):
    return TOKEN.search(client.get(path).get_data(as_text=True)).group(1)


def register(client, email):
    return client.post("/register", data={
        "name": "Test", "email": email, "password": "password123", "csrf_token": token(client, "/register"),
    })


def main():
    assert app.config["SQLALCHEMY_DATABASE_URI"].endswith("test.db")
    c = app.test_client()

    # Logged-out visitors get the public landing page (no login form), not a redirect
    r = c.get("/")
    page = r.get_data(as_text=True)
    assert r.status_code == 200 and "What WebSecure checks" in page and 'type="password"' not in page
    assert "/terms" in page and "/privacy" in page and "/register" in page
    assert c.get("/history").headers["Location"].endswith("/login")  # private pages still need login

    # CSRF: a POST without the token, or with a wrong one, is rejected
    assert c.post("/login", data={"email": "a@b.co", "password": "x"}).status_code == 400
    assert c.post("/login", data={"email": "a@b.co", "password": "x", "csrf_token": "forged"}).status_code == 400
    assert register(c, "alice@example.com").status_code == 302

    # Security headers, and WebSecure's own scanner rates them all PASS
    r = c.get("/")
    nonce = re.search(r"'nonce-([^']+)'", r.headers["Content-Security-Policy"]).group(1)
    assert f'nonce="{nonce}"' in r.get_data(as_text=True), "inline script must carry the CSP nonce"
    # The session cookie is HttpOnly + SameSite=Lax here; Secure comes from SESSION_COOKIE_SECURE=true in production.
    cookie = r.headers.get("Set-Cookie", "session=x; HttpOnly; SameSite=Lax")
    assert "HttpOnly" in cookie and "SameSite=Lax" in cookie, cookie
    assert "SESSION_COOKIE_SECURE" in open("render.yaml").read()
    pairs = [(k, v) for k, v in r.headers.items() if k != "Set-Cookie"] + [("Set-Cookie", cookie + "; Secure")]
    page = SimpleNamespace(url="https://websecure.live/", status_code=200, headers=scanner.make_headers(pairs), text="", history=[])
    score, findings = scanner.evaluate(page, ssl_warning=False)
    assert score == 100, [(f["header_name"], f["status"]) for f in findings if f["status"] != "PASS"]

    # Scan ownership: Bob cannot open Alice's scan or its PDF
    with app.app_context():
        scan = save_scan_result({"target_url": "https://example.com", "security_score": 50, "risk_level": "Weak", "findings": []}, user_id=1)
        scan_id = scan.scan_id
    assert c.get(f"/results/{scan_id}").status_code == 200
    bob = app.test_client()
    register(bob, "bob@example.com")
    assert bob.get(f"/results/{scan_id}").status_code == 404
    assert bob.get(f"/report/download/{scan_id}").status_code == 404

    # Turso HTTP driver: values survive the JSON encoding both ways
    import turso_http
    for value in (None, 0, -7, 2**40, 1.5, "text", b"\x00\xffbytes"):
        assert turso_http._decode(turso_http._encode(value)) == value, value
    assert turso_http._decode(turso_http._encode(True)) == 1

    # Turso HTTP driver: a write after the server dropped the idle connection is retried once.
    # (This failed on Render: a slow scan left the socket idle, and saving the result raised.)
    import http.client
    import json

    class FakeResponse:
        status = 200

        def read(self):
            return json.dumps({"baton": "b1", "results": [
                {"type": "ok", "response": {"type": "execute", "result": {"cols": [], "rows": [], "affected_row_count": 0}}},
                {"type": "ok", "response": {"type": "execute", "result": {"cols": [], "rows": [], "affected_row_count": 1, "last_insert_rowid": "42"}}},
            ]}).encode()

    class FlakyHTTP:
        calls = 0

        def __init__(self, *args, **kwargs):
            pass

        def request(self, *args, **kwargs):
            FlakyHTTP.calls += 1
            if FlakyHTTP.calls == 1:
                raise http.client.RemoteDisconnected("Remote end closed connection without response")

        def getresponse(self):
            return FakeResponse()

        def close(self):
            pass

    real_http = turso_http.http.client.HTTPSConnection
    turso_http.http.client.HTTPSConnection = FlakyHTTP
    try:
        conn = turso_http.connect("https://db.example.invalid", "token")
        cur = conn.cursor().execute("INSERT INTO t VALUES (?)", (1,))
        assert FlakyHTTP.calls == 2 and cur.lastrowid == 42 and conn.in_transaction
    finally:
        turso_http.http.client.HTTPSConnection = real_http

    print("OK: app checks passed")


if __name__ == "__main__":
    main()
