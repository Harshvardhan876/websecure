import hmac
import secrets
import time
from collections import Counter, defaultdict
from functools import wraps
from urllib.parse import urlparse

from flask import Flask, Response, abort, flash, g, redirect, render_template, request, session, url_for

import scanner
from config import Config
from db import db, init_db
from report import build_report_pdf, report_filename
from scanner import FIX_EXAMPLES, InvalidURLError, ScanError, describe_scan_error, points_for, server_config

app = Flask(__name__)
app.config.from_object(Config)
init_db(app)

import models  # noqa: E402  (registers User/Scan/Finding on db.metadata before create_all)
from models import (  # noqa: E402
    EmailAlreadyRegisteredError,
    authenticate,
    claim_scans,
    create_user,
    get_scan_by_id,
    get_scans_for_user,
    save_scan_result,
)

with app.app_context():
    db.create_all()


def csrf_token():
    """Per-session secret that every form must send back (blocks cross-site form posts)."""
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)
    return session["csrf_token"]


def csp_nonce():
    """Per-request nonce so the page's own inline scripts run under the CSP and injected ones don't."""
    if "csp_nonce" not in g:
        g.csp_nonce = secrets.token_urlsafe(16)
    return g.csp_nonce


app.jinja_env.globals.update(csrf_token=csrf_token, csp_nonce=csp_nonce)


@app.before_request
def check_csrf():
    if request.method == "POST":
        expected = session.get("csrf_token")
        sent = request.form.get("csrf_token", "")
        if not expected or not hmac.compare_digest(sent, expected):
            abort(400, "This form has expired. Go back, reload the page and try again.")


@app.after_request
def security_headers(response):
    """WebSecure sends every header its own scanner checks for."""
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        f"script-src 'self' 'nonce-{csp_nonce()}'; "
        "style-src 'self' 'unsafe-inline'; "  # the dashboard sets CSS variables in style attributes
        "img-src 'self' data:; object-src 'none'; base-uri 'self'; "
        "form-action 'self'; frame-ancestors 'none'"
    )
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=()"
    return response


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)
    return wrapped


def safe_next(default="/"):
    """The ?next= page to return to after login, only if it is a path on this site (no open redirect)."""
    target = request.values.get("next", "")
    if target.startswith("/") and not target.startswith("//") and "\\" not in target:
        return target
    return default


def current_user():
    return db.session.get(models.User, session["user_id"]) if "user_id" in session else None


# Scans run without an account are saved with user_id NULL; their IDs live in the visitor's
# signed session cookie, so only that browser can open them until they log in and claim them.
ANON_SCANS = "anon_scans"


def can_view(scan):
    if scan.user_id is not None:
        return scan.user_id == session.get("user_id")
    return scan.scan_id in session.get(ANON_SCANS, [])


# Each scan launches a real browser, so anonymous visitors get a small hourly allowance.
# ponytail: in-memory and per process; resets on restart and is not shared between workers.
# Move it to the database if Render ever runs more than one worker.
ANON_SCAN_LIMIT = 5
ANON_SCAN_WINDOW_SECONDS = 3600
_anon_scan_times = defaultdict(list)


def client_ip():
    # Render sits behind Cloudflare, which sets CF-Connecting-IP and overwrites any value a client sends.
    return request.headers.get("CF-Connecting-IP") or request.remote_addr or "unknown"


def anon_scan_allowed():
    now = time.monotonic()
    key = client_ip()
    recent = [t for t in _anon_scan_times[key] if now - t < ANON_SCAN_WINDOW_SECONDS]
    allowed = len(recent) < ANON_SCAN_LIMIT
    if allowed:
        recent.append(now)
    _anon_scan_times[key] = recent
    return allowed


def log_in(user):
    """Start a fresh session for the user and move any scans they ran before logging in into their account."""
    pending = session.get(ANON_SCANS, [])
    session.clear()  # drops any session ID an attacker planted (session fixation)
    session["user_id"] = user.id
    return claim_scans(pending, user.id)


def dashboard_stats(scans):
    """Numbers for the dashboard, from the user's own scans (newest first). None if there are none."""
    if not scans:
        return None
    latest = scans[0]
    findings = latest.findings
    open_findings = [f for f in findings if f.status != "PASS"]
    failing = Counter(f.header_name for s in scans for f in s.findings if f.status == "FAIL")
    return {
        "latest": latest,
        "delta": latest.security_score - scans[1].security_score if len(scans) > 1 else None,
        "average": round(sum(s.security_score for s in scans) / len(scans)),
        "total": len(scans),
        "sites": len({urlparse(s.target_url).hostname for s in scans}),
        "finding_total": len(findings),
        "breakdown": [
            ("Passed", len(findings) - len(open_findings), "pass"),
            ("High", sum(f.severity == "High" for f in open_findings), "fail"),
            ("Medium", sum(f.severity == "Medium" for f in open_findings), "warn"),
            ("Low", sum(f.severity == "Low" for f in open_findings), "low"),
        ],
        "trend": scans[:10][::-1],
        "top_failing": [(name, n, round(100 * n / len(scans))) for name, n in failing.most_common(5)],
    }


def render_index(error=None):
    # ponytail: loads every scan for the stats; page it or aggregate in SQL if users reach thousands of scans.
    scans = get_scans_for_user(session["user_id"], limit=None)
    return render_template(
        "index.html",
        error=error,
        user=db.session.get(models.User, session["user_id"]),
        scans=scans[:5],
        stats=dashboard_stats(scans),
    )


def site_key(url):
    """Same site and page, ignoring "www." and a trailing slash, so repeat scans of one page match."""
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower().removeprefix("www.")
    return host + parsed.path.rstrip("/")


def previous_scan(scan):
    """The viewer's most recent earlier scan of the same page, or None."""
    if scan.user_id is not None:
        candidates = models.Scan.query.filter(models.Scan.user_id == scan.user_id)
    else:
        candidates = models.Scan.query.filter(
            models.Scan.scan_id.in_(session.get(ANON_SCANS, [])), models.Scan.user_id.is_(None)
        )
    earlier = candidates.filter(models.Scan.scan_date < scan.scan_date).order_by(models.Scan.scan_date.desc()).limit(50)
    key = site_key(scan.target_url)
    return next((s for s in earlier if site_key(s.target_url) == key), None)


STATUS_RANK = {"FAIL": 0, "WARNING": 1, "PASS": 2}


def compare_scans(old, new):
    before = {f.header_name: f.status for f in old.findings}
    changes = []
    for f in new.findings:
        was = before.get(f.header_name)
        if was and was != f.status:
            changes.append({
                "check": f.header_name, "was": was, "now": f.status,
                "points": (points_for(f.header_name, f.status) or 0) - (points_for(f.header_name, was) or 0),
                "better": STATUS_RANK.get(f.status, 1) > STATUS_RANK.get(was, 1),
            })
    return {"previous": old, "delta": new.security_score - old.security_score, "changes": changes}


def recent_sites(user_id, limit=6):
    """Distinct recently scanned addresses, newest first, for one-click rescans."""
    seen, sites = set(), []
    for s in get_scans_for_user(user_id, limit=40):
        if site_key(s.target_url) not in seen:
            seen.add(site_key(s.target_url))
            sites.append(s.target_url)
        if len(sites) == limit:
            break
    return sites


def render_scan_page(error=None, status=200):
    return render_template(
        "scan.html", error=error, user=current_user(), recent=recent_sites(session["user_id"])
    ), status


@app.route("/")
def index():
    # Visitors get a public page that explains the service; the dashboard is for logged-in users.
    if "user_id" not in session:
        return render_template("landing.html")
    return render_index()


@app.route("/scan", methods=["GET", "POST"])
def run_scan():
    logged_in = "user_id" in session
    if request.method == "GET":
        # Visitors scan from the landing page; the New scan page is part of the logged-in app.
        return render_scan_page() if logged_in else redirect(url_for("index"))

    target_url = request.form.get("target_url", "").strip()

    def scan_page(error, status):
        if logged_in:
            return render_scan_page(error, status)
        return render_template("landing.html", error=error), status

    if not logged_in and not anon_scan_allowed():
        return scan_page(
            f"You have used your {ANON_SCAN_LIMIT} free scans for this hour. Create a free account to keep scanning.", 429
        )

    try:
        result = scanner.scan(target_url)
    except InvalidURLError as e:
        return scan_page(str(e), 400)
    except ScanError as e:
        return scan_page(describe_scan_error(e), 400)

    saved = save_scan_result(result, user_id=session.get("user_id"))
    if not logged_in:
        session[ANON_SCANS] = (session.get(ANON_SCANS, []) + [saved.scan_id])[-20:]
    return redirect(url_for("results", scan_id=saved.scan_id))


@app.route("/results/<int:scan_id>")
def results(scan_id):
    scan = get_scan_by_id(scan_id)
    if scan is None or not can_view(scan):
        abort(404)
    previous = previous_scan(scan)
    failing = {f.header_name for f in scan.findings if f.status != "PASS"}
    return render_template(
        "results.html", scan=scan, user=current_user(), fixes=FIX_EXAMPLES,
        comparison=compare_scans(previous, scan) if previous else None,
        config=server_config(failing),
    )


@app.route("/history")
@login_required
def history():
    scans = get_scans_for_user(session["user_id"], limit=None)
    return render_template("history.html", scans=scans, user=current_user())


@app.route("/report/download/<int:scan_id>")
@login_required
def download_report(scan_id):
    scan = get_scan_by_id(scan_id)
    if scan is None or scan.user_id != session["user_id"]:
        abort(404)

    pdf_bytes = build_report_pdf(scan)
    return Response(
        pdf_bytes,
        mimetype="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{report_filename(scan)}"'
        },
    )


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not name or not email or not password:
            return render_template("auth.html", mode="register", error="All fields are required."), 400
        if len(password) < 8:
            return render_template("auth.html", mode="register", error="Password must be at least 8 characters."), 400

        try:
            user = create_user(name, email, password)
        except EmailAlreadyRegisteredError:
            return render_template("auth.html", mode="register", error="That email is already registered."), 400

        claimed = log_in(user)
        flash("Account created. Welcome to WebSecure!" + (" Your scan was saved to your account." if claimed else ""))
        return redirect(safe_next())

    return render_template("auth.html", mode="register")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        user = authenticate(email, password)
        if user is None:
            return render_template("auth.html", mode="login", error="Invalid email or password."), 401

        claimed = log_in(user)
        flash(f"Welcome back, {user.name}." + (" Your scan was saved to your account." if claimed else ""))
        return redirect(safe_next())

    return render_template("auth.html", mode="login")


@app.route("/logout", methods=["POST"])
def logout():
    # POST with a CSRF token, so another site cannot log people out with a link or image.
    session.pop("user_id", None)
    flash("You have been logged out.")
    return redirect(url_for("index"))


@app.route("/terms")
def terms():
    return render_template("terms.html", user=current_user())


@app.route("/privacy")
def privacy():
    return render_template("privacy.html", user=current_user())


ERROR_PAGES = {
    400: ("Something went wrong with that request", "Go back, reload the page and try again."),
    404: ("Page not found", "The page does not exist, or it belongs to another account."),
    405: ("That action is not allowed here", "Use the buttons on the page instead of typing the address."),
    500: ("Something went wrong on our side", "Please try again in a minute. If it keeps happening, the scan target may be causing it."),
}


@app.errorhandler(400)
@app.errorhandler(404)
@app.errorhandler(405)
@app.errorhandler(500)
def error_page(error):
    code = getattr(error, "code", 500)
    title, hint = ERROR_PAGES.get(code, ERROR_PAGES[500])
    # abort(400, "...") passes a specific message, e.g. the expired-form text from check_csrf.
    description = getattr(error, "description", None) if code == 400 else None
    return render_template("error.html", code=code, title=title, hint=description or hint), code


if __name__ == "__main__":
    app.run(debug=True)
