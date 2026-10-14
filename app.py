from functools import wraps

from flask import Flask, Response, abort, redirect, render_template, request, session, url_for

import scanner
from config import Config
from db import db, init_db
from report import build_report_pdf
from scanner import InvalidURLError, ScanError

app = Flask(__name__)
app.config.from_object(Config)
init_db(app)

import models  # noqa: E402  (registers User/Scan/Finding on db.metadata before create_all)
from models import (  # noqa: E402
    EmailAlreadyRegisteredError,
    authenticate,
    create_user,
    get_scan_by_id,
    get_scans_for_user,
    save_scan_result,
)

with app.app_context():
    db.create_all()


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


def render_index(error=None):
    recent_scans = get_scans_for_user(session["user_id"], limit=5)
    return render_template("index.html", error=error, recent_scans=recent_scans)


@app.route("/")
@login_required
def index():
    return render_index()


@app.route("/scan", methods=["POST"])
@login_required
def run_scan():
    target_url = request.form.get("target_url", "").strip()

    try:
        result = scanner.scan(target_url)
    except InvalidURLError as e:
        return render_index(error=str(e)), 400
    except ScanError:
        return render_index(
            error="Could not reach that URL. Check it's correct and reachable, then try again."
        ), 400

    saved = save_scan_result(result, user_id=session["user_id"])
    return redirect(url_for("results", scan_id=saved.scan_id))


@app.route("/results/<int:scan_id>")
@login_required
def results(scan_id):
    scan = get_scan_by_id(scan_id)
    if scan is None or scan.user_id != session["user_id"]:
        abort(404)
    return render_template("results.html", scan=scan)


@app.route("/history")
@login_required
def history():
    scans = get_scans_for_user(session["user_id"])
    return render_template("history.html", scans=scans)


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
            "Content-Disposition": f"attachment; filename=websecure-scan-{scan.scan_id}.pdf"
        },
    )


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not name or not email or not password:
            return render_template("register.html", error="All fields are required."), 400
        if len(password) < 8:
            return render_template("register.html", error="Password must be at least 8 characters."), 400

        try:
            user = create_user(name, email, password)
        except EmailAlreadyRegisteredError:
            return render_template("register.html", error="That email is already registered."), 400

        session["user_id"] = user.id
        return redirect(url_for("index"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        user = authenticate(email, password)
        if user is None:
            return render_template("login.html", error="Invalid email or password."), 401

        session["user_id"] = user.id
        return redirect(url_for("index"))

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.pop("user_id", None)
    return redirect(url_for("login"))


@app.route("/terms")
def terms():
    return render_template("terms.html")


@app.route("/privacy")
def privacy():
    return render_template("privacy.html")


if __name__ == "__main__":
    app.run(debug=True)
