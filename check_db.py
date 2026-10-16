"""Standalone connectivity check: run `python check_db.py`.

Connects to whichever database the app is configured for (Turso when
TURSO_DATABASE_URL / TURSO_AUTH_TOKEN are set, otherwise local SQLite),
runs SELECT 1 and lists the tables. The auth token is never printed.
"""
from sqlalchemy import inspect, text

from app import app
from db import db


def main():
    with app.app_context():
        uri = app.config["SQLALCHEMY_DATABASE_URI"]
        target = "Turso" if uri.startswith("sqlite+tursohttp://") else "local SQLite"
        try:
            db.session.execute(text("SELECT 1"))
        except Exception as exc:
            print(f"FAIL: {target} not reachable: {exc}")
            raise SystemExit(1)
        print(f"OK: {target} reachable. Tables: {', '.join(sorted(inspect(db.engine).get_table_names()))}")


if __name__ == "__main__":
    main()
