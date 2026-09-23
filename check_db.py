"""Standalone connectivity check: run `python check_db.py`.

Checks two things:
1. Local SQLite (the app's actual DB for now, via Flask-SQLAlchemy).
2. Turso reachability, if TURSO_DATABASE_URL / TURSO_AUTH_TOKEN are set,
   using libsql-client's HTTP transport directly (its dbapi2/SQLAlchemy
   shim only supports WebSocket, which this project's Turso instance
   rejects at handshake -- see docs/05_IMPLEMENTATION_LOG.md).
"""
from dotenv import load_dotenv

load_dotenv()

import os

from sqlalchemy import text

from app import app
from db import db


def check_local_sqlite():
    with app.app_context():
        try:
            db.session.execute(text("SELECT 1"))
            print(f"OK: local SQLite reachable ({app.config['SQLALCHEMY_DATABASE_URI']})")
        except Exception as exc:
            print(f"FAIL: local SQLite check failed: {exc}")
            raise SystemExit(1)


def check_turso():
    turso_url = os.getenv("TURSO_DATABASE_URL", "")
    turso_token = os.getenv("TURSO_AUTH_TOKEN", "")

    if not turso_url or not turso_token:
        print("SKIP: TURSO_DATABASE_URL / TURSO_AUTH_TOKEN not set, skipping Turso check")
        return

    import libsql_client

    http_url = turso_url.replace("libsql://", "https://", 1)
    client = libsql_client.create_client_sync(url=http_url, auth_token=turso_token)
    try:
        client.execute("SELECT 1")
        print(f"OK: Turso reachable via HTTPS ({http_url})")
    except Exception as exc:
        print(f"FAIL: could not reach Turso: {exc}")
        raise SystemExit(1)
    finally:
        client.close()


if __name__ == "__main__":
    check_local_sqlite()
    check_turso()
