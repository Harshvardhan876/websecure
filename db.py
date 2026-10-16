import os

from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


def init_db(app):
    """Use Turso when TURSO_DATABASE_URL and TURSO_AUTH_TOKEN are set, else local SQLite.

    Turso goes through the sqlalchemy-libsql dialect, which talks to Turso over HTTPS.
    The older libsql-client shim only spoke WebSocket, which this Turso instance rejects.
    Render's disk is wiped on every deploy, so production must use Turso.
    """
    turso_url = app.config.get("TURSO_DATABASE_URL", "")
    turso_token = app.config.get("TURSO_AUTH_TOKEN", "")

    if turso_url and turso_token:
        host = turso_url.split("://", 1)[-1]
        app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite+libsql://{host}/?secure=true"
        app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
            "connect_args": {"auth_token": turso_token},
            "pool_pre_ping": True,  # remote connections can go stale between requests
        }
    else:
        os.makedirs(app.instance_path, exist_ok=True)
        # SQLITE_PATH lets tests use a throwaway file instead of the real database.
        db_path = os.getenv("SQLITE_PATH") or os.path.join(app.instance_path, "websecure.db")
        app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{db_path}"

    db.init_app(app)
