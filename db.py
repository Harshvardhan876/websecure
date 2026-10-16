import os

from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.dialects import registry

db = SQLAlchemy()

# Our pure-Python Turso driver (turso_http.py), available as the "sqlite+tursohttp://" URL scheme.
registry.register("sqlite.tursohttp", "turso_http", "TursoHTTPDialect")


def init_db(app):
    """Use Turso when TURSO_DATABASE_URL and TURSO_AUTH_TOKEN are set, else local SQLite.

    Turso goes through turso_http.py, a pure-Python driver for Turso's HTTP API. The compiled
    libsql drivers either needed WebSocket (rejected by this instance) or hung and crashed on
    Render's Linux servers. Render's disk is wiped on every deploy, so production must use Turso.
    """
    turso_url = app.config.get("TURSO_DATABASE_URL", "")
    turso_token = app.config.get("TURSO_AUTH_TOKEN", "")

    if turso_url and turso_token:
        host = turso_url.split("://", 1)[-1]
        app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite+tursohttp://{host}"
        app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {"connect_args": {"auth_token": turso_token}}
    else:
        os.makedirs(app.instance_path, exist_ok=True)
        # SQLITE_PATH lets tests use a throwaway file instead of the real database.
        db_path = os.getenv("SQLITE_PATH") or os.path.join(app.instance_path, "websecure.db")
        app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{db_path}"

    db.init_app(app)
