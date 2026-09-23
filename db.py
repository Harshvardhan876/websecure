import os

from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


def init_db(app):
    """Wire Flask-SQLAlchemy to local SQLite.

    Turso ORM wiring is deferred to Phase 3: libsql-client's dbapi2 shim only
    supports the WebSocket (Hrana) transport, which this project's Turso
    instance rejects at the handshake (400). Turso reachability is verified
    separately in check_db.py via libsql-client's working HTTP transport.
    """
    os.makedirs(app.instance_path, exist_ok=True)
    db_path = os.path.join(app.instance_path, "websecure.db")
    app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{db_path}"
    db.init_app(app)
