"""Pure-Python DB-API 2.0 driver for Turso over its HTTP API, plus a SQLAlchemy dialect for it.

Why this exists: the compiled libsql driver worked on macOS but hung and crashed the
process on Render's Linux servers. This module uses only the standard library (http.client,
json), so there is no native code, and every request has a timeout, so a slow or unreachable
database raises an error instead of freezing a gunicorn worker.

Protocol: Turso's "Hrana over HTTP" pipeline endpoint, POST /v2/pipeline. A "baton" returned
by the server keeps one stream (and so one transaction) open across requests.
"""
import base64
import http.client
import json
from urllib.parse import urlparse

from sqlalchemy import pool
from sqlalchemy.dialects.sqlite.pysqlite import SQLiteDialect_pysqlite

apilevel = "2.0"
threadsafety = 1
paramstyle = "qmark"
# SQLAlchemy's SQLite dialect reads these to decide which SQL features it may use.
sqlite_version_info = (3, 45, 0)
sqlite_version = "3.45.0"

REQUEST_TIMEOUT_SECONDS = 20
_WRITE_KEYWORDS = ("INSERT", "UPDATE", "DELETE", "REPLACE")


class Warning(Exception):  # noqa: A001 (DB-API name)
    pass


class Error(Exception):
    pass


class InterfaceError(Error):
    pass


class DatabaseError(Error):
    pass


class DataError(DatabaseError):
    pass


class OperationalError(DatabaseError):
    pass


class IntegrityError(DatabaseError):
    pass


class InternalError(DatabaseError):
    pass


class ProgrammingError(DatabaseError):
    pass


class NotSupportedError(DatabaseError):
    pass


def connect(url, auth_token):
    return Connection(url, auth_token)


def _encode(value):
    if value is None:
        return {"type": "null"}
    if isinstance(value, (bool, int)):
        return {"type": "integer", "value": str(int(value))}
    if isinstance(value, float):
        return {"type": "float", "value": value}
    if isinstance(value, (bytes, bytearray, memoryview)):
        return {"type": "blob", "base64": base64.b64encode(bytes(value)).decode()}
    return {"type": "text", "value": str(value)}


def _decode(cell):
    kind = cell["type"]
    if kind == "null":
        return None
    if kind == "integer":
        return int(cell["value"])
    if kind == "float":
        return float(cell["value"])
    if kind == "blob":
        return base64.b64decode(cell["base64"])
    return cell["value"]


def _raise_for(error):
    message = error.get("message", "Turso error")
    if "CONSTRAINT" in (error.get("code") or "") or "constraint failed" in message:
        raise IntegrityError(message)
    raise OperationalError(message)


class Connection:
    def __init__(self, url, auth_token):
        self._host = urlparse(url if "://" in url else f"https://{url}").hostname
        self._headers = {"Authorization": f"Bearer {auth_token}", "Content-Type": "application/json"}
        self._http = None
        self._baton = None
        self.in_transaction = False
        self.isolation_level = ""  # read by SQLAlchemy's pysqlite dialect

    def _pipeline(self, requests):
        body = json.dumps({"baton": self._baton, "requests": requests})
        # A kept-alive socket may have been closed by the server while idle (e.g. during a
        # slow scan): reconnect once. That is safe while no server-side stream exists yet
        # (no baton), because nothing from this connection is pending on the server.
        # Mid-transaction (baton set) a resend could double-apply, so the error is raised.
        can_retry = self._baton is None
        for attempt in (1, 2):
            if self._http is None:
                self._http = http.client.HTTPSConnection(self._host, timeout=REQUEST_TIMEOUT_SECONDS)
            try:
                self._http.request("POST", "/v2/pipeline", body, self._headers)
                response = self._http.getresponse()
                raw = response.read()
                break
            except (http.client.HTTPException, OSError) as exc:
                self._http.close()
                self._http = None
                if attempt == 2 or not can_retry:
                    raise OperationalError(f"Turso request failed: {exc}") from exc

        if response.status != 200:
            raise OperationalError(f"Turso HTTP {response.status}: {raw[:300].decode(errors='replace')}")
        payload = json.loads(raw)
        self._baton = payload.get("baton")
        if payload.get("base_url"):  # the server asks to keep this stream on a specific host
            new_host = urlparse(payload["base_url"]).hostname
            if new_host and new_host != self._host:
                self._http.close()
                self._http, self._host = None, new_host

        responses = []
        for result in payload["results"]:
            if result["type"] == "error":
                _raise_for(result["error"])
            responses.append(result["response"])
        return responses

    def _execute(self, sql, params):
        requests = []
        # Like Python's sqlite3 module: writes start a transaction that lasts until commit().
        if not self.in_transaction and sql.lstrip().upper().startswith(_WRITE_KEYWORDS):
            requests.append({"type": "execute", "stmt": {"sql": "BEGIN"}})
            self.in_transaction = True
        index = len(requests)
        requests.append({"type": "execute", "stmt": {"sql": sql, "args": [_encode(p) for p in params]}})
        if not self.in_transaction:
            requests.append({"type": "close"})
        return self._pipeline(requests)[index]["result"]

    def _end_transaction(self, sql):
        if self.in_transaction and self._baton is None:
            # The opening request never reached the server, so there is nothing to end there.
            self.in_transaction = False
            return
        if self.in_transaction:
            try:
                self._pipeline([{"type": "execute", "stmt": {"sql": sql}}, {"type": "close"}])
            finally:
                self.in_transaction = False
                self._baton = None

    def commit(self):
        self._end_transaction("COMMIT")

    def rollback(self):
        self._end_transaction("ROLLBACK")

    def cursor(self):
        return Cursor(self)

    def close(self):
        try:
            self.rollback()
        finally:
            if self._http is not None:
                self._http.close()
                self._http = None


class Cursor:
    arraysize = 1

    def __init__(self, connection):
        self.connection = connection
        self.description = None
        self.rowcount = -1
        self.lastrowid = None
        self._rows = []

    def execute(self, sql, params=()):
        result = self.connection._execute(sql, params or ())
        columns = result.get("cols") or []
        self.description = [(c["name"], None, None, None, None, None, None) for c in columns] or None
        self._rows = [tuple(_decode(cell) for cell in row) for row in result.get("rows", [])]
        self.rowcount = result.get("affected_row_count", -1) if not columns else -1
        last = result.get("last_insert_rowid")
        self.lastrowid = int(last) if last is not None else None
        return self

    def executemany(self, sql, seq_of_params):
        total = 0
        for params in seq_of_params:
            self.execute(sql, params)
            total += max(self.rowcount, 0)
        self.rowcount = total
        return self

    def fetchone(self):
        return self._rows.pop(0) if self._rows else None

    def fetchmany(self, size=None):
        size = size or self.arraysize
        rows, self._rows = self._rows[:size], self._rows[size:]
        return rows

    def fetchall(self):
        rows, self._rows = self._rows, []
        return rows

    def close(self):
        self._rows = []


class TursoHTTPDialect(SQLiteDialect_pysqlite):
    """SQLAlchemy dialect `sqlite+tursohttp://<host>`; pass the token as connect_args={"auth_token": ...}."""

    driver = "tursohttp"
    supports_statement_cache = True

    @classmethod
    def import_dbapi(cls):
        import turso_http

        return turso_http

    @classmethod
    def get_pool_class(cls, url):
        return pool.QueuePool

    def create_connect_args(self, url):
        return [], {"url": f"https://{url.host}"}

    def on_connect(self):
        # The pysqlite dialect registers Python functions on local sqlite3 connections; not possible over HTTP.
        return None

    def is_disconnect(self, e, connection, cursor):
        return isinstance(e, OperationalError) and "request failed" in str(e)
