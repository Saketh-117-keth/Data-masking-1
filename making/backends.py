"""Database abstraction layer.

The engine and scanner only talk to the `Backend` interface, so supporting a new
database means implementing five small methods. SQLite is fully implemented and
tested; PostgreSQL and MySQL adapters are provided (optional drivers).
"""
from __future__ import annotations

import sqlite3
from abc import ABC, abstractmethod


class Backend(ABC):
    name = "abstract"

    @abstractmethod
    def quote(self, ident: str) -> str: ...

    @abstractmethod
    def list_tables(self) -> list[str]: ...

    @abstractmethod
    def list_columns(self, table: str) -> list[tuple[str, str]]: ...

    @abstractmethod
    def execute_readonly(self, sql: str, params=(), max_rows: int = 1000):
        """Return (column_names, rows, truncated). Must be physically unable to write."""

    def sample(self, table: str, column: str, n: int = 200) -> list:
        sql = (
            f"SELECT {self.quote(column)} FROM {self.quote(table)} "
            f"WHERE {self.quote(column)} IS NOT NULL LIMIT {int(n)}"
        )
        _, rows, _ = self.execute_readonly(sql, max_rows=n)
        return [r[0] for r in rows]


class SQLiteBackend(Backend):
    name = "sqlite"
    _ALLOWED = {
        sqlite3.SQLITE_SELECT,
        sqlite3.SQLITE_READ,
        sqlite3.SQLITE_FUNCTION,
        sqlite3.SQLITE_RECURSIVE,
    }

    def __init__(self, path: str):
        self.path = path

    def quote(self, ident: str) -> str:
        return '"' + ident.replace('"', '""') + '"'

    def _connect_ro(self) -> sqlite3.Connection:
        # mode=ro: the driver itself refuses writes; authorizer blocks ATTACH/PRAGMA etc.
        conn = sqlite3.connect(f"file:{self.path}?mode=ro", uri=True, check_same_thread=False)
        conn.set_authorizer(lambda action, *_: sqlite3.SQLITE_OK if action in self._ALLOWED else sqlite3.SQLITE_DENY)
        return conn

    def list_tables(self) -> list[str]:
        conn = sqlite3.connect(f"file:{self.path}?mode=ro", uri=True)
        try:
            rows = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
            ).fetchall()
        finally:
            conn.close()
        return [r[0] for r in rows]

    def list_columns(self, table: str) -> list[tuple[str, str]]:
        conn = sqlite3.connect(f"file:{self.path}?mode=ro", uri=True)
        try:
            rows = conn.execute(f"PRAGMA table_info({self.quote(table)})").fetchall()
        finally:
            conn.close()
        return [(r[1], r[2] or "") for r in rows]

    def execute_readonly(self, sql, params=(), max_rows=1000):
        conn = self._connect_ro()
        try:
            cur = conn.execute(sql, params)
            cols = [d[0] for d in cur.description or []]
            rows = cur.fetchmany(max_rows + 1)
        finally:
            conn.close()
        return cols, [list(r) for r in rows[:max_rows]], len(rows) > max_rows


class PostgresBackend(Backend):
    """Needs `pip install psycopg2-binary`. Connect with a read-only DB role in production."""

    name = "postgresql"

    def __init__(self, dsn: str, schema: str = "public"):
        self.dsn, self.schema = dsn, schema

    def quote(self, ident: str) -> str:
        return '"' + ident.replace('"', '""') + '"'

    def _conn(self):
        import psycopg2  # lazy: optional dependency

        conn = psycopg2.connect(self.dsn)
        conn.set_session(readonly=True, autocommit=False)
        return conn

    def _fetch(self, sql, params=()):
        conn = self._conn()
        try:
            with conn.cursor() as cur:
                cur.execute(sql, params)
                return cur.fetchall()
        finally:
            conn.close()

    def list_tables(self):
        rows = self._fetch(
            "SELECT table_name FROM information_schema.tables "
            "WHERE table_schema=%s AND table_type='BASE TABLE' ORDER BY 1",
            (self.schema,),
        )
        return [r[0] for r in rows]

    def list_columns(self, table):
        rows = self._fetch(
            "SELECT column_name, data_type FROM information_schema.columns "
            "WHERE table_schema=%s AND table_name=%s ORDER BY ordinal_position",
            (self.schema, table),
        )
        return [(r[0], r[1]) for r in rows]

    def execute_readonly(self, sql, params=(), max_rows=1000):
        conn = self._conn()
        try:
            with conn.cursor() as cur:
                cur.execute(sql, params or None)
                cols = [d[0] for d in cur.description or []]
                rows = cur.fetchmany(max_rows + 1)
        finally:
            conn.close()
        return cols, [list(r) for r in rows[:max_rows]], len(rows) > max_rows


class MySQLBackend(Backend):
    """Needs `pip install pymysql`. Pass pymysql.connect kwargs (host, user, password, database)."""

    name = "mysql"

    def __init__(self, **kwargs):
        self.kwargs = kwargs

    def quote(self, ident: str) -> str:
        return "`" + ident.replace("`", "``") + "`"

    def _conn(self):
        import pymysql  # lazy: optional dependency

        conn = pymysql.connect(**self.kwargs)
        with conn.cursor() as cur:
            cur.execute("SET SESSION TRANSACTION READ ONLY")
        return conn

    def _fetch(self, sql, params=()):
        conn = self._conn()
        try:
            with conn.cursor() as cur:
                cur.execute(sql, params)
                return cur.fetchall()
        finally:
            conn.close()

    def list_tables(self):
        rows = self._fetch(
            "SELECT table_name FROM information_schema.tables "
            "WHERE table_schema=DATABASE() AND table_type='BASE TABLE' ORDER BY 1"
        )
        return [r[0] for r in rows]

    def list_columns(self, table):
        rows = self._fetch(
            "SELECT column_name, data_type FROM information_schema.columns "
            "WHERE table_schema=DATABASE() AND table_name=%s ORDER BY ordinal_position",
            (table,),
        )
        return [(r[0], r[1]) for r in rows]

    def execute_readonly(self, sql, params=(), max_rows=1000):
        conn = self._conn()
        try:
            with conn.cursor() as cur:
                cur.execute(sql, params or None)
                cols = [d[0] for d in cur.description or []]
                rows = cur.fetchmany(max_rows + 1)
        finally:
            conn.close()
        return cols, [list(r) for r in rows[:max_rows]], len(rows) > max_rows
