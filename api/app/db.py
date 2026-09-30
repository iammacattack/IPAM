"""PostgreSQL access: one psycopg connection pool, plain SQL.

Plain SQL rather than an ORM because the integrity rules (exclusion
constraints, advisory locks, partial unique indexes) are PostgreSQL features
that are clearer written out than hidden behind a mapper.
"""

from __future__ import annotations

import time
from contextlib import contextmanager
from typing import Iterator

import psycopg
from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool

from .config import settings

_pool: ConnectionPool | None = None


def open_pool() -> ConnectionPool:
    global _pool
    if _pool is None:
        _pool = ConnectionPool(
            settings.database_url,
            min_size=1,
            max_size=settings.db_pool_max,
            kwargs={"row_factory": dict_row},
            open=False,
        )
        _pool.open()
    return _pool


def close_pool() -> None:
    global _pool
    if _pool is not None:
        _pool.close()
        _pool = None


def wait_for_database(timeout_s: int = 60) -> None:
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            with psycopg.connect(settings.database_url, connect_timeout=3) as conn:
                conn.execute("SELECT 1")
            return
        except psycopg.OperationalError:
            if time.monotonic() > deadline:
                raise
            time.sleep(1)


@contextmanager
def tx() -> Iterator[psycopg.Connection]:
    """A connection inside one transaction; commits on success, rolls back on error."""
    pool = open_pool()
    with pool.connection() as conn:
        conn.autocommit = True  # so transaction() below is the real outer transaction, not a savepoint
        with conn.transaction():
            yield conn


@contextmanager
def autocommit() -> Iterator[psycopg.Connection]:
    """Each statement commits on its own, so a write survives even if the caller then raises
    (a failed-2FA counter, a revoked session, an audit row). tx() still gets a real transaction:
    conn.transaction() issues BEGIN/COMMIT explicitly when autocommit is on."""
    pool = open_pool()
    with pool.connection() as conn:
        conn.autocommit = True
        yield conn
