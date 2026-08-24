"""
Database utilities and SQLAlchemy session management.
"""
from __future__ import annotations

import os
from contextlib import contextmanager
from typing import Generator

from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker
from sqlalchemy.pool import NullPool
from dotenv import load_dotenv
load_dotenv()


DATABASE_URL = os.getenv("DATABASE_URL")

# ---------------------------------------------------------------------------
# Force the Supabase SESSION pooler (port 5432 on pooler.supabase.com).
# On Supabase Free Plan:
#   - Direct connection (db.<ref>.supabase.co:5432) has no IPv4 — unreachable
#     from Render without the paid IPv4 add-on.
#   - Transaction pooler (port 6543) breaks `Base.metadata.create_all()` and
#     prepared-statement paths in SQLAlchemy.
# Session pooler (pooler.supabase.com:5432) is the only correct endpoint for
# this stack. If the env var points at 6543, rewrite to 5432 automatically so
# a stale env var cannot silently re-introduce the transaction-pooler bug.
# ---------------------------------------------------------------------------
if DATABASE_URL and "pooler.supabase.com:6543" in DATABASE_URL:
    DATABASE_URL = DATABASE_URL.replace("pooler.supabase.com:6543", "pooler.supabase.com:5432")
if not DATABASE_URL:
    import logging
    import sys
    # Configure logging if not already configured
    if not logging.getLogger().handlers:
        logging.basicConfig(
            level=logging.ERROR,
            format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
            stream=sys.stderr
        )
    logger = logging.getLogger(__name__)
    error_msg = (
        "=" * 60 + "\n"
        "FATAL ERROR: DATABASE_URL environment variable is required!\n"
        "=" * 60 + "\n"
        "To fix this:\n"
        "1. Go to Render Dashboard → Your Service → Environment\n"
        "2. Add environment variable: DATABASE_URL\n"
        "3. Set value to your PostgreSQL connection string\n"
        "   Example: postgresql://user:pass@host:5432/dbname?sslmode=require\n"
        "4. Save and redeploy\n"
        "=" * 60
    )
    logger.error(error_msg)
    print(error_msg, file=sys.stderr)
    raise RuntimeError(
        "DATABASE_URL environment variable is required. "
        "Set it in Render dashboard → Environment → DATABASE_URL"
    )

connect_args = {}
if DATABASE_URL.startswith("sqlite"):
    # Required for SQLite when used across multiple threads (SocketIO workers).
    connect_args["check_same_thread"] = False

# PostgreSQL (Supabase Session Pooler @ pooler.supabase.com:5432): long-lived
# connections with TCP keepalives so silently-dropped sockets fail fast
# instead of being handed to a handler that then hangs.
if DATABASE_URL.startswith("postgresql"):
    connect_args.update({
        "connect_timeout": 10,
        "keepalives": 1,
        "keepalives_idle": 30,
        "keepalives_interval": 10,
        "keepalives_count": 3,
        "application_name": "kciade-prod",
    })

# NullPool is the supported pool class under `gunicorn -k eventlet` when
# the database endpoint is itself a connection pool (Supabase Session
# Pooler at pooler.supabase.com:5432).
#
# Why not QueuePool here:
#   QueuePool's internal Queue uses threading.Condition. Under eventlet
#   monkey-patching, lock ownership is tracked per-greenlet. When the
#   pre-ping / invalidate path runs after a transient libpq error, the
#   greenlet holding `not_empty` can yield mid-wait, another greenlet
#   may resume and operate on the queue, and when the original greenlet
#   wakes its `notify()` raises `cannot notify on un-acquired lock`. In
#   production this manifests as repeated 503s because every retry
#   re-enters the broken pool.
#
# Why NullPool is safe + fast here:
#   1. Supabase Session Pooler does the actual connection pooling — it
#      multiplexes our short-lived libpq connections onto its warm
#      Postgres backends, so we do not pay a real Postgres handshake
#      per request, only a TLS+pooler handshake.
#   2. psycogreen yields the libpq wait to the eventlet hub, so a fresh
#      connect/close per request never blocks the worker.
#   3. There is no in-process pool state for greenlets to corrupt, so
#      the eventlet-vs-threading.Condition race cannot happen.
#
# pool_pre_ping is meaningless for NullPool (no reuse), so it is dropped.
engine = create_engine(
    DATABASE_URL,
    poolclass=NullPool,
    future=True,
    echo=False,
    connect_args=connect_args,
)

SessionLocal = sessionmaker(
    bind=engine,
    autoflush=False,
    autocommit=False,
    expire_on_commit=False,
    future=True,
)

Base = declarative_base()


# ---------------------------------------------------------------------------
# SECOND (claims) database — optional, fully isolated.
#
# Holds the durable claim log that powers the /count command (multi-day
# retention). Lives in a SEPARATE Supabase project so this write-heavy log can
# never compete for connections with the auth-critical license DB (the
# /api/license/verify path). Isolation is total: its own engine, its own
# sessionmaker, and its own declarative Base — so create_all() here builds ONLY
# the claims table and never touches the license tables (and vice-versa).
#
# If CLAIMS_DATABASE_URL is unset, CLAIMS_DB_ENABLED stays False and the
# claim-history layer transparently falls back to its in-memory deque (the
# legacy 24h behaviour). A missing/!broken claims DB must NEVER crash startup.
# Same hardening as the primary: force the Supabase SESSION pooler (:5432),
# auto-rewriting a stale :6543 so the transaction-pooler bug can't reappear.
# ---------------------------------------------------------------------------
CLAIMS_DATABASE_URL = os.getenv("CLAIMS_DATABASE_URL")
if CLAIMS_DATABASE_URL and "pooler.supabase.com:6543" in CLAIMS_DATABASE_URL:
    CLAIMS_DATABASE_URL = CLAIMS_DATABASE_URL.replace(
        "pooler.supabase.com:6543", "pooler.supabase.com:5432"
    )

CLAIMS_DB_ENABLED = bool(CLAIMS_DATABASE_URL)
claims_engine = None
ClaimsSessionLocal = None
ClaimsBase = declarative_base()

if CLAIMS_DB_ENABLED:
    import logging as _logging_claims
    _claims_connect_args: dict = {}
    if CLAIMS_DATABASE_URL.startswith("sqlite"):
        _claims_connect_args["check_same_thread"] = False
    if CLAIMS_DATABASE_URL.startswith("postgresql"):
        _claims_connect_args.update({
            "connect_timeout": 10,
            "keepalives": 1,
            "keepalives_idle": 30,
            "keepalives_interval": 10,
            "keepalives_count": 3,
            "application_name": "kciade-claims",
        })
    # NullPool for the same eventlet-safety reasons documented on the primary
    # engine: the Supabase Session Pooler does the real pooling, psycogreen
    # yields libpq waits to the hub, and there is no in-process pool state for
    # greenlets to corrupt.
    claims_engine = create_engine(
        CLAIMS_DATABASE_URL,
        poolclass=NullPool,
        future=True,
        echo=False,
        connect_args=_claims_connect_args,
    )
    ClaimsSessionLocal = sessionmaker(
        bind=claims_engine,
        autoflush=False,
        autocommit=False,
        expire_on_commit=False,
        future=True,
    )
    _logging_claims.getLogger(__name__).info(
        "Claims DB ENABLED — second Supabase engine initialised (application_name=kciade-claims)."
    )
    # === TEMP DIAGNOSTIC (observational only — remove after capture) ==========
    # Proves the claims-DB "Second simultaneous read on fileno N" race. For every
    # DBAPI connect/close and every SQL op it logs greenlet id, DBAPI connection
    # id, socket fileno and timestamp. op=INSERT ⇒ writer greenlet; op=DELETE ⇒
    # pruner greenlet. Pure observers — NO writer/pruner behavior change.
    # Correlate at the next collision:
    #   • same dbapi id used by two greenlets (INSERT + DELETE, no CLOSE between)
    #       ⇒ shared DBAPI connection (Scenario 1)
    #   • CLOSE of a fileno, then a different greenlet hits the SAME fileno
    #       ⇒ OS descriptor reuse (Scenario 2)
    try:
        import threading as _cdbg_threading, time as _cdbg_time, logging as _cdbg_logging
        from sqlalchemy import event as _cdbg_event
        try:
            import eventlet as _cdbg_ev
            def _cdbg_glet():
                try:
                    return hex(id(_cdbg_ev.getcurrent()))
                except Exception:
                    return "?"
        except Exception:
            def _cdbg_glet():
                return "?"
        _cdbg = _cdbg_logging.getLogger("claimsdbg")

        def _cdbg_fileno(raw):
            try:
                return raw.fileno()
            except Exception:
                return "?"

        @_cdbg_event.listens_for(claims_engine, "connect")
        def _cdbg_on_connect(dbapi_conn, conn_record):
            _cdbg.info(
                "CONNECT | glet=%s thr=%s eng=%s dbapi=%s fileno=%s ts=%.6f",
                _cdbg_glet(), _cdbg_threading.get_ident(), hex(id(claims_engine)),
                hex(id(dbapi_conn)), _cdbg_fileno(dbapi_conn), _cdbg_time.time(),
            )

        @_cdbg_event.listens_for(claims_engine, "close")
        def _cdbg_on_close(dbapi_conn, conn_record):
            _cdbg.info(
                "CLOSE   | glet=%s thr=%s dbapi=%s fileno=%s ts=%.6f",
                _cdbg_glet(), _cdbg_threading.get_ident(),
                hex(id(dbapi_conn)), _cdbg_fileno(dbapi_conn), _cdbg_time.time(),
            )

        @_cdbg_event.listens_for(claims_engine, "before_cursor_execute")
        def _cdbg_on_sql(conn, cursor, statement, parameters, context, executemany):
            raw = getattr(conn.connection, "dbapi_connection", None) \
                or getattr(conn.connection, "connection", None)
            op = statement.strip().split(None, 1)[0].upper() if statement else "?"
            _cdbg.info(
                "SQL     | op=%s glet=%s thr=%s dbapi=%s fileno=%s ts=%.6f",
                op, _cdbg_glet(), _cdbg_threading.get_ident(),
                (hex(id(raw)) if raw is not None else "?"),
                _cdbg_fileno(raw), _cdbg_time.time(),
            )

        _cdbg.info("claims-DB diagnostic instrumentation ACTIVE (connect/close/SQL observers)")
    except Exception as _cdbg_exc:
        _logging_claims.getLogger(__name__).warning(
            f"claims-DB diagnostic instrumentation failed to attach: {_cdbg_exc}"
        )
    # === END TEMP DIAGNOSTIC ==================================================
else:
    import logging as _logging_claims
    _logging_claims.getLogger(__name__).info(
        "CLAIMS_DATABASE_URL not set — /count claim history will use the in-memory fallback."
    )


def init_db() -> None:
    """
    Import models and create tables. Should be invoked once during startup.
    """
    import logging
    try:
        from app import models  # noqa: F401  (side-effect import)
        Base.metadata.create_all(bind=engine)
    except Exception as e:
        logging.error(f"Error initializing database: {e}", exc_info=True)
        raise


def ensure_license_columns() -> None:
    """
    Idempotently ensure the prepaid-balance columns exist on `licenses`.

    `Base.metadata.create_all()` only CREATEs missing tables — it never ALTERs
    an existing one — so a freshly added column would otherwise require a manual
    migration. This runs `ALTER TABLE ... ADD COLUMN IF NOT EXISTS` (Postgres) so
    a deploy onto an existing DB self-heals.

    Best-effort and idempotent: it is called at boot (top of
    `rebuild_cache_from_db()`) BEFORE anything selects the new columns. A failure
    here must NEVER crash startup — the feature simply stays dormant until the
    columns exist. Skipped on non-Postgres (e.g. SQLite dev, where create_all
    already builds the column from the model).
    """
    if not DATABASE_URL or not DATABASE_URL.startswith("postgresql"):
        return
    import logging
    from sqlalchemy import text

    statements = (
        "ALTER TABLE licenses ADD COLUMN IF NOT EXISTS "
        "available_balance DOUBLE PRECISION NOT NULL DEFAULT 0",
        "ALTER TABLE licenses ADD COLUMN IF NOT EXISTS "
        "deduction_percentage DOUBLE PRECISION",
        # New licenses default to 4% at the DB level too, so ANY creation path
        # (ORM, raw SQL, admin) gets it. This only affects FUTURE inserts that
        # omit the column — existing NULL ("After Claims") rows are untouched.
        "ALTER TABLE licenses ALTER COLUMN deduction_percentage SET DEFAULT 4",
        # Preferred bot UI language (ISO 639-1). NULL => auto-detect from the
        # Telegram client. Added idempotently so a deploy self-heals BEFORE any
        # query selects it (create_all never ALTERs an existing table).
        "ALTER TABLE licenses ADD COLUMN IF NOT EXISTS language VARCHAR(8)",
    )
    try:
        with engine.begin() as conn:
            for stmt in statements:
                conn.execute(text(stmt))
        logging.getLogger(__name__).info(
            "ensure_license_columns: available_balance + deduction_percentage "
            "ensured (new-license default 4%)"
        )
    except Exception as e:
        logging.getLogger(__name__).warning(
            f"ensure_license_columns failed (non-fatal): {e}"
        )


def ensure_payments_table() -> None:
    """
    Idempotently create the `payments` table (OxaPay top-up audit log).

    Uses SQLAlchemy's `create(checkfirst=True)` so it is a no-op when the table
    already exists and builds it (with all UNIQUE constraints + indexes) when it
    doesn't — no manual migration required. Best-effort: a failure here must
    never crash startup; the top-up endpoints simply return a 5xx until the
    table exists. Runs at boot before any payment request can arrive.
    """
    if not DATABASE_URL:
        return
    import logging
    try:
        from app.models import Payment  # noqa: F401 (registers table on Base)
        Payment.__table__.create(bind=engine, checkfirst=True)
        logging.getLogger(__name__).info("ensure_payments_table: payments table ensured")
    except Exception as e:
        logging.getLogger(__name__).warning(
            f"ensure_payments_table failed (non-fatal): {e}"
        )


def ensure_claimer_apis_table() -> None:
    """
    Idempotently create the `claimer_apis` table (admin remote-management store).

    Same pattern as `ensure_payments_table`: `create(checkfirst=True)` is a no-op
    when the table already exists and otherwise builds it (with its unique index)
    — no manual migration. Best-effort: a failure here must never crash startup;
    the admin /api feature simply stays dormant until the table exists. Runs at
    boot (top of `rebuild_claimer_cache_from_db()`) before any read/flush.
    """
    if not DATABASE_URL:
        return
    import logging
    try:
        from app.models import ClaimerApi  # noqa: F401 (registers table on Base)
        ClaimerApi.__table__.create(bind=engine, checkfirst=True)
        logging.getLogger(__name__).info("ensure_claimer_apis_table: claimer_apis table ensured")
    except Exception as e:
        logging.getLogger(__name__).warning(
            f"ensure_claimer_apis_table failed (non-fatal): {e}"
        )


@contextmanager
def db_session() -> Generator:
    """
    Context manager that yields a SQLAlchemy session and guarantees cleanup.
    """
    session = SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def init_claims_db() -> None:
    """
    Create the claims table on the SECOND (claims) database.

    No-op when the claims DB is not configured. CRUCIALLY this must NEVER
    raise: a claims-DB init failure should degrade to the in-memory fallback,
    not take the whole service down (unlike init_db(), which is fatal because
    licenses are load-bearing).
    """
    if not CLAIMS_DB_ENABLED:
        return
    import logging
    try:
        from app import claims_models  # noqa: F401  (registers Claim on ClaimsBase)
        ClaimsBase.metadata.create_all(bind=claims_engine)
        logging.getLogger(__name__).info("Claims DB schema ensured (claims table).")
    except Exception as e:
        logging.getLogger(__name__).error(
            f"init_claims_db failed — continuing with in-memory fallback: {e}",
            exc_info=True,
        )
        # Intentionally NOT re-raised: degrade gracefully.


@contextmanager
def claims_db_session() -> Generator:
    """
    Context manager yielding a session bound to the CLAIMS database.

    Raises RuntimeError if the claims DB is not configured — callers must
    gate on CLAIMS_DB_ENABLED (and fall back to the in-memory deque) before
    using this. Guarantees commit/rollback/close like db_session().
    """
    if not CLAIMS_DB_ENABLED or ClaimsSessionLocal is None:
        raise RuntimeError("Claims DB is not configured (CLAIMS_DATABASE_URL unset)")
    session = ClaimsSessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
