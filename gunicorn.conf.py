"""
Gunicorn configuration for production deployment.

Single eventlet worker is REQUIRED because all shared state
(sse_manager, user_service cache, rate-limit deques, claimed-code dedupe)
lives in-process. Multi-worker would split the broadcast fan-out and
rate-limit state and is explicitly forbidden at this stage.

psycopg2 is green-patched in `app/_bootstrap.py`, which is imported as
the first line of `wsgi.py` — after gunicorn's init_process has already
applied eventlet.monkey_patch(). No bootstrap call belongs in this file.
"""
import os

PORT = int(os.environ.get("PORT", 5000))
bind = f"0.0.0.0:{PORT}"
backlog = 2048

workers = 1
worker_class = "eventlet"
worker_connections = 2000
# 180s gives the eventlet hub ample headroom when psycogreen is active.
# Under the prior (un-patched) configuration the worker could stall for
# >120s on blocking libpq I/O; with psycogreen installed this margin is
# effectively untouchable during normal operation.
timeout = 180
graceful_timeout = 30
keepalive = 5
preload_app = False

accesslog = "-"
errorlog = "-"
loglevel = "info"

proc_name = "code-server"


def on_starting(server):
    pass


def when_ready(server):
    pass


def worker_int(worker):
    import logging
    logging.warning(f"Worker {worker.pid} received INT/QUIT signal")
    # Suppress claimer-offline notifications during teardown (SIGINT/SIGQUIT).
    try:
        from app.routes.tmc_routes import mark_shutting_down
        mark_shutting_down()
    except Exception:
        pass


def pre_fork(server, worker):
    pass


def post_fork(server, worker):
    pass


def post_worker_init(worker):
    """Start background threads in the worker process so they share memory
    with the request handlers. Threads do NOT survive fork()."""
    import logging
    import os
    import threading
    logger = logging.getLogger(__name__)
    try:
        # API_CLAIMER_MODE: ensure the API-Claimer tables exist WITHOUT needing
        # RUN_INIT_DB. create_all(checkfirst=True) only issues DDL for missing
        # tables → fast no-op after the first boot. Runs here (post-fork, socket
        # already bound) so it can't fail Render's port detection. Non-fatal.
        if os.environ.get('API_CLAIMER_MODE', 'true').lower() == 'true':
            try:
                from app.database import engine, Base
                from app.models import ApiAccount, ApiSlot, ApiClaim, ApiOrder
                Base.metadata.create_all(engine, tables=[
                    ApiAccount.__table__, ApiSlot.__table__, ApiClaim.__table__,
                    ApiOrder.__table__])
                # create_all only creates MISSING tables; it does NOT add new
                # columns to an already-existing api_accounts. Add the pool
                # columns idempotently (Postgres ADD COLUMN IF NOT EXISTS).
                try:
                    from sqlalchemy import text as _sql_text
                    with engine.begin() as _conn:
                        _conn.execute(_sql_text(
                            "ALTER TABLE api_accounts "
                            "ADD COLUMN IF NOT EXISTS is_pool BOOLEAN NOT NULL DEFAULT FALSE"))
                        _conn.execute(_sql_text(
                            "ALTER TABLE api_accounts "
                            "ADD COLUMN IF NOT EXISTS worker_label VARCHAR(40)"))
                        _conn.execute(_sql_text(
                            "CREATE INDEX IF NOT EXISTS ix_api_accounts_is_pool "
                            "ON api_accounts (is_pool)"))
                except Exception as _mexc:
                    logger.error(f"post_worker_init: api_accounts column migration "
                                 f"failed: {_mexc}", exc_info=True)
                logger.info("post_worker_init: API-Claimer tables ensured "
                            "(api_accounts/api_slots/api_claims/api_orders)")
            except Exception as exc:
                logger.error(f"post_worker_init: ensure api tables failed: {exc}",
                             exc_info=True)

        from wsgi import app as flask_app
        from app import (
            _start_sse_cleanup_thread,
            _start_active_disconnect_worker,
            _start_cache_sweep_worker,
            _start_license_activation_scanner,
            _start_slot_expiry_sweep,
        )
        _start_sse_cleanup_thread()
        _start_active_disconnect_worker(flask_app)
        _start_cache_sweep_worker(flask_app)

        # API_CLAIMER_MODE: slot-sales expiry + reservation sweep (capacity cleanup).
        if os.environ.get('API_CLAIMER_MODE', 'true').lower() == 'true':
            try:
                _start_slot_expiry_sweep(flask_app)
            except Exception as exc:
                logger.error(f"post_worker_init: slot expiry sweep start failed: {exc}",
                             exc_info=True)

        # License cache bootstrap + scanner (Phase F)
        try:
            from app.license_manager import rebuild_cache_from_db
            n = rebuild_cache_from_db()
            logger.info(f"License cache loaded: {n} active licenses")
        except Exception as exc:
            logger.warning(f"License cache load failed (non-fatal): {exc}")
        _start_license_activation_scanner(flask_app)

        # Claimer remote-management cache bootstrap + batched flush worker
        try:
            from app.claimer_manager import (
                rebuild_claimer_cache_from_db,
                start_claimer_flush_worker,
            )
            cn = rebuild_claimer_cache_from_db()
            logger.info(f"Claimer cache loaded: {cn} claimers")
            start_claimer_flush_worker()
        except Exception as exc:
            logger.warning(f"Claimer cache/worker init failed (non-fatal): {exc}")

        # API_CLAIMER_MODE: the balance/currency conversion worker is main-product
        # (queries the balance tables) — do NOT start it against the new DB.
        _api_claimer_mode = os.environ.get('API_CLAIMER_MODE', 'false').lower() == 'true'
        if _api_claimer_mode:
            logger.info("post_worker_init: conversion worker NOT started (API_CLAIMER_MODE)")
        else:
            from app.routes.api import _conversion_worker, _worker_thread_start_pid
            if _worker_thread_start_pid != os.getpid():
                t = threading.Thread(
                    target=_conversion_worker,
                    daemon=True,
                    name="Conversion-Worker",
                )
                t.start()
                logger.info(
                    f"post_worker_init: conversion worker restarted in pid={os.getpid()} "
                    f"(was started in pid={_worker_thread_start_pid})"
                )
            else:
                logger.info(
                    f"post_worker_init: conversion worker already alive in pid={os.getpid()}"
                )

        # Shutdown guard for claimer-offline notifications on the production
        # deploy path. Render/Docker send SIGTERM -> gunicorn -> SIGTERM to the
        # worker -> handle_exit, which calls NO gunicorn hook. init_signals ran
        # before this, so getsignal(SIGTERM) is gunicorn's own handler: chain a
        # handler that sets the flag then delegates to it, leaving gunicorn's
        # graceful shutdown exactly as-is. (SIGINT/SIGQUIT are covered by
        # worker_int above.)
        try:
            import signal
            from app.routes.tmc_routes import mark_shutting_down
            _prev_term = signal.getsignal(signal.SIGTERM)

            def _term_guard(signum, frame, _prev=_prev_term):
                mark_shutting_down()
                if callable(_prev):
                    _prev(signum, frame)          # gunicorn's handle_exit
                elif _prev == signal.SIG_DFL:
                    raise SystemExit(0)           # default: terminate
                # SIG_IGN -> mirror ignore (do nothing)

            signal.signal(signal.SIGTERM, _term_guard)
            logger.info("post_worker_init: chained SIGTERM shutdown guard installed")
        except Exception as exc:
            logger.warning(f"post_worker_init: SIGTERM guard not installed: {exc}")

        logger.info(f"post_worker_init: all background workers ready in pid={os.getpid()}")

        # 24-hour rolling claim history pruner (for /count Telegram command).
        # Starts AFTER the other workers are healthy so a startup failure here
        # never blocks the claim/broadcast paths. Idempotent: safe to call
        # multiple times.
        # API_CLAIMER_MODE: main-product claim_history pruner (legacy /count) —
        # not used by the API-Claimer product (which has its own api_claims).
        if not _api_claimer_mode:
            try:
                from app import claim_history
                claim_history.start_pruner()
            except Exception as exc:
                logger.warning(f"post_worker_init: claim_history pruner start failed (non-fatal): {exc}")
    except Exception as e:
        logger.error(
            f"post_worker_init: failed to start background workers: {e}",
            exc_info=True,
        )
