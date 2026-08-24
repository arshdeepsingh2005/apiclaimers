"""
Durable claim history for the Telegram /count command.

Two storage backends, selected automatically at import time:

  * CLAIMS DB (preferred) — when CLAIMS_DATABASE_URL is set, claims are written
    to a `claims` table on a SECOND Supabase project (see app.claims_models).
    Retention is multi-day (default 30) and survives restarts/redeploys.
    Queries support arbitrary [start, end] windows with SQL GROUP BY.

  * IN-MEMORY DEQUE (fallback) — when the claims DB is NOT configured, the
    legacy bounded deque (24h, volatile) is used so the feature keeps working
    with no external dependency. A missing claims DB never breaks anything.

WRITE PATH (DB backend) — built for 1000 concurrent claimers:
  Every claim already funnels through ONE conversion-worker greenlet, so
  record_claim() is called serially. It does an O(1), non-blocking put_nowait
  onto a dedicated claims-write queue and returns immediately — the conversion
  worker is NEVER blocked on claims-DB latency. A separate writer greenlet
  drains that queue and flushes in BATCHES (>= BATCH_SIZE rows OR every
  FLUSH_INTERVAL seconds) via a single INSERT ... ON CONFLICT DO NOTHING.
  1000 claims collapse into a handful of batched inserts.

  Best-effort throughout: a claims-DB failure logs and is swallowed; the claim/
  credit path is never broken. ON CONFLICT (username, code) DO NOTHING gives a
  DB-level idempotency safety net on top of the upstream dedup marker.

READ PATH:
  /count reads query the claims DB directly (time window + GROUP BY username).
  Bounded staleness <= FLUSH_INTERVAL (a couple of seconds) — irrelevant for a
  human-initiated, rate-limited report.

All public query functions return the SAME record-dict shape the bot already
consumes, so internal.py / the bot need no shape changes:
  {ts, license_key, telegram_id, username, code, amount_usd, currency,
   original_amount}
(ts is a float epoch-seconds, matching the legacy deque records.)
"""
from __future__ import annotations

from collections import deque
from datetime import datetime, timezone, timedelta
from typing import Deque, List, Optional
import logging
import os
import threading
import time

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Backend selection
# ---------------------------------------------------------------------------
try:
    from app.database import CLAIMS_DB_ENABLED
except Exception:  # pragma: no cover - defensive
    CLAIMS_DB_ENABLED = False

# ---------------------------------------------------------------------------
# IST window math (fixed UTC+5:30 — India has no DST, so a fixed offset is
# exact and dependency-free, no tzdata needed on the container).
# ---------------------------------------------------------------------------
IST = timezone(timedelta(hours=5, minutes=30))


def _parse_hhmm(value: str, default: tuple) -> tuple:
    try:
        hh, mm = value.strip().split(":")
        return int(hh), int(mm)
    except Exception:
        return default


# Stream-special window + retention are env-configurable; defaults per spec.
STREAM_WINDOW_START = _parse_hhmm(os.getenv("STREAM_WINDOW_START", "06:00"), (6, 0))
STREAM_WINDOW_END = _parse_hhmm(os.getenv("STREAM_WINDOW_END", "09:30"), (9, 30))

try:
    CLAIM_RETENTION_DAYS = int(os.getenv("CLAIM_RETENTION_DAYS", "30"))
except (TypeError, ValueError):
    CLAIM_RETENTION_DAYS = 30
if CLAIM_RETENTION_DAYS <= 0:
    CLAIM_RETENTION_DAYS = 30

# Custom-range cap (days). Each /count custom query spans at most this many days.
CUSTOM_RANGE_MAX_DAYS = 7


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def stream_window_utc(reference: Optional[datetime] = None) -> tuple:
    """
    Today's STREAM_WINDOW_START-END (IST) as a (start_utc, end_utc) pair.
    If the reference instant (in IST) is before the window start, the PREVIOUS
    day's window is used so the option always returns a real (completed or
    in-progress) stream rather than an empty future range.
    """
    ref = (reference or now_utc()).astimezone(IST)
    day = ref.date()
    start_ist = datetime(day.year, day.month, day.day,
                         STREAM_WINDOW_START[0], STREAM_WINDOW_START[1], 0, tzinfo=IST)
    if ref < start_ist:
        day = (ref - timedelta(days=1)).date()
        start_ist = datetime(day.year, day.month, day.day,
                             STREAM_WINDOW_START[0], STREAM_WINDOW_START[1], 0, tzinfo=IST)
    end_ist = datetime(day.year, day.month, day.day,
                       STREAM_WINDOW_END[0], STREAM_WINDOW_END[1], 0, tzinfo=IST)
    return start_ist.astimezone(timezone.utc), end_ist.astimezone(timezone.utc)


def rolling_window_utc(days: float, reference: Optional[datetime] = None) -> tuple:
    """Last `days` days as (start_utc, end_utc)."""
    end = reference or now_utc()
    return end - timedelta(days=days), end


def custom_window_utc(from_str: str, to_str: str) -> tuple:
    """
    Parse 'YYYY-MM-DD' from/to dates (interpreted in IST), validate, and return
    an inclusive (start_utc, end_utc): [from 00:00:00 IST, to 23:59:59.999999 IST].

    Raises ValueError with a short, user-facing message on any problem
    (bad format, reversed, gap > CUSTOM_RANGE_MAX_DAYS, future, older than
    retention).
    """
    try:
        d_from = datetime.strptime(from_str.strip(), "%Y-%m-%d").date()
        d_to = datetime.strptime(to_str.strip(), "%Y-%m-%d").date()
    except (ValueError, AttributeError):
        raise ValueError("dates must be in YYYY-MM-DD format")
    if d_to < d_from:
        raise ValueError("the 'to' date is before the 'from' date")
    gap = (d_to - d_from).days
    if gap > CUSTOM_RANGE_MAX_DAYS:
        raise ValueError(
            f"that range is {gap} days - the maximum is {CUSTOM_RANGE_MAX_DAYS} days"
        )
    today_ist = now_utc().astimezone(IST).date()
    oldest_allowed = today_ist - timedelta(days=CLAIM_RETENTION_DAYS)
    if d_from < oldest_allowed:
        raise ValueError(
            f"'from' is older than the {CLAIM_RETENTION_DAYS}-day history limit"
        )
    if d_from > today_ist:
        raise ValueError("'from' date is in the future")
    start_ist = datetime(d_from.year, d_from.month, d_from.day, 0, 0, 0, tzinfo=IST)
    end_ist = datetime(d_to.year, d_to.month, d_to.day, 23, 59, 59, 999999, tzinfo=IST)
    return start_ist.astimezone(timezone.utc), end_ist.astimezone(timezone.utc)


# ---------------------------------------------------------------------------
# In-memory deque (fallback backend + legacy)
# ---------------------------------------------------------------------------
_MAX_RECORDS = 50_000
_FALLBACK_RETENTION_SECONDS = 24 * 3600          # deque is 24h only
_PRUNE_INTERVAL_SECONDS = 5 * 60
_claim_history: Deque[dict] = deque(maxlen=_MAX_RECORDS)
_claim_history_lock = threading.Lock()


# ---------------------------------------------------------------------------
# Claims-DB write queue + batched writer (DB backend)
# ---------------------------------------------------------------------------
import queue as _queue_mod

_BATCH_SIZE = 100
_FLUSH_INTERVAL = 2.0          # seconds
_WRITE_QUEUE_MAX = 5000
_claims_write_queue = _queue_mod.Queue(maxsize=_WRITE_QUEUE_MAX)


def _normalize_record(license_key, telegram_id, username, code,
                      amount_usd, currency, original_amount) -> dict:
    return {
        'ts': time.time(),
        'license_key': (license_key or '')[:128],
        'telegram_id': int(telegram_id) if telegram_id else 0,
        'username': (username or '').strip()[:64],
        'code': (code or '').strip()[:64],
        'amount_usd': float(amount_usd),
        'currency': (currency or '').upper()[:10],
        'original_amount': float(original_amount) if original_amount is not None else 0.0,
    }


def record_claim(
    *,
    license_key: Optional[str],
    telegram_id: Optional[int],
    username: str,
    code: str,
    amount_usd: float,
    currency: str,
    original_amount: float,
) -> None:
    """
    Record a successful, credited claim.

    DB backend: O(1) non-blocking enqueue onto the batched writer's queue.
    Fallback : append to the in-memory deque.

    Never raises - history must never break the claim path.
    """
    try:
        record = _normalize_record(license_key, telegram_id, username, code,
                                   amount_usd, currency, original_amount)
    except Exception as exc:
        logger.warning(f"claim_history.record_claim normalize failed: {exc}", exc_info=True)
        return

    if CLAIMS_DB_ENABLED:
        try:
            _claims_write_queue.put_nowait(record)
        except _queue_mod.Full:
            # Writer is behind a very large burst - drop + log (best-effort),
            # exactly like the conversion queue's queue_full behaviour.
            logger.warning(
                f"claim_history: write queue full; dropped "
                f"user={record['username']} code={record['code']}"
            )
        except Exception as exc:
            logger.warning(f"claim_history.record_claim enqueue failed: {exc}", exc_info=True)
        return

    # Fallback: in-memory deque
    try:
        with _claim_history_lock:
            _claim_history.append(record)
    except Exception as exc:
        logger.warning(f"claim_history.record_claim (deque) failed: {exc}", exc_info=True)


def _flush_batch(batch: List[dict]) -> int:
    """
    Write a batch to the claims DB via a single INSERT ... ON CONFLICT
    (username, code) DO NOTHING. Returns rows attempted. Best-effort: logs and
    swallows DB errors so the writer greenlet never dies.
    """
    if not batch:
        return 0
    try:
        from app.database import claims_db_session
        from app.claims_models import Claim
        from sqlalchemy.dialects.postgresql import insert as pg_insert

        rows = []
        for r in batch:
            rows.append({
                'ts': datetime.fromtimestamp(r['ts'], tz=timezone.utc),
                'license_key': r['license_key'] or None,
                'telegram_id': r['telegram_id'] or None,
                'username': r['username'],
                'code': r['code'],
                'amount_usd': r['amount_usd'],
                'currency': r['currency'] or None,
                'original_amount': r['original_amount'],
            })
        with claims_db_session() as s:
            stmt = pg_insert(Claim.__table__).values(rows)
            stmt = stmt.on_conflict_do_nothing(index_elements=['username', 'code'])
            s.execute(stmt)
        return len(rows)
    except Exception as exc:
        logger.warning(
            f"claim_history._flush_batch failed (dropped {len(batch)} rows): {exc}",
            exc_info=True,
        )
        return 0


def _writer_loop() -> None:
    """
    Dedicated greenlet: drain the write queue and flush in batches. Flushes when
    the batch reaches _BATCH_SIZE OR _FLUSH_INTERVAL elapses with items pending.
    Never dies on per-iteration errors.
    """
    import eventlet
    batch: List[dict] = []
    last_flush = time.time()
    while True:
        try:
            try:
                # Block up to the flush interval for the next record.
                item = _claims_write_queue.get(timeout=_FLUSH_INTERVAL)
                if item is not None:
                    batch.append(item)
                _claims_write_queue.task_done()
                # Opportunistically drain whatever else is immediately available.
                while len(batch) < _BATCH_SIZE:
                    try:
                        item = _claims_write_queue.get_nowait()
                        if item is not None:
                            batch.append(item)
                        _claims_write_queue.task_done()
                    except _queue_mod.Empty:
                        break
            except _queue_mod.Empty:
                pass

            now = time.time()
            if batch and (len(batch) >= _BATCH_SIZE or (now - last_flush) >= _FLUSH_INTERVAL):
                written = _flush_batch(batch)
                if written:
                    logger.debug(f"claim_history: flushed {written} claim rows")
                batch = []
                last_flush = now
        except Exception as exc:
            logger.warning(f"claim_history._writer_loop iteration error: {exc}", exc_info=True)
            try:
                eventlet.sleep(1)
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Queries - return legacy record-dict shape regardless of backend
# ---------------------------------------------------------------------------
def _rows_to_records(rows) -> List[dict]:
    out = []
    for row in rows:
        ts = row.ts
        if isinstance(ts, datetime):
            ts_epoch = ts.timestamp()
        else:
            ts_epoch = float(ts) if ts else 0.0
        out.append({
            'ts': ts_epoch,
            'license_key': row.license_key or '',
            'telegram_id': int(row.telegram_id) if row.telegram_id else 0,
            'username': row.username or '',
            'code': row.code or '',
            'amount_usd': float(row.amount_usd) if row.amount_usd is not None else 0.0,
            'currency': row.currency or '',
            'original_amount': float(row.original_amount) if row.original_amount is not None else 0.0,
        })
    return out


def _query_db(column, value, start_utc: datetime, end_utc: datetime) -> List[dict]:
    """Run the windowed SELECT on the claims DB for the given filter column."""
    from app.database import claims_db_session
    from app.claims_models import Claim
    from sqlalchemy import select
    col = getattr(Claim, column)
    stmt = (
        select(Claim)
        .where(col == value)
        .where(Claim.ts >= start_utc)
        .where(Claim.ts <= end_utc)
        .order_by(Claim.ts.desc())
    )
    with claims_db_session() as s:
        rows = s.execute(stmt).scalars().all()
    return _rows_to_records(rows)


def _filter_deque(predicate, start_utc: datetime, end_utc: datetime) -> List[dict]:
    start_ep, end_ep = start_utc.timestamp(), end_utc.timestamp()
    with _claim_history_lock:
        snap = list(_claim_history)
    return [r for r in snap if predicate(r) and start_ep <= r['ts'] <= end_ep]


def query_by_telegram_window(telegram_id: int, start_utc: datetime, end_utc: datetime) -> List[dict]:
    """Claims for a Telegram user within [start, end]. Regular-user /count."""
    if not telegram_id:
        return []
    tg = int(telegram_id)
    if CLAIMS_DB_ENABLED:
        try:
            return _query_db('telegram_id', tg, start_utc, end_utc)
        except Exception as exc:
            logger.warning(f"query_by_telegram_window DB error: {exc}", exc_info=True)
            return []
    return _filter_deque(lambda r: r['telegram_id'] == tg, start_utc, end_utc)


def query_by_license_window(license_key: str, start_utc: datetime, end_utc: datetime) -> List[dict]:
    """Claims for a license within [start, end]. Admin only."""
    if not license_key:
        return []
    if CLAIMS_DB_ENABLED:
        try:
            return _query_db('license_key', license_key, start_utc, end_utc)
        except Exception as exc:
            logger.warning(f"query_by_license_window DB error: {exc}", exc_info=True)
            return []
    return _filter_deque(lambda r: r['license_key'] == license_key, start_utc, end_utc)


def query_by_username_window(username: str, start_utc: datetime, end_utc: datetime) -> List[dict]:
    """Claims for a Stake username within [start, end]. Admin only."""
    if not username:
        return []
    uname = username.strip()
    if not uname:
        return []
    if CLAIMS_DB_ENABLED:
        try:
            return _query_db('username', uname, start_utc, end_utc)
        except Exception as exc:
            logger.warning(f"query_by_username_window DB error: {exc}", exc_info=True)
            return []
    return _filter_deque(lambda r: r['username'] == uname, start_utc, end_utc)


# ---- Backward-compatible hours-based wrappers (used by any legacy caller) ----
def query_by_telegram(telegram_id: int, hours: float) -> List[dict]:
    if hours <= 0:
        return []
    s, e = rolling_window_utc(hours / 24.0)
    return query_by_telegram_window(telegram_id, s, e)


def query_by_license(license_key: str, hours: float) -> List[dict]:
    if hours <= 0:
        return []
    s, e = rolling_window_utc(hours / 24.0)
    return query_by_license_window(license_key, s, e)


def query_by_username(username: str, hours: float) -> List[dict]:
    if hours <= 0:
        return []
    s, e = rolling_window_utc(hours / 24.0)
    return query_by_username_window(username, s, e)


def stats() -> dict:
    """Lightweight diagnostics. DB backend reports the queue depth."""
    if CLAIMS_DB_ENABLED:
        return {
            'backend': 'claims_db',
            'write_queue_depth': _claims_write_queue.qsize(),
            'retention_days': CLAIM_RETENTION_DAYS,
        }
    with _claim_history_lock:
        total = len(_claim_history)
        oldest_ts = _claim_history[0]['ts'] if _claim_history else None
        newest_ts = _claim_history[-1]['ts'] if _claim_history else None
    return {
        'backend': 'memory',
        'total_records': total,
        'oldest_ts': oldest_ts,
        'newest_ts': newest_ts,
        'cap': _MAX_RECORDS,
    }


# ---------------------------------------------------------------------------
# Retention pruner
# ---------------------------------------------------------------------------
def _prune_once() -> int:
    """
    DB backend: DELETE rows older than the retention window. Returns rows
    removed (or -1 on error). Fallback: trim the 24h deque.
    """
    if CLAIMS_DB_ENABLED:
        try:
            from app.database import claims_db_session
            from app.claims_models import Claim
            from sqlalchemy import delete
            cutoff = now_utc() - timedelta(days=CLAIM_RETENTION_DAYS)
            with claims_db_session() as s:
                result = s.execute(delete(Claim).where(Claim.ts < cutoff))
            return int(result.rowcount or 0)
        except Exception as exc:
            logger.warning(f"claim_history._prune_once (DB) failed: {exc}", exc_info=True)
            return -1
    cutoff = time.time() - _FALLBACK_RETENTION_SECONDS
    removed = 0
    with _claim_history_lock:
        while _claim_history and _claim_history[0]['ts'] < cutoff:
            _claim_history.popleft()
            removed += 1
    return removed


def _prune_loop() -> None:
    import eventlet
    while True:
        try:
            eventlet.sleep(_PRUNE_INTERVAL_SECONDS)
            removed = _prune_once()
            if removed and removed > 0:
                logger.info(f"claim_history.prune | backend={'db' if CLAIMS_DB_ENABLED else 'memory'} | removed={removed}")
        except Exception as exc:
            logger.warning(f"claim_history.prune_loop error: {exc}", exc_info=True)
            try:
                eventlet.sleep(60)
            except Exception:
                pass


def start_pruner() -> None:
    """
    Start the background greenlets exactly once (idempotent):
      * the retention pruner (both backends)
      * the batched DB writer (DB backend only)
    """
    if getattr(start_pruner, '_started', False):
        return
    try:
        import eventlet
        eventlet.spawn(_prune_loop)
        if CLAIMS_DB_ENABLED:
            eventlet.spawn(_writer_loop)
        start_pruner._started = True
        logger.info(
            f"claim_history started | backend={'claims_db' if CLAIMS_DB_ENABLED else 'memory'} | "
            f"retention_days={CLAIM_RETENTION_DAYS} | prune_interval={_PRUNE_INTERVAL_SECONDS}s | "
            f"writer={'on' if CLAIMS_DB_ENABLED else 'off'}"
        )
    except Exception as exc:
        logger.warning(f"claim_history.start_pruner failed: {exc}", exc_info=True)
