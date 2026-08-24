"""
Admin remote claimer management — runtime cache + durable store + flush worker.

Mirrors the license layer's split: an in-memory cache is the RUNTIME source of
truth (like `active_license_cache`), the `claimer_apis` table is the DURABLE
backing store, and a background worker batches dirty rows to the DB every
30-60s (like `_conversion_worker`). This keeps DB egress to: reads only at boot,
writes = rare desired-config write-throughs + one batched upsert per interval.

HARD separation (the "backend is authoritative" rule, enforced structurally):
  * `set_desired_*` — the ONLY writers of the authoritative `desired_*` fields;
    they are write-through (persisted to the DB immediately).
  * `record_observed` — the ONLY writer of `observed_*`/meta; cache-only + marks
    the row dirty so it is never able to overwrite `desired_*`.

Tokens live behind `_enc_token`/`_dec_token` (pass-through in Phase 1) and are
NEVER logged; only their fingerprint is compared.
"""
from __future__ import annotations

import hashlib
import json
import logging
import threading
import time
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# key -> entry dict (see _new_entry). Runtime source of truth.
_claimer_cache: "Dict[Tuple[int, str], dict]" = {}
_claimer_cache_lock = threading.RLock()
# keys whose observed/meta changed since the last flush (desired writes are
# write-through and don't rely on this).
_dirty: "set[Tuple[int, str]]" = set()

_FLUSH_INTERVAL_S = 45.0          # batch cadence (30-60s window)
_MAX_NAME_LEN = 64
_MAX_CURRENCY_LEN = 10
_MAX_VERSION_LEN = 32
_MAX_FILTER_KEYS = 32


# ---------------------------------------------------------------------------
# Token confidentiality seam (Phase 1 = pass-through; Phase 2 swaps in crypto)
# ---------------------------------------------------------------------------
def _enc_token(plain: Optional[str]) -> Optional[str]:
    return plain if plain else None


def _dec_token(stored: Optional[str]) -> Optional[str]:
    return stored if stored else None


def token_fp(token: Optional[str]) -> Optional[str]:
    """Non-reversible short fingerprint for comparing tokens without exposing them."""
    if not token:
        return None
    return hashlib.sha256(token.encode('utf-8')).hexdigest()[:16]


def _key(telegram_id: int, claimer_id: str) -> Tuple[int, str]:
    return (int(telegram_id or 0), str(claimer_id or ''))


def _san(v, maxlen: int) -> Optional[str]:
    """Bound + strip control chars from an attacker-influenced string."""
    if v is None:
        return None
    s = ''.join(ch for ch in str(v) if ch >= ' ')[:maxlen].strip()
    return s or None


def _canon_filters(raw) -> Optional[dict]:
    """Canonicalise a filters map to a TRUE-ONLY dict of blocked keys.

    Accepts a dict like {"1":true,"2":false} or a list of keys; returns
    {"1": true, ...} with only the enabled (blocked) entries, capped.
    Returns None when input is None (unmanaged); {} means 'no blocks'.
    """
    if raw is None:
        return None
    out: dict = {}
    try:
        if isinstance(raw, dict):
            for k, v in raw.items():
                if v is True or v == 1 or v == '1' or v == 'true':
                    out[str(k)] = True
        elif isinstance(raw, (list, tuple)):
            for k in raw:
                out[str(k)] = True
    except Exception:
        return {}
    if len(out) > _MAX_FILTER_KEYS:
        out = dict(list(out.items())[:_MAX_FILTER_KEYS])
    return out


def _new_entry(claimer_name: Optional[str]) -> dict:
    now = time.time()
    return {
        'claimer_name': claimer_name,
        # desired (authoritative)
        'desired_token': None,
        'desired_token_fp': None,
        'desired_currency': None,
        'desired_filters': None,        # dict | None (None = unmanaged)
        # observed (informational)
        'observed_api_fp': None,
        'observed_api_valid': False,
        'observed_currency': None,
        'observed_filters': None,
        'stake_username': None,
        'version': None,
        # meta
        'online': False,
        'config_state': 'synced',
        'created_at': now,
        'last_seen': None,
        'last_api_validation': None,
        'last_push': None,
    }


# ---------------------------------------------------------------------------
# Boot: load the durable table into the cache once.
# ---------------------------------------------------------------------------
def rebuild_claimer_cache_from_db() -> int:
    """Load all claimer rows into `_claimer_cache`. Best-effort; never raises."""
    from app.database import SessionLocal, ensure_claimer_apis_table
    from app.models import ClaimerApi
    from sqlalchemy import select

    ensure_claimer_apis_table()
    loaded = 0
    try:
        with SessionLocal() as session:
            rows = session.execute(select(ClaimerApi)).scalars().all()
            with _claimer_cache_lock:
                _claimer_cache.clear()
                _dirty.clear()
                for r in rows:
                    e = _new_entry(r.claimer_name)
                    e['desired_token'] = _dec_token(r.desired_token)
                    e['desired_token_fp'] = r.desired_token_fp
                    e['desired_currency'] = r.desired_currency
                    e['desired_filters'] = _load_json(r.desired_filters)
                    e['observed_api_fp'] = r.observed_api_fp
                    e['observed_api_valid'] = bool(r.observed_api_valid)
                    e['observed_currency'] = r.observed_currency
                    e['observed_filters'] = _load_json(r.observed_filters)
                    e['stake_username'] = r.stake_username
                    e['version'] = r.version
                    # NOTE: never trust persisted online across a restart — a
                    # claimer is online only if it (re)connects. Start offline.
                    e['online'] = False
                    e['config_state'] = r.config_state or 'synced'
                    _claimer_cache[_key(r.telegram_id, r.claimer_id)] = e
                    loaded += 1
    except Exception as exc:
        logger.warning(f"rebuild_claimer_cache_from_db: {exc}")
    return loaded


def _load_json(s):
    if not s:
        return None
    try:
        return json.loads(s)
    except Exception:
        return None


# ---------------------------------------------------------------------------
# OBSERVED / meta writers (cache-only + dirty). Never touch desired_*.
# ---------------------------------------------------------------------------
def ensure_claimer(telegram_id: int, claimer_id: str, claimer_name: Optional[str]) -> dict:
    """Create the row if new; refresh the display name. Returns a copy of the entry."""
    k = _key(telegram_id, claimer_id)
    name = _san(claimer_name, _MAX_NAME_LEN)
    with _claimer_cache_lock:
        e = _claimer_cache.get(k)
        if e is None:
            e = _new_entry(name)
            _claimer_cache[k] = e
        elif name:
            e['claimer_name'] = name
        _dirty.add(k)
        return dict(e)


def record_observed(telegram_id: int, claimer_id: str, observed: dict) -> Optional[dict]:
    """Client `claimerStatus` — writes ONLY observed_*/meta, marks dirty.

    Returns a copy of the entry (for reconcile), or None if unknown.
    """
    k = _key(telegram_id, claimer_id)
    with _claimer_cache_lock:
        e = _claimer_cache.get(k)
        if e is None:
            return None
        e['observed_api_fp'] = _san(observed.get('apiFp'), 64)
        e['observed_api_valid'] = bool(observed.get('apiValid'))
        e['observed_currency'] = (_san(observed.get('currency'), _MAX_CURRENCY_LEN) or '').lower() or None
        e['observed_filters'] = _canon_filters(observed.get('filters'))
        e['stake_username'] = _san(observed.get('username'), _MAX_NAME_LEN)
        e['version'] = _san(observed.get('version'), _MAX_VERSION_LEN)
        e['online'] = True
        e['last_seen'] = time.time()
        _dirty.add(k)
        return dict(e)


def set_online(telegram_id: int, claimer_id: str, online: bool) -> Optional[bool]:
    """Set the online flag; return the PREVIOUS value (None if the claimer is
    unknown) so callers can detect a genuine online->offline transition. The
    read+write is atomic under the cache lock."""
    k = _key(telegram_id, claimer_id)
    with _claimer_cache_lock:
        e = _claimer_cache.get(k)
        if e is None:
            return None
        prev = bool(e['online'])
        e['online'] = bool(online)
        if online:
            e['last_seen'] = time.time()
        _dirty.add(k)
        return prev


def set_config_state(telegram_id: int, claimer_id: str, state: str,
                     stamp_push: bool = False, stamp_validation: bool = False) -> None:
    k = _key(telegram_id, claimer_id)
    with _claimer_cache_lock:
        e = _claimer_cache.get(k)
        if e is None:
            return
        e['config_state'] = state
        now = time.time()
        if stamp_push:
            e['last_push'] = now
        if stamp_validation:
            e['last_api_validation'] = now
        _dirty.add(k)


def apply_observed_after_push(telegram_id: int, claimer_id: str, applied: dict) -> None:
    """Record the values a push actually applied (from the apiResult ack) into
    observed_*, so reconcile immediately sees them as in-sync. Cache-only."""
    k = _key(telegram_id, claimer_id)
    with _claimer_cache_lock:
        e = _claimer_cache.get(k)
        if e is None:
            return
        if 'apiFp' in applied:
            e['observed_api_fp'] = _san(applied.get('apiFp'), 64)
        if 'valid' in applied:
            e['observed_api_valid'] = bool(applied.get('valid'))
        if applied.get('currency'):
            e['observed_currency'] = str(applied['currency']).lower()
        if applied.get('filters') is not None:
            e['observed_filters'] = _canon_filters(applied.get('filters'))
        if applied.get('username'):
            e['stake_username'] = _san(applied.get('username'), _MAX_NAME_LEN)
        _dirty.add(k)


# ---------------------------------------------------------------------------
# DESIRED writers (write-through: persist immediately). Admin-only callers.
# ---------------------------------------------------------------------------
def set_desired(telegram_id: int, claimer_id: str, *, token=..., currency=...,
                filters=...) -> Optional[dict]:
    """Set one or more authoritative desired_* fields and persist immediately.

    Pass a value to change a field, or leave the kwarg at its `...` sentinel to
    leave it untouched. `token=None` clears the API (Remove API). Returns a copy
    of the entry, or None if the claimer is unknown.
    """
    k = _key(telegram_id, claimer_id)
    with _claimer_cache_lock:
        e = _claimer_cache.get(k)
        if e is None:
            return None
        if token is not ...:
            e['desired_token'] = (str(token).strip() or None) if token else None
            e['desired_token_fp'] = token_fp(e['desired_token'])
        if currency is not ...:
            e['desired_currency'] = (_san(currency, _MAX_CURRENCY_LEN) or '').lower() or None
        if filters is not ...:
            e['desired_filters'] = _canon_filters(filters)
        snapshot = dict(e)
    _persist_row(telegram_id, claimer_id)   # write-through, outside the lock
    return snapshot


# ---------------------------------------------------------------------------
# Reads (cache only — no DB).
# ---------------------------------------------------------------------------
def get_claimer(telegram_id: int, claimer_id: str) -> Optional[dict]:
    with _claimer_cache_lock:
        e = _claimer_cache.get(_key(telegram_id, claimer_id))
        return dict(e) if e else None


def list_claimers(telegram_id: int) -> List[dict]:
    """All of this admin's known claimers (online + offline), from cache."""
    tid = int(telegram_id or 0)
    out: List[dict] = []
    with _claimer_cache_lock:
        for (t, cid), e in _claimer_cache.items():
            if t == tid:
                row = dict(e)
                row['claimer_id'] = cid
                out.append(row)
    out.sort(key=lambda r: (not r.get('online'), (r.get('claimer_name') or '').lower()))
    return out


# ---------------------------------------------------------------------------
# Persistence: single-row write-through + batched flush.
# ---------------------------------------------------------------------------
def _row_values(telegram_id: int, claimer_id: str, e: dict) -> dict:
    return {
        'telegram_id': int(telegram_id or 0),
        'claimer_id': str(claimer_id),
        'claimer_name': e.get('claimer_name'),
        'desired_token': _enc_token(e.get('desired_token')),
        'desired_token_fp': e.get('desired_token_fp'),
        'desired_currency': e.get('desired_currency'),
        'desired_filters': json.dumps(e['desired_filters']) if e.get('desired_filters') is not None else None,
        'observed_api_fp': e.get('observed_api_fp'),
        'observed_api_valid': bool(e.get('observed_api_valid')),
        'observed_currency': e.get('observed_currency'),
        'observed_filters': json.dumps(e['observed_filters']) if e.get('observed_filters') is not None else None,
        'stake_username': e.get('stake_username'),
        'version': e.get('version'),
        'online': bool(e.get('online')),
        'config_state': e.get('config_state') or 'synced',
        'last_seen': _to_dt(e.get('last_seen')),
        'last_api_validation': _to_dt(e.get('last_api_validation')),
        'last_push': _to_dt(e.get('last_push')),
    }


def _to_dt(ts):
    if not ts:
        return None
    from datetime import datetime, timezone
    try:
        return datetime.fromtimestamp(float(ts), tz=timezone.utc)
    except Exception:
        return None


def _upsert(session, values: dict) -> None:
    from app.models import ClaimerApi
    from sqlalchemy.dialects.postgresql import insert as pg_insert
    stmt = pg_insert(ClaimerApi.__table__).values(**values)
    update_cols = {c: stmt.excluded[c] for c in values
                   if c not in ('telegram_id', 'claimer_id')}
    stmt = stmt.on_conflict_do_update(
        index_elements=['telegram_id', 'claimer_id'],
        set_=update_cols,
    )
    session.execute(stmt)


def _persist_row(telegram_id: int, claimer_id: str) -> None:
    """Write-through a single row immediately (used by desired_* changes)."""
    from app.database import SessionLocal
    k = _key(telegram_id, claimer_id)
    with _claimer_cache_lock:
        e = _claimer_cache.get(k)
        if e is None:
            return
        values = _row_values(telegram_id, claimer_id, e)
        _dirty.discard(k)
    try:
        with SessionLocal() as session:
            _upsert(session, values)
            session.commit()
    except Exception as exc:
        logger.warning(f"claimer _persist_row failed: {exc}")
        with _claimer_cache_lock:
            _dirty.add(k)   # retry on next flush


def flush_dirty() -> int:
    """Batch-write all dirty rows in ONE transaction. Returns rows written."""
    from app.database import SessionLocal
    with _claimer_cache_lock:
        keys = list(_dirty)
        batch = []
        for k in keys:
            e = _claimer_cache.get(k)
            if e is not None:
                batch.append(_row_values(k[0], k[1], e))
        _dirty.clear()
    if not batch:
        return 0
    try:
        with SessionLocal() as session:
            for values in batch:
                _upsert(session, values)
            session.commit()
        return len(batch)
    except Exception as exc:
        logger.warning(f"claimer flush_dirty failed ({len(batch)} rows): {exc}")
        with _claimer_cache_lock:
            _dirty.update(keys)   # retry next tick
        return 0


def _claimer_flush_worker() -> None:
    """Background loop: batched flush every ~45s (mirrors _conversion_worker)."""
    import eventlet
    while True:
        try:
            eventlet.sleep(_FLUSH_INTERVAL_S)
            n = flush_dirty()
            if n:
                logger.debug(f"claimer flush: {n} rows")
        except Exception as exc:
            logger.warning(f"claimer flush worker tick failed: {exc}")


def start_claimer_flush_worker() -> None:
    """Start the flush greenlet once (called from post_worker_init)."""
    from app import socketio
    socketio.start_background_task(_claimer_flush_worker)
    logger.info("claimer flush worker started (interval=%ss)", _FLUSH_INTERVAL_S)
