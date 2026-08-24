"""Throttled admin alert when a license hits a rate limit.

Mirrors app/utils/conn_attack_monitor.py / attack_monitor.py: a bounded LRU of
per-(license, kind) cooldown timestamps mutated under a short lock; the alert is
built under the lock but SENT after the lock is released, via the fire-and-forget
detached-curl notify_bot_service. Best-effort — never raises, never blocks a
request, never spams (at most one DM per cooldown per license+kind, even under a
sustained flood).

Env:
  RATELIMIT_NOTIFY_ENABLED   on/off (default true)
  RATELIMIT_NOTIFY_COOLDOWN_S per (license, kind) cooldown seconds (default 300)
Delivery requires ADMIN_TELEGRAM_ID (same as the broadcast / attack alerts).

Called ONLY on the already-rejecting branch of a rate-limit check, so it adds
zero cost to the happy path.
"""
import logging
import os
import threading
import time
from collections import OrderedDict

logger = logging.getLogger(__name__)

_LOCK = threading.Lock()
# (license_key, kind) -> last_alert_ts, used as a bounded LRU.
_TRACKER: "OrderedDict[tuple, float]" = OrderedDict()
_MAX_KEYS = 5000


def _enabled() -> bool:
    v = (os.environ.get('RATELIMIT_NOTIFY_ENABLED', 'true') or 'true').strip().lower()
    return v not in ('0', 'false', 'no', 'off')


def _cooldown() -> float:
    try:
        c = float(os.environ.get('RATELIMIT_NOTIFY_COOLDOWN_S', '300'))
        return c if c > 0 else 300.0
    except (TypeError, ValueError):
        return 300.0


def _kind_desc(kind: str) -> str:
    if kind == 'userclaim':
        n = os.environ.get('RATELIMIT_USERCLAIM_PER_LICENSE', '1500')
        return f"userClaim report limit ({n}/60s) — claim reports are being dropped"
    if kind == 'claimer_events':
        n = os.environ.get('RATELIMIT_CLAIMER_EVENTS_PER_LICENSE', '1000')
        return f"claimer-management event limit ({n}/60s)"
    if kind == 'connection':
        return "connection limit (too many sessions/tabs)"
    return f"{kind} limit"


def notify_rate_limit(license_key, kind, telegram_id=0) -> None:
    """Best-effort throttled admin DM that `license_key` hit the `kind` rate limit.

    All shared-state work happens under _LOCK; the alert is SENT after the lock is
    released. Never raises, never blocks, never rejects anything.
    """
    try:
        if not _enabled() or not license_key:
            return
        now = time.time()
        key = (str(license_key), str(kind))
        cooldown = _cooldown()

        should_send = False
        with _LOCK:
            last = _TRACKER.get(key)
            if last is None or (now - last) >= cooldown:
                # Capacity: evict the LRU head (O(1)) before inserting a new key.
                if key not in _TRACKER and len(_TRACKER) >= _MAX_KEYS:
                    _TRACKER.popitem(last=False)
                _TRACKER[key] = now          # atomic check-and-set under the lock
                _TRACKER.move_to_end(key)    # O(1) LRU touch (MRU end)
                should_send = True
            else:
                _TRACKER.move_to_end(key)    # touch so it isn't evicted while hot
        if not should_send:
            return

        # ---- Everything below runs AFTER the lock is released ----
        admin = (os.environ.get('ADMIN_TELEGRAM_ID') or '').strip()
        if not admin or not admin.isdigit():
            logger.warning("rate_limit_notify: ADMIN_TELEGRAM_ID not set; alert skipped")
            return
        from app.license_manager import redact_key
        redacted = redact_key(str(license_key))
        tid_line = f" (tid {int(telegram_id)})" if telegram_id else ""
        msg = (
            "🚦 <b>Rate limit hit</b>\n"
            f"License <code>{redacted}</code>{tid_line}\n"
            f"{_kind_desc(str(kind))}"
        )
        from app.utils.telegram import notify_bot_service   # detached curl, fire-and-forget
        notify_bot_service(int(admin), msg)
        logger.warning(f"rate_limit_notify: ALERT fired kind={kind} license={redacted}")
    except Exception as e:
        logger.warning(f"rate_limit_notify: {e}")
