"""
Global request-rate monitor with a debounced Telegram alert.

Detects HTTP request floods (abuse that gets past Cloudflare, or a direct-to-
origin hit) and pings the admin. Built to be safe under load:

  * O(1) per request, FIXED memory — a 60-second ring buffer of counters, with
    NO per-IP map. This is deliberate: a per-IP structure could be ballooned by
    a distributed flood into a memory-exhaustion amplifier. The ring buffer
    cannot grow, so the monitor can never make an attack worse.
  * No locks, and no I/O on the hot path. The only I/O is the alert send, which
    is detached (fire-and-forget via the existing notify path) and DEBOUNCED, so
    an ongoing attack can raise at most one alert per cooldown window.
  * Best-effort: every path is guarded so monitoring can NEVER break a request.

Note: this is a *secondary* signal. Cloudflare's edge DDoS protection +
analytics is the primary defense and sees attacks before they reach the origin;
this only sees requests that actually arrive at the app.

Tuning (env vars, all optional — a bad value falls back to the default, it will
never crash startup):
    ATTACK_ALERT_GLOBAL_RPM    requests per 60s that trip an alert (default 12000)
    ATTACK_ALERT_COOLDOWN_SEC  minimum seconds between alerts (default 300)

Delivery requires ADMIN_TELEGRAM_ID (same as the broadcast alert).
"""
import os
import time
import logging

logger = logging.getLogger(__name__)


def _int_env(name: str, default: int) -> int:
    """Read an int env var; fall back to default on anything invalid (never raises)."""
    try:
        return int(os.environ.get(name, str(default)))
    except (TypeError, ValueError):
        return default


_WINDOW_SEC = 60
_GLOBAL_RPM = _int_env("ATTACK_ALERT_GLOBAL_RPM", 12000)
_COOLDOWN_SEC = _int_env("ATTACK_ALERT_COOLDOWN_SEC", 300)

# Ring buffer: one bucket per second of the window. Fixed size, never grows.
_counts = [0] * _WINDOW_SEC
_epochs = [-1] * _WINDOW_SEC   # which integer-second each bucket currently holds
_last_alert = 0.0


def record_request() -> None:
    """Count one request; alert if the rolling 60s total exceeds the threshold.

    O(1), fixed memory, no I/O except a debounced detached alert. Never raises —
    monitoring must not be able to break request handling.
    """
    global _last_alert
    try:
        now = time.time()
        sec = int(now)
        idx = sec % _WINDOW_SEC

        # Sliding window: if this slot still holds an older second, recycle it.
        if _epochs[idx] != sec:
            _epochs[idx] = sec
            _counts[idx] = 0
        _counts[idx] += 1

        # Rolling total over the buckets still inside the window.
        cutoff = sec - _WINDOW_SEC + 1
        total = 0
        for i in range(_WINDOW_SEC):
            if _epochs[i] >= cutoff:
                total += _counts[i]

        if total > _GLOBAL_RPM and (now - _last_alert) >= _COOLDOWN_SEC:
            _last_alert = now          # set BEFORE sending so concurrent reqs can't double-fire
            _fire_alert(total)
    except Exception:
        # Monitoring must never break request handling.
        pass


def _fire_alert(total: int) -> None:
    """Send the admin a detached, best-effort Telegram alert."""
    try:
        admin_id = os.environ.get("ADMIN_TELEGRAM_ID", "").strip()
        if not admin_id:
            logger.warning("attack_monitor: ADMIN_TELEGRAM_ID not set; alert skipped")
            return
        msg = (
            "🚨 <b>HIGH REQUEST VOLUME</b>\n\n"
            f"~<b>{total}</b> requests in the last {_WINDOW_SEC}s "
            f"(threshold <b>{_GLOBAL_RPM}</b>).\n"
            "Possible flood/attack — check Cloudflare analytics and origin load."
        )
        from app.utils.telegram import notify_bot_service
        notify_bot_service(int(admin_id), msg)
        logger.warning(f"attack_monitor: ALERT fired — {total} requests in {_WINDOW_SEC}s")
    except Exception as e:
        logger.warning(f"attack_monitor: alert send failed: {e}")
