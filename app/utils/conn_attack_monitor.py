"""
Authenticated per-license connection-attack monitor (V1).

Detects one license generating an abnormal number of AUTHENTICATED /_tmc
connection attempts (valid JWT, license_id known) within a rolling 60-second
window, and fires a single admin-only Telegram alert (debounced by a cooldown).

Design mirrors app/utils/attack_monitor.py (the proven global flood monitor):
fixed-memory ring + detached fire-and-forget alert, with EVERY path guarded so
monitoring can NEVER break, delay, or reject a connection.

Hot-path guarantees (per attempt):
  * O(1) bucket update + O(60) fixed-window sum — no per-attempt history, no
    structure that scales with client/attack size.
  * Bounded memory: at most _MAX_LICENSES tracked licenses (LRU-evicted in O(1),
    never a scan), each with a fixed 60-slot ring and an IP set capped at
    _MAX_IPS. Tracker keys are valid signed-JWT license IDs — not attacker
    forgeable — and are hard-capped regardless.
  * No DB, no network, no sleep, no file I/O, no blocking queue, no Popen, and
    no eventlet-yielding call while the lock is held. The only outbound I/O is
    the rare alert, delivered via the existing detached-curl notify_bot_service
    AFTER the lock is released.

Delivery requires ADMIN_TELEGRAM_ID (same as the broadcast/flood alerts).
Tuning env (all optional, invalid values fall back to the default, never crash):
    CONN_ATTACK_THRESHOLD       attempts/60s that trip an alert (default 100)
    CONN_ATTACK_COOLDOWN_SEC    min seconds between alerts per license (default 300)
    CONN_ATTACK_MAX_LICENSES    hard cap on tracked licenses (default 8192)
"""
import os
import time
import logging
import threading
from collections import OrderedDict

from app.license_manager import redact_key

logger = logging.getLogger(__name__)


def _int_env(name: str, default: int) -> int:
    """Read a POSITIVE int env var; fall back to `default` on missing, invalid/
    non-integer, zero, or negative values (never raises). `default` must be a
    positive int. Centralizes validation so callers need no extra clamping."""
    try:
        v = int(os.environ.get(name, str(default)))
    except (TypeError, ValueError):
        return default
    return v if v > 0 else default


_WINDOW = 60                                              # fixed = ring size (seconds)
_THRESHOLD = _int_env("CONN_ATTACK_THRESHOLD", 100)       # validated positive-or-default
_COOLDOWN = _int_env("CONN_ATTACK_COOLDOWN_SEC", 300)
_MAX_LICENSES = _int_env("CONN_ATTACK_MAX_LICENSES", 8192)
_MAX_IPS = 16                                             # fixed cap per license
_MAX_IP_LEN = 45                                          # IPv6 max textual length
_MAX_ENDPOINT_LEN = 16

# license_key -> entry, used as a bounded LRU (move_to_end on touch, popitem head on evict)
_TRACKER: "OrderedDict[str, dict]" = OrderedDict()
_LOCK = threading.Lock()


def _new_entry(now: float) -> dict:
    return {
        "counts": [0] * _WINDOW,     # per-second bucket counts
        "epochs": [-1] * _WINDOW,    # integer-second each bucket currently holds
        "ips": set(),                # distinct source IPs this activity period (capped)
        "first_seen": now,           # start of current activity PERIOD (not exact window start)
        "last_alert": 0.0,           # cooldown state
        "last_seen": now,            # last attempt time (TTL / LRU)
    }


def _fmt(ts: float) -> str:
    """Bounded, safe timestamp format (UTC). Pure/local — safe to build under lock."""
    try:
        return time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(ts))
    except Exception:
        return "?"


def record_connect_attempt(license_key: str, ip: str, endpoint: str) -> None:
    """Count one AUTHENTICATED connection attempt for `license_key`; fire an
    admin alert on the first rolling-60s threshold crossing (then cooldown).

    Best-effort and self-contained: never raises, never blocks, never rejects a
    connection. All shared-state work happens under _LOCK; the alert send happens
    AFTER the lock is released.
    """
    try:
        if not license_key:
            return
        now = time.time()
        sec = int(now)
        idx = sec % _WINDOW
        # Bound attacker-influenced strings before they are stored/logged.
        ip = (ip or "unknown")[:_MAX_IP_LEN]
        endpoint = (endpoint or "?")[:_MAX_ENDPOINT_LEN]

        alert = None
        with _LOCK:
            entry = _TRACKER.get(license_key)
            if entry is None:
                # Capacity: evict LRU head in O(1) (never a scan) before inserting.
                if len(_TRACKER) >= _MAX_LICENSES:
                    _TRACKER.popitem(last=False)
                entry = _new_entry(now)
                _TRACKER[license_key] = entry            # new key inserted at MRU end
            else:
                _TRACKER.move_to_end(license_key)        # O(1) LRU touch
                if now - entry["last_seen"] > _WINDOW:
                    # Idle beyond the window → start a NEW activity period so it
                    # can't inherit the previous period's IPs / "16+".
                    entry["first_seen"] = now
                    entry["ips"].clear()

            # Ring rotation (recycle a slot that still holds an older second).
            if entry["epochs"][idx] != sec:
                entry["epochs"][idx] = sec
                entry["counts"][idx] = 0
            entry["counts"][idx] += 1

            # Rolling total over buckets still inside the fixed window (O(60)).
            cutoff = sec - _WINDOW + 1
            total = 0
            counts = entry["counts"]
            epochs = entry["epochs"]
            for i in range(_WINDOW):
                if epochs[i] >= cutoff:
                    total += counts[i]

            # Capped distinct-IP set for this period.
            ips = entry["ips"]
            if len(ips) < _MAX_IPS:
                ips.add(ip)

            entry["last_seen"] = now

            # Incremental, bounded TTL cleanup: evict at most ONE stale front
            # (LRU/oldest) entry. O(1) peek + O(1) pop; never a full scan. The
            # current key was just moved/inserted to the MRU end, so it is never
            # the front and cannot be evicted here.
            fk, fe = next(iter(_TRACKER.items()))
            if fk != license_key and now - fe["last_seen"] > _WINDOW:
                _TRACKER.popitem(last=False)

            # Cooldown decision — set last_alert BEFORE releasing the lock and copy
            # every field the message needs, so delivery runs lock-free.
            if total >= _THRESHOLD and (now - entry["last_alert"]) >= _COOLDOWN:
                entry["last_alert"] = now
                ipn = len(ips)
                alert = {
                    "lic": redact_key(license_key),      # pure O(1) string op — safe under lock
                    "count": total,
                    "ips": f"{ipn}+" if ipn >= _MAX_IPS else str(ipn),
                    "since": entry["first_seen"],
                    "now": now,
                    "endpoint": endpoint,
                }
        # ── lock released ──
        if alert is not None:
            _fire_alert(alert)
    except Exception:
        # Monitoring must NEVER break connection handling.
        pass


def _fire_alert(a: dict) -> None:
    """Send the admin a detached, best-effort Telegram alert. Runs OUTSIDE _LOCK.
    notify_bot_service is fire-and-forget (detached curl, --max-time 5), so the
    worker never waits on Telegram; a failure here can never affect a connection."""
    try:
        admin = os.environ.get("ADMIN_TELEGRAM_ID", "").strip()
        if not admin:
            logger.warning("conn_attack: ADMIN_TELEGRAM_ID not set; alert skipped")
            return
        msg = (
            "🚨 <b>LICENSE CONNECTION ABUSE</b>\n\n"
            f"License <code>{a['lic']}</code>\n"
            f"~<b>{a['count']}</b> auth'd connects in the last {_WINDOW}s "
            f"(threshold <b>{_THRESHOLD}</b>)\n"
            f"Distinct IPs this period: <b>{a['ips']}</b> · endpoint: {a['endpoint']}\n"
            f"active since {_fmt(a['since'])} · detected {_fmt(a['now'])}"
        )
        # `since` = start of the current continuous activity PERIOD (resets after a
        # >60s idle gap), NOT the exact first event inside the rolling window; there
        # is no per-attempt history. `detected` is the authoritative alert time.
        from app.utils.telegram import notify_bot_service   # lazy, like attack_monitor
        notify_bot_service(int(admin), msg)
        logger.warning(f"conn_attack: ALERT license={a['lic']} count={a['count']}")
    except Exception as e:
        logger.warning(f"conn_attack: alert send failed: {e}")
