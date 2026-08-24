"""
/_tmc namespace — license-authenticated Socket.IO transport for Telegram
bot drop/reload/connected workflows.

Isolated from /_v, /embed, /events, /ws/ingest. Uses per-license rooms.
Event names per tele.md §3:
  Server → client: fromTele, getBrowsers, connected, license_deleted,
                   license_key_changed, session_key
  Client → server: userClaim, sendBrowsers (both return ACK dict per §C)

Payloads are AES-128-GCM encrypted when Config.ENABLE_RSA_AUTH=true (§B).
"""
import base64
import logging
import os
import threading
import time
import uuid
from collections import OrderedDict, defaultdict, deque
from typing import Deque, Dict, List, Optional

from flask import request
from flask_socketio import ConnectionRefusedError, emit, join_room

from app import socketio
from app.config import Config
from app.license_manager import (
    add_session,
    can_admit,
    decrypt_payload,
    encrypt_broadcast,
    encrypt_payload,
    get_broadcast_key,
    get_session_by_sid,
    mark_session_bk_version,
    snapshot_global_delivery,
    snapshot_license_delivery,
    snapshot_username_delivery,
    wrap_broadcast_key_for_session,
    get_session_count,
    get_unique_username_count,
    get_username_connection_count,
    is_license_active,
    license_sids,
    pop_session_key,
    redact_key,
    redact_room,
    remove_session,
    revoke_license_sessions,
    rsa_encrypt_session_key,
    sids_for_claimer,
    store_session_key,
    try_global_connect,
    validate_jwt,
)
from app.utils.telegram import notify_bot_service, safe_html
from app.utils.conn_attack_monitor import record_connect_attempt

logger = logging.getLogger(__name__)

TMC_NS = '/_tmc'


# ---------------------------------------------------------------------------
# Collectors for /reload and /connected (sse-style aggregation over WS)
# Keyed by license_key; cleared each time the bot invokes the endpoint.
# ---------------------------------------------------------------------------
_reload_collectors: Dict[str, List[dict]] = defaultdict(list)
_browsers_collectors: Dict[str, List[dict]] = defaultdict(list)
# Admin remote-management ack collectors. Key: "telegram_id:claimer_id".
# Acks are buffered ONLY while a synchronous admin action is waiting on them
# (the ckey is "armed" by collect_claimer_result). Acks produced by the
# fire-and-forget auto-reconcile path have no waiter, so they must NOT be
# buffered here or the collector would grow unbounded.
_api_collectors: Dict[str, List[dict]] = defaultdict(list)
_api_armed: set = set()
_collectors_lock = threading.Lock()

# Set true while the worker is shutting down so teardown-time /_tmc disconnects
# never emit a storm of "claimer offline" notifications. Set from gunicorn's
# worker_int hook (SIGINT/SIGQUIT) and a chained SIGTERM handler; its ONLY
# reader is _notify_claimer_offline.
_shutting_down = False


def mark_shutting_down() -> None:
    global _shutting_down
    _shutting_down = True

# Per-code drop-claim aggregator. Key: (license_key, code).
# Value: list of result dicts. Bounded at 200 active codes to cap memory.
_claim_collectors: Dict[tuple, List[dict]] = {}
_claim_collectors_lock = threading.Lock()
_CLAIM_COLLECTORS_MAX = 200

# ---------------------------------------------------------------------------
# Broadcast response report (F-report): ~10s after a code is broadcast, send
# the admin ONE aggregate message — total responses + a per-category count
# (incl. unknown/"other"). Re-broadcast of the SAME code extends the window and
# reports only the NEW responses since the last report (delta). Fully in-memory
# and bounded. Keyed by the normalized code (aggregates one code across every
# license/username it was broadcast to).
#
# Concurrency: this store is guarded by _claim_collectors_lock (above) — the
# real-time fold (_fold_response_tally) runs INSIDE _add_drop_result's already
# held critical section, so there is NO new lock and NO extra lock acquisition
# per response. The window is opened BEFORE the broadcast fan-out
# (_schedule_or_extend) so a fast client's userClaim — folded in a separate
# greenlet while the per-SID fan-out loop is still running — always finds an
# open window. spawn_after / notify_bot_service / message building are all done
# OUTSIDE the lock.
# ---------------------------------------------------------------------------
_response_tallies: "OrderedDict[str, dict]" = OrderedDict()
_report_gen_seq = 0                  # monotonic per-window generation token
_REPORT_WINDOW = 10.0                # base reporting window (seconds)
_REPORT_HARD_MAX = 30.0              # a window can be extended at most this far
_REPORT_MAX_CODES = 50               # LRU cap on distinct tracked codes
_REPORT_TTL = 120.0                  # stale-entry TTL (seconds)
_REPORT_MAX_CATS = 20                # distinct categories/code before → 'other'
_REPORT_MAX_CLAIMED_USERS = 10000    # hard cap on a window's claimed-dedup set
_REPORT_LABEL_CHARS = set('abcdefghijklmnopqrstuvwxyz0123456789_')


def _room(license_key: str) -> str:
    return f"license:{license_key}"


def _now_ms() -> int:
    return int(time.time() * 1000)


# ---------------------------------------------------------------------------
# Per-message dedup for userClaim retry-once (F-02)
# Key: (license_key, code, username, minute). Lifetime: 90s rolling.
# ---------------------------------------------------------------------------
_claim_dedup: Dict[tuple, tuple] = {}   # key → (timestamp, was_claimed)
_claim_dedup_lock = threading.Lock()
_CLAIM_DEDUP_TTL = 90.0


# ---------------------------------------------------------------------------
# Bonus-code memory (F-bonus): remembers the most recent codes that were
# BROADCAST/SENT as bonus, so a claim for one of them is excluded from
# usd_claim_amount / the license total REGARDLESS of the claimer's script
# version. Old scripts never echo couponType back, so relying on the client
# alone leaks bonus amounts into the total; this backend-side record closes
# that. Bounded to the last _BONUS_CODES_MAX codes (LRU) with a TTL, so it
# can never grow unbounded. Bonus codes are infrequent (weekly/monthly/forum),
# so 50 covers a long horizon.
# ---------------------------------------------------------------------------
_bonus_codes: "OrderedDict[str, float]" = OrderedDict()
_bonus_codes_lock = threading.Lock()
_BONUS_CODES_MAX = 50
try:
    _BONUS_CODES_TTL = float(os.environ.get('BONUS_CODE_TTL_S', '21600'))  # 6h
    if _BONUS_CODES_TTL <= 0:
        _BONUS_CODES_TTL = 21600.0
except (TypeError, ValueError):
    _BONUS_CODES_TTL = 21600.0


def _mark_bonus_code(code: str) -> None:
    """Record a code as a bonus so later claims for it are excluded from the
    license total. Keeps only the most recent _BONUS_CODES_MAX entries."""
    c = (code or '').strip().lower()[:64]
    if not c:
        return
    now = time.time()
    with _bonus_codes_lock:
        _bonus_codes[c] = now
        _bonus_codes.move_to_end(c)
        # prune by TTL (cheap — only the front can be stale-oldest)
        while _bonus_codes:
            oldest_k = next(iter(_bonus_codes))
            if now - _bonus_codes[oldest_k] > _BONUS_CODES_TTL:
                _bonus_codes.pop(oldest_k, None)
            else:
                break
        # prune by count (LRU)
        while len(_bonus_codes) > _BONUS_CODES_MAX:
            _bonus_codes.popitem(last=False)


def _is_bonus_code(code: str) -> bool:
    """True if this code was recently sent as a bonus (within TTL)."""
    c = (code or '').strip().lower()[:64]
    if not c:
        return False
    now = time.time()
    with _bonus_codes_lock:
        ts = _bonus_codes.get(c)
        if ts is None:
            return False
        if now - ts > _BONUS_CODES_TTL:
            _bonus_codes.pop(c, None)
            return False
        return True


def _claim_already_recorded(key: tuple, is_claimed: bool = False) -> bool:
    now = time.time()
    with _claim_dedup_lock:
        # opportunistic prune
        if len(_claim_dedup) > 5000:
            drop = [k for k, v in _claim_dedup.items() if now - v[0] > _CLAIM_DEDUP_TTL]
            for k in drop:
                _claim_dedup.pop(k, None)
        if key in _claim_dedup:
            ts, prev_claimed = _claim_dedup[key]
            if now - ts < _CLAIM_DEDUP_TTL:
                # Allow upgrade: failed result → claimed result for same key
                if is_claimed and not prev_claimed:
                    _claim_dedup[key] = (now, True)
                    return False   # let the claimed=1 through
                return True        # true duplicate, block it
        _claim_dedup[key] = (now, is_claimed)
        return False


# ---------------------------------------------------------------------------
# Connect/disconnect notification debounce
# ---------------------------------------------------------------------------
# Suppresses notification noise from two normal scenarios:
#
#   1. Transient reconnects (network blip, NAT TTL, CF edge re-route): if the
#      user reconnects within RECONNECT_NOTIFY_GRACE_S, BOTH the disconnect
#      and the subsequent connect notifications are suppressed.
#
#   2. Multi-tab browsing: only the FIRST connect and the LAST disconnect for
#      a given (license, username) fire a Telegram message. Opening or closing
#      additional tabs of the same user is silent.
#
# State machine per (license_key, username):
#
#     [connected] --(last tab disconnects)--> [pending_disconnect]
#                                                 |          |
#                <--(reconnect within grace,      |          | grace expires:
#                    timer killed, no notify)-----+          | fire disconnect
#                                                            v notify
#                                                     [disconnected]
#                                                            |
#                                            (reconnect: fire connect notify)
#                                                            v
#                                                       [connected]
#
# Concurrency model:
#   * All state mutations are inside _notif_state_lock.
#   * Session counts come from active_sessions (held briefly under its own
#     lock); we look it up BEFORE acquiring _notif_state_lock so the locks
#     never nest, eliminating any deadlock risk.
#   * Delayed notify runs in an eventlet GreenThread (eventlet.spawn_after).
#     A reconnect within grace cancels the pending thread via .kill().
#   * This subsystem touches ONLY the Telegram notification path. The
#     broadcast (fromTele emit), claim recording, and license cache are
#     untouched — broadcast latency and claim correctness are unaffected.
# ---------------------------------------------------------------------------
RECONNECT_NOTIFY_GRACE_S = float(
    os.environ.get('RECONNECT_NOTIFY_GRACE_S', '10')
)
_NOTIF_STATE_MAX_KEYS = 10000  # bounded to avoid unbounded memory growth

_notif_state: Dict[tuple, dict] = {}
_notif_state_lock = threading.Lock()


def _count_user_sessions_for(license_key: str, username: str) -> int:
    """
    Count CURRENTLY active sessions for a given (license_key, username).
    Includes all tabs/devices of that user. Called outside _notif_state_lock
    so the two locks never nest.
    """
    from app.license_manager import active_sessions, _sessions_lock
    with _sessions_lock:
        bucket = active_sessions.get(license_key) or {}
        return sum(
            1 for sess in bucket.values()
            if sess.get('username') == username
        )


def _fmt_connect_msg(username: str, license_key: str) -> str:
    # Friendly + scan-friendly. Username FIRST so an operator reading a busy
    # channel can identify the user before parsing the rest. Sparkle emoji
    # adds personality without being over-the-top.
    return (
        f"🟢 <b>{safe_html(username)}</b> is online ✨\n"
        f"━━━━━━━━━━━━━━━\n"
        f"🔑 <code>{redact_key(license_key)}</code>\n"
        f"🕐 {_now_ist()}"
    )


def _fmt_disconnect_msg(username: str, license_key: str, duration_s: int) -> str:
    # Mirror layout of connect, with session length surfaced prominently
    # (operators usually care: "did they leave quickly or stick around?").
    # Wave emoji softens the "offline" tone — they're not gone, just away.
    return (
        f"🔴 <b>{safe_html(username)}</b> went offline 👋\n"
        f"━━━━━━━━━━━━━━━\n"
        f"⏱ Was online for <b>{_format_duration(duration_s)}</b>\n"
        f"🔑 <code>{redact_key(license_key)}</code>\n"
        f"🕐 {_now_ist()}"
    )


def _notif_prune_locked() -> None:
    """
    Opportunistic cleanup of stale entries in _notif_state. Removes entries
    in 'disconnected' state older than 1 hour. Must be called WITH the lock.
    """
    if len(_notif_state) < _NOTIF_STATE_MAX_KEYS:
        return
    now = time.time()
    stale = [
        k for k, v in _notif_state.items()
        if v.get('effective_state') == 'disconnected'
        and now - v.get('last_change_ts', 0) > 3600
    ]
    for k in stale:
        _notif_state.pop(k, None)


def _fire_delayed_disconnect_notify(
    license_key: str, username: str, telegram_id: int, duration_s: int,
    state_key: tuple,
) -> None:
    """
    Fires after RECONNECT_NOTIFY_GRACE_S if the user has NOT reconnected.
    A reconnect within grace cancels this greenlet via .kill() in the
    connect handler — so we re-check the state flag before sending.
    """
    with _notif_state_lock:
        st = _notif_state.get(state_key)
        if not st or st.get('effective_state') != 'pending_disconnect':
            # Reconnect arrived between schedule and fire — abort silently.
            return
        st['effective_state'] = 'disconnected'
        st['pending_handle'] = None
        st['last_change_ts'] = time.time()
    # Network call OUTSIDE the lock so a slow Telegram API doesn't block
    # any other connect/disconnect on this license.
    try:
        notify_bot_service(
            telegram_id, _fmt_disconnect_msg(username, license_key, duration_s)
        )
    except Exception:
        pass


def _handle_connect_notify(
    license_key: str, username: str, telegram_id: int,
) -> None:
    """
    Called from the /_tmc connect handler AFTER add_session(). Decides
    whether to fire the green USER CONNECTED Telegram message.

    Suppresses the notify when:
      * Multi-tab: this is NOT the user's first active session (other tab
        already connected).
      * Reconnect-within-grace: a pending_disconnect timer exists for this
        (license, username); we cancel it and stay silent.
    """
    # Compute session count BEFORE taking _notif_state_lock to keep lock
    # order strict: _sessions_lock (inside the count helper) is always
    # acquired BEFORE _notif_state_lock, never nested.
    session_count = _count_user_sessions_for(license_key, username)
    key = (license_key, username)
    should_notify = False

    with _notif_state_lock:
        st = _notif_state.get(key)

        if session_count > 1:
            # Multi-tab: another tab is already connected. Keep current state
            # (don't touch it — could still be in pending_disconnect if a
            # different tab is in the grace window).
            return

        # session_count == 1 — this connect made the user "present" again.
        if st and st.get('pending_handle') is not None:
            # Reconnect inside the grace window — cancel the delayed
            # disconnect and stay silent.
            try:
                st['pending_handle'].kill()
            except Exception:
                pass
            st['pending_handle'] = None
            st['effective_state'] = 'connected'
            st['last_change_ts'] = time.time()
            # Update telegram_id in case it changed (rotation).
            st['telegram_id'] = telegram_id
            return

        # First time this user becomes present OR a reconnect AFTER grace
        # window (state was already 'disconnected'). Either way, fire.
        _notif_state[key] = {
            'effective_state': 'connected',
            'pending_handle': None,
            'telegram_id': telegram_id,
            'last_change_ts': time.time(),
        }
        _notif_prune_locked()
        should_notify = True

    if should_notify:
        try:
            notify_bot_service(
                telegram_id, _fmt_connect_msg(username, license_key)
            )
        except Exception:
            pass


def _handle_disconnect_notify(
    license_key: str, username: str, telegram_id: int, duration_s: int,
) -> None:
    """
    Called from the /_tmc disconnect handler AFTER remove_session(). Schedules
    a delayed disconnect notify (cancellable by a reconnect within grace).

    Suppresses the notify when:
      * Multi-tab: another tab of the same user is still connected.
      * Delayed (default): scheduled, but cancelled by a reconnect within
        RECONNECT_NOTIFY_GRACE_S — the user sees nothing for transient blips.
    """
    session_count = _count_user_sessions_for(license_key, username)
    key = (license_key, username)

    with _notif_state_lock:
        if session_count > 0:
            # User still has other tabs open — no notification, no state
            # change. (The remaining tabs keep the user "present".)
            return

        st = _notif_state.get(key, {})
        # Defensive: cancel any previously scheduled pending notify. This
        # shouldn't normally exist (we'd be in 'connected' here), but a
        # rapid disconnect-connect-disconnect sequence might leave one.
        existing = st.get('pending_handle')
        if existing is not None:
            try: existing.kill()
            except Exception: pass

        import eventlet
        handle = eventlet.spawn_after(
            RECONNECT_NOTIFY_GRACE_S,
            _fire_delayed_disconnect_notify,
            license_key, username, telegram_id, duration_s, key,
        )
        _notif_state[key] = {
            'effective_state': 'pending_disconnect',
            'pending_handle': handle,
            'telegram_id': telegram_id,
            'last_change_ts': time.time(),
        }
        _notif_prune_locked()


# Per-license sliding-window rate limit for userClaim events.
_userclaim_buckets: Dict[str, Deque[float]] = {}
_userclaim_lock = threading.Lock()
_USERCLAIM_WINDOW = 60.0
# Per-license claim-report cap per 60s window. Sized for many-users-per-license:
# 100 users x 10 codes/min = 1000 reports at peak, so the default 1500 clears that
# with headroom for claim retries (F-02) and reconnect re-reports. Env-tunable; a
# bad/missing value falls back to the default and can never crash startup.
try:
    _USERCLAIM_MAX = int(os.environ.get('RATELIMIT_USERCLAIM_PER_LICENSE', '1500'))
    if _USERCLAIM_MAX < 1:
        _USERCLAIM_MAX = 1500
except (TypeError, ValueError):
    _USERCLAIM_MAX = 1500
_USERCLAIM_MAX_KEYS = 5000

# Per-license sliding-window rate limit for CLAIMER-MANAGEMENT events
# (claimerStatus + apiResult) — deliberately SEPARATE from the userClaim limiter
# above so remote-management chatter can never throttle real claim reports.
#
# WHAT IT COUNTS: every claimerStatus + apiResult the server accepts from all
# sessions sharing ONE license, within a 60s sliding window.
# HOW TO SIZE IT: a claimer emits ~1 claimerStatus per (re)connect, plus up to
# ~3 apiResult acks when its config differs from desired. Budget ~10 events per
# claimer per minute (covers a claimer stuck reconnecting a couple times/min
# while out-of-sync). So:  cap ≈ (number of userscripts) × 10.
# Default 1000 = ~100 userscripts on one admin telegram id, with headroom.
# Env-tunable via RATELIMIT_CLAIMER_EVENTS_PER_LICENSE; bad/missing → default.
_claimer_evt_buckets: Dict[str, Deque[float]] = {}
_claimer_evt_lock = threading.Lock()
_CLAIMER_EVT_WINDOW = 60.0
_CLAIMER_EVT_MAX_KEYS = 5000
try:
    _CLAIMER_EVT_MAX = int(os.environ.get('RATELIMIT_CLAIMER_EVENTS_PER_LICENSE', '1000'))
    if _CLAIMER_EVT_MAX < 1:
        _CLAIMER_EVT_MAX = 1000
except (TypeError, ValueError):
    _CLAIMER_EVT_MAX = 1000

# Per-username connection (tab) cap on a single license: at most N simultaneous
# connections for the SAME username on one license. <=0 disables the cap.
# Env-tunable; a bad/missing value falls back to the default.
try:
    _MAX_CONNS_PER_USERNAME = int(os.environ.get('MAX_CONNECTIONS_PER_USERNAME', '5'))
except (TypeError, ValueError):
    _MAX_CONNS_PER_USERNAME = 5

# Admin-only override of the per-username cap. API-token claimers often connect
# under one placeholder username, so the normal per-user tab cap would reject
# them. This higher cap applies ONLY to connections whose telegram_id is in
# ADMIN_TELEGRAM_ID (comma/space separated). Env-tunable; set it to 0 for an
# unlimited admin cap. A bad/missing value falls back to the default.
try:
    _MAX_CONNS_PER_USERNAME_ADMIN = int(
        os.environ.get('MAX_CONNECTIONS_PER_USERNAME_ADMIN', '100'))
except (TypeError, ValueError):
    _MAX_CONNS_PER_USERNAME_ADMIN = 100

_ADMIN_TELEGRAM_IDS = set()
for _p in (os.environ.get('ADMIN_TELEGRAM_ID') or '').replace(',', ' ').split():
    if _p.isdigit():
        _ADMIN_TELEGRAM_IDS.add(int(_p))


def _userclaim_rate_ok(license_key: str) -> bool:
    if not license_key:
        return True
    now = time.time()
    cutoff = now - _USERCLAIM_WINDOW
    with _userclaim_lock:
        if len(_userclaim_buckets) > _USERCLAIM_MAX_KEYS:
            drop = [k for k, dq in _userclaim_buckets.items()
                    if not dq or dq[-1] < cutoff]
            for k in drop:
                _userclaim_buckets.pop(k, None)
        dq = _userclaim_buckets.get(license_key)
        if dq is None:
            dq = deque()
            _userclaim_buckets[license_key] = dq
        while dq and dq[0] < cutoff:
            dq.popleft()
        if len(dq) >= _USERCLAIM_MAX:
            return False
        dq.append(now)
        return True


def _claimer_evt_rate_ok(license_key: str) -> bool:
    """Sliding-window limiter for claimerStatus/apiResult. Separate buckets from
    _userclaim_rate_ok so management traffic never consumes the claim budget."""
    if not license_key:
        return True
    now = time.time()
    cutoff = now - _CLAIMER_EVT_WINDOW
    with _claimer_evt_lock:
        if len(_claimer_evt_buckets) > _CLAIMER_EVT_MAX_KEYS:
            drop = [k for k, dq in _claimer_evt_buckets.items()
                    if not dq or dq[-1] < cutoff]
            for k in drop:
                _claimer_evt_buckets.pop(k, None)
        dq = _claimer_evt_buckets.get(license_key)
        if dq is None:
            dq = deque()
            _claimer_evt_buckets[license_key] = dq
        while dq and dq[0] < cutoff:
            dq.popleft()
        if len(dq) >= _CLAIMER_EVT_MAX:
            return False
        dq.append(now)
        return True


# ---------------------------------------------------------------------------
# Origin gate (matches /_v style)
# ---------------------------------------------------------------------------

def _origin_ok() -> bool:
    from urllib.parse import urlparse
    from app.routes.sse_routes import is_origin_allowed
    origin = request.headers.get('Origin', '')
    referer = request.headers.get('Referer', '') or request.environ.get('HTTP_REFERER', '')
    if origin and not is_origin_allowed(origin):
        return False
    if not origin:
        # Require referer to live on an exact allowed host (no prefix match)
        allowed_refer = False
        if referer:
            try:
                host = urlparse(referer).hostname or ''
                allowed_refer = host in {'kciade.online', 'www.kciade.online'}
            except Exception:
                allowed_refer = False
        if not allowed_refer:
            host = request.host or ''
            if not (host.startswith('localhost') or host.startswith('127.0.0.1')):
                return False
    return True


# ---------------------------------------------------------------------------
# /_tmc namespace handlers
# ---------------------------------------------------------------------------

@socketio.on('connect', namespace=TMC_NS)
def tmc_connect():
    # Mode-gate-safe — /_tmc is NEVER gated by SSE_BROADCAST_ENABLED.

    if not _origin_ok():
        raise ConnectionRefusedError({'code': 403, 'message': 'Bad origin'})

    if not try_global_connect():
        raise ConnectionRefusedError({'code': 503, 'message': 'Server busy'})

    token = (request.args.get('token') or '').strip()
    user = (request.args.get('user') or '').strip()
    if not token:
        raise ConnectionRefusedError({'code': 401, 'message': 'Token required'})
    if not user:
        raise ConnectionRefusedError({'code': 400, 'message': 'user required'})

    payload = validate_jwt(token)
    if not payload:
        raise ConnectionRefusedError({'code': 401, 'message': 'Invalid or expired token'})

    license_key = payload.get('license_id')

    # Observational only: count this AUTHENTICATED attempt (valid JWT, license
    # known) for per-license connection-abuse detection, BEFORE any admission
    # rejection so inactive/banned/limit rejects are still counted. Best-effort
    # and fully wrapped — it can never delay or reject a connection.
    if license_key:
        try:
            record_connect_attempt(
                license_key,
                request.headers.get('CF-Connecting-IP') or request.remote_addr or 'unknown',
                'tmc',
            )
        except Exception:
            pass

    if not license_key or not is_license_active(license_key):
        raise ConnectionRefusedError({'code': 403, 'message': 'License not active'})

    from app.license_manager import get_license_cache_entry
    entry = get_license_cache_entry(license_key) or {}
    if entry.get('banned'):
        raise ConnectionRefusedError({'code': 403, 'message': 'License banned'})
    max_usernames = int(entry.get('maximum_usernames', Config.MAX_CONNECTIONS_PER_LICENSE))
    if max_usernames <= 0:
        raise ConnectionRefusedError({'code': 429, 'message': 'No slots available'})

    # 'unknown' is a temporary PENDING identity (a tab that connected before its
    # Stake username resolved). It is a non-accounting placeholder here: the real
    # license/username limits are enforced atomically when it updates to a real
    # username via tmc_update_identity (and the reaper cleans up stuck 'unknown's).
    if user != 'unknown' and not can_admit(license_key, user, max_usernames):
        try:
            from app.utils.rate_limit_notify import notify_rate_limit
            notify_rate_limit(license_key, 'connection',
                              int(entry.get('telegram_id') or payload.get('tid') or 0))
        except Exception:
            pass
        raise ConnectionRefusedError({
            'code': 429,
            'reason': 'license_user_limit',
            'limit': max_usernames,
            'message': 'License user limit reached',
        })

    # Per-username connection (tab) cap: at most N live connections for the
    # SAME username on this license. The message deliberately avoids the words
    # older clients treat as terminal (ban / inactive / not found), so old
    # scripts fall through to their generic "Reconnecting" path while new
    # scripts read `reason`/`limit` to show a precise message.
    # Admin (ADMIN_TELEGRAM_ID) gets the higher/unlimited per-username cap; every
    # other user keeps the normal cap unchanged.
    _conn_tid = int(entry.get('telegram_id') or payload.get('tid') or 0)
    _uname_cap = (_MAX_CONNS_PER_USERNAME_ADMIN
                  if (_conn_tid and _conn_tid in _ADMIN_TELEGRAM_IDS)
                  else _MAX_CONNS_PER_USERNAME)
    if (user != 'unknown'
            and _uname_cap > 0
            and get_username_connection_count(license_key, user)
            >= _uname_cap):
        try:
            from app.utils.rate_limit_notify import notify_rate_limit
            notify_rate_limit(license_key, 'connection', _conn_tid)
        except Exception:
            pass
        raise ConnectionRefusedError({
            'code': 429,
            'reason': 'username_conn_limit',
            'limit': _uname_cap,
            'message': 'Per-user tab limit reached',
        })

    telegram_id = int(entry.get('telegram_id') or payload.get('tid') or 0)

    # §B: RSA handshake when ENABLE_RSA_AUTH=true
    encrypted_session_key_b64 = None
    if Config.ENABLE_RSA_AUTH:
        rsa_pub = request.args.get('rsa_pub') or ''
        if not rsa_pub:
            raise ConnectionRefusedError({'code': 400, 'message': 'rsa_pub required'})
        aes_key = os.urandom(16)
        try:
            encrypted_session_key_b64 = rsa_encrypt_session_key(rsa_pub, aes_key)
        except Exception:
            raise ConnectionRefusedError({'code': 400, 'message': 'Invalid rsa_pub'})
        store_session_key(request.sid, aes_key)

    # Capture the real client IP (Cloudflare-aware, mirrors the SSE connect log)
    # and store it on the session so /licenselivecount can show it to the admin.
    client_ip = request.headers.get('CF-Connecting-IP') or request.remote_addr or 'unknown'
    client_ver = (request.args.get('ver') or '').strip()[:32]
    # Admin remote-management identity (sanitized; bound to this session).
    claimer_id = (request.args.get('cid') or '').strip()[:64] or None
    claimer_name = (request.args.get('cname') or '').strip()[:64] or None
    logger.info(f"TMC_CONNECT | ip={client_ip} | ver={client_ver or '?'} | user={user or 'MISSING'}")
    add_session(license_key, request.sid, user, telegram_id, payload.get('jti', ''),
                ip=client_ip, version=client_ver, claimer_id=claimer_id, claimer_name=claimer_name)
    join_room(_room(license_key), namespace=TMC_NS)
    # Register/refresh the claimer row + mark online (cache-only; batched flush).
    # Setting online here (not just on claimerStatus) makes the flag correct even
    # before the first status arrives, and — combined with the recompute on
    # disconnect — keeps it right across reconnects and multi-tab churn.
    if claimer_id:
        try:
            from app import claimer_manager
            claimer_manager.ensure_claimer(telegram_id, claimer_id, claimer_name)
            claimer_manager.set_online(telegram_id, claimer_id, True)
        except Exception:
            pass

    if encrypted_session_key_b64:
        # session_key is NEVER encrypted with the session AES key itself —
        # it bootstraps the AES key, so it goes RSA-encrypted only.
        emit('session_key', {'key': encrypted_session_key_b64})

    emit('connected', _wrap({
        'type': 'connected',
        'license': license_key,
        'telegram_id': telegram_id,
        'timestamp': _now_ms(),
    }, request.sid))

    # Fire connect notification through the debounce layer:
    # suppresses notify on multi-tab additional connects and on reconnects
    # within RECONNECT_NOTIFY_GRACE_S of a recent disconnect.
    try:
        _handle_connect_notify(license_key, user, telegram_id)
    except Exception:
        pass

    logger.info(
        f"TMC | CONNECT sid={request.sid[:12]} user={safe_html(user)[:32]} "
        f"room={redact_room(_room(license_key))}"
    )


@socketio.on('disconnect', namespace=TMC_NS)
def tmc_disconnect():
    sid = request.sid
    rec = remove_session(sid)
    pop_session_key(sid)
    if not rec:
        return

    license_key = rec.get('license_key')
    username = rec.get('username') or ''
    telegram_id = int(rec.get('telegram_id') or 0)
    connected_at = float(rec.get('connected_at') or time.time())
    duration_s = max(0, int(time.time() - connected_at))

    # Recompute the claimer's online flag from the live sessions AFTER this sid
    # was removed (remove_session ran above). This is order-independent: if the
    # same claimer_id still has any live sid — another tab, or the new sid of a
    # reconnect whose old disconnect is firing late — it stays online. Only when
    # no live sid remains does it go offline. (Purely the display flag; routing
    # always reads active_sessions directly.)
    if rec.get('claimer_id'):
        try:
            from app import claimer_manager
            still_live = bool(sids_for_claimer(rec['claimer_id'], telegram_id))
            prev_online = claimer_manager.set_online(
                telegram_id, rec['claimer_id'], still_live)
            # Notify only on a genuine online->offline edge: the claimer was
            # online and now has no live sid left. Duplicate disconnects
            # (prev False) and other still-connected tabs (still_live True)
            # are silent.
            if prev_online is True and not still_live:
                _notify_claimer_offline(telegram_id, rec['claimer_id'])
        except Exception:
            pass

    # Fire disconnect notification through the debounce layer:
    # suppresses notify when other tabs of the same user remain connected,
    # OR when the user reconnects within RECONNECT_NOTIFY_GRACE_S.
    try:
        _handle_disconnect_notify(license_key, username, telegram_id, duration_s)
    except Exception:
        pass

    logger.info(
        f"TMC | DISCONNECT sid={sid[:12]} user={safe_html(username)[:32]} "
        f"room={redact_room(_room(license_key))} duration={duration_s}s"
    )


@socketio.on('userClaim', namespace=TMC_NS)
def on_user_claim(data):
    """
    Receives claim result from Tampermonkey; bumps theclaimers_count on
    real success, aggregates per-code drop results for a single
    consolidated Telegram message, and returns ACK dict.
    """
    sid = request.sid
    session_info = get_session_by_sid(sid)
    if not session_info:
        return {'ok': False, 'error': 'not_authenticated'}

    license_key = session_info['license_key']
    telegram_id = int(session_info.get('telegram_id') or 0)

    # Per-license burst rate limit
    if not _userclaim_rate_ok(license_key):
        try:
            from app.utils.rate_limit_notify import notify_rate_limit
            notify_rate_limit(license_key, 'userclaim', telegram_id)
        except Exception:
            pass
        return {'ok': False, 'error': 'rate_limited'}

    # Decrypt if RSA mode
    if Config.ENABLE_RSA_AUTH:
        aes_key = _get_session_aes(sid)
        if not aes_key:
            return {'ok': False, 'error': 'no_session_key'}
        try:
            data = decrypt_payload(aes_key, data)
        except Exception:
            logger.warning(f"userClaim: decrypt failed sid={sid[:12]}")
            return {'ok': False, 'error': 'decrypt_failed'}

    if not isinstance(data, dict):
        return {'ok': False, 'error': 'bad_payload'}

    task_type = (data.get('type') or 'drop').lower()
    if task_type not in ('drop', 'reload'):
        return {'ok': False, 'error': 'bad_task'}

    code = (data.get('code') or '').strip()[:64]
    # Bonus claims (weekly/monthly/forum) are excluded from usd_claim_amount and
    # /count. A bonus is detected EITHER from the backend's own record of codes
    # it broadcast as bonus (works for OLD scripts that don't echo couponType)
    # OR from the client's couponType (new scripts). Either source is enough.
    is_bonus_claim = (
        _is_bonus_code(code)
        or (data.get('couponType') or 'drop').strip().lower() == 'bonus'
    )

    results = data.get('result') or []

    if results and isinstance(results, list):
        r = results[0] if isinstance(results[0], dict) else {}
        username = (r.get('username') or session_info.get('username') or 'unknown').strip()[:64]
        currency = (r.get('currency') or 'usdt').strip().lower()[:10]
        claimed_int = 1 if r.get('claimed') in (1, '1', True) else 0
        claimed = claimed_int == 1
        reload_avail = bool(r.get('reloadAvailable'))
        time_left = int(r.get('timeLeft') or 0)
        amount = r.get('amount')
        error_code = (r.get('error') or '').strip()[:32] if not claimed else ''
    else:
        r = {}
        username = session_info.get('username', 'unknown')[:64]
        currency = 'usdt'
        claimed = False
        claimed_int = 0
        reload_avail = False
        time_left = 0
        amount = None
        error_code = 'no_result'

    # Receipt log — EVERY received userClaim is printed here, BEFORE the dedup
    # check below, so re-broadcasts of the same code (each sent as its own report by
    # the client) are all visible in the logs. Logging only: it changes no dedup,
    # persistence, notification, ACK, or timing behavior.
    try:
        logger.info(
            f"USERCLAIM recv | lic={redact_key(license_key)} user={username} "
            f"code={str(code)[:32]} claimed={claimed} cur={currency} type={task_type}"
        )
    except Exception:
        pass

    # Server-side dedup — extended with currency so drop+reload of the same
    # code under the same username don't collide.
    #
    # IMPORTANT: for DROP claims this gates ONLY the Telegram notification and
    # the LICENSE_ACTIVE log — NOT the amount recording. Amount recording has
    # its own per-(username,code) idempotency (inside _record_claim_amount),
    # so a corrected amount on a follow-up userClaim (e.g. after the verify
    # query resolves and supplies bonusValue) is still credited even if the
    # first userClaim already fired the notification. Previously the dedup
    # marked the tuple on the first claim regardless of amount, which made a
    # null-amount first claim permanently block a later valid-amount one —
    # the root cause of "claimed but usd_claim_amount not updated".
    dedup_key = (license_key, code, username, task_type, currency)
    notification_dup = _claim_already_recorded(dedup_key, is_claimed=claimed)

    if task_type == 'drop':
        if not notification_dup:
            _persist_drop_claim(license_key, username, code, currency, claimed)
            _add_drop_result(license_key, telegram_id, code, {
                'username': username,
                'currency': currency,
                'claimed': claimed,
                'amount': amount,
                'reloadAvailable': reload_avail,
                'timeLeft': time_left,
                'error': error_code,
            })

        # Amount recording runs INDEPENDENTLY of the notification dedup.
        # _record_claim_amount is idempotent per (username, code) and only
        # consumes its idempotency slot when a REAL amount is queued, so a
        # null-amount first claim does not block a later valid one.
        amount_status = 'skipped'
        if claimed and not is_bonus_claim:
            amount_status = _record_claim_amount(
                license_key, username, code, currency, amount, telegram_id,
            )

        # ACK carries the recording outcome so the client can (optionally)
        # resend the amount if it wasn't recorded (e.g. it had no amount yet).
        return {
            'ok': True,
            'received': True,
            'dedup': notification_dup,
            'amount_recorded': amount_status in ('recorded', 'duplicate'),
            'amount_status': amount_status,
        }

    elif task_type == 'reload':
        # A reload STATUS check (claimed=0) is a fresh query every time /reload
        # runs, and its dedup_key is constant (code is the literal 'RELOAD'), so
        # the 90s claim-dedup would suppress every repeat within the window —
        # that is the "first reply then no response" bug. The collector must
        # ALWAYS receive the reload status, so it is NOT dedup-gated here.
        _add_reload_response(license_key, {
            'username': username,
            'reloadAvailable': reload_avail,
            'timeLeft': time_left,
            'claimed': claimed_int,
        })
        # Only the "reload claimed" push (claimed=1) stays dedup-gated, to avoid
        # duplicate Telegram messages if auto-reload reports the same claim twice.
        if claimed and not notification_dup:
            _notify_reload_claimed(telegram_id, username, amount, currency)
        return {'ok': True, 'received': True, 'dedup': notification_dup}

    return {'ok': True, 'received': True}


@socketio.on('accountDeactivated', namespace=TMC_NS)
def on_account_deactivated(data):
    """Tampermonkey reports that the operator's Stake API token stopped resolving
    (key deactivated / session expired) — the 5-min recheck flipped the account
    from verified to invalid. Forward one engaging 'disconnected' message to the
    user via the bot. Deduped so reconnects / double-emits cannot spam."""
    sid = request.sid
    session_info = get_session_by_sid(sid)
    if not session_info:
        return {'ok': False, 'error': 'not_authenticated'}

    license_key = session_info['license_key']
    telegram_id = int(session_info.get('telegram_id') or 0)

    # Decrypt if RSA mode
    if Config.ENABLE_RSA_AUTH:
        aes_key = _get_session_aes(sid)
        if not aes_key:
            return {'ok': False, 'error': 'no_session_key'}
        try:
            data = decrypt_payload(aes_key, data)
        except Exception:
            logger.warning(f"accountDeactivated: decrypt failed sid={sid[:12]}")
            return {'ok': False, 'error': 'decrypt_failed'}

    if not isinstance(data, dict):
        return {'ok': False, 'error': 'bad_payload'}

    username = (data.get('username') or session_info.get('username') or 'your account').strip()[:64]

    # One alert per deactivation event (the client one-shot already guards; this
    # is the server-side backstop against double-emits / rapid reconnects).
    if _claim_already_recorded((license_key, 'ACCOUNT_DEACTIVATED', username, 'deact', '')):
        return {'ok': True, 'received': True, 'dedup': True}

    _notify_account_deactivated(telegram_id, username)
    return {'ok': True, 'received': True}


@socketio.on('ping', namespace=TMC_NS)
def on_ping(data=None):
    """Application-level heartbeat — client expects a 'pong' within 10s."""
    if not get_session_by_sid(request.sid):
        return {'ok': False}
    try:
        emit('pong', {'t': _now_ms()})
    except Exception:
        pass
    return {'ok': True}


@socketio.on('sendBrowsers', namespace=TMC_NS)
def on_send_browsers(data):
    sid = request.sid
    session_info = get_session_by_sid(sid)
    if not session_info:
        return {'ok': False, 'error': 'not_authenticated'}

    if Config.ENABLE_RSA_AUTH:
        aes_key = _get_session_aes(sid)
        if not aes_key:
            return {'ok': False, 'error': 'no_session_key'}
        try:
            data = decrypt_payload(aes_key, data)
        except Exception:
            return {'ok': False, 'error': 'decrypt_failed'}

    if not isinstance(data, dict):
        return {'ok': False, 'error': 'bad_payload'}

    _add_browsers_response(session_info['license_key'], data)
    return {'ok': True, 'received': True}


@socketio.on('tmc_update_identity', namespace=TMC_NS)
def on_update_identity(data):
    """Client reports its resolved Stake username; relabel THIS session's username
    in place (same SID, no reconnect) after re-running the same license/username
    validation a fresh connect does. Session-bound: only the caller's own sid is
    ever touched. Returns {ok, username} or {ok:false, error}."""
    sid = request.sid
    session_info = get_session_by_sid(sid)
    if not session_info:
        return {'ok': False, 'error': 'not_authenticated'}
    if not _claimer_evt_rate_ok(session_info['license_key']):
        return {'ok': False, 'error': 'rate_limited'}
    data, err = _decrypt_if_rsa(sid, data)
    if err:
        return {'ok': False, 'error': err}
    if not isinstance(data, dict):
        return {'ok': False, 'error': 'bad_payload'}

    license_key = session_info['license_key']
    # Same fresh-connect gates: license still active + not banned.
    if not is_license_active(license_key):
        return {'ok': False, 'error': 'license_inactive'}
    from app.license_manager import (get_license_cache_entry,
                                     try_update_session_username)
    entry = get_license_cache_entry(license_key) or {}
    if entry.get('banned'):
        return {'ok': False, 'error': 'license_banned'}

    new_username = (str(data.get('username') or '')).strip()[:64]
    if not new_username or new_username == 'unknown':
        return {'ok': False, 'error': 'bad_username'}

    max_usernames = int(entry.get('maximum_usernames', Config.MAX_CONNECTIONS_PER_LICENSE))
    telegram_id = int(session_info.get('telegram_id') or 0)
    uname_cap = (_MAX_CONNS_PER_USERNAME_ADMIN
                 if (telegram_id and telegram_id in _ADMIN_TELEGRAM_IDS)
                 else _MAX_CONNS_PER_USERNAME)

    ok, reason = try_update_session_username(
        sid, new_username, max_usernames, uname_cap,
        _ADMIN_TELEGRAM_IDS, telegram_id)
    if ok:
        return {'ok': True, 'username': new_username}
    return {'ok': False, 'error': reason or 'rejected'}


# ---------------------------------------------------------------------------
# Shared broadcast key (BK) handshake — client-pull + ack (see plan §2)
#
# The three handshake event names are deliberately OPAQUE on the wire (Network-tab
# hiding); the semantic mapping is kept here for maintenance. They ONLY appear when
# ENABLE_RSA_AUTH is on, and old userscripts (pre-BK) never emit/listen for them, so
# renaming them cannot affect RSA-off traffic or old clients. The client must use the
# SAME literals — keep both sides in sync.
#   _EV_BK_REQUEST : client -> server  "give me the broadcast key"
#   _EV_BK_DELIVER : server -> client  "here is BK, wrapped in your per-conn key"
#   _EV_BK_ACK     : client -> server  "BK stored — mark me BK-capable"
# ---------------------------------------------------------------------------
_EV_BK_REQUEST = 'm1'
_EV_BK_DELIVER = 'm2'
_EV_BK_ACK = 'm3'


@socketio.on(_EV_BK_REQUEST, namespace=TMC_NS)
def on_request_broadcast_key(data=None):
    """Client asks for BK after its per-connection key is ready. Reply with BK
    wrapped in that per-connection key. bk_ver is NOT set yet — that happens on ack,
    so a session is never marked BK-capable before the client provably holds BK."""
    if not Config.ENABLE_RSA_AUTH:
        return
    sid = request.sid
    if not get_session_by_sid(sid):
        return
    env = wrap_broadcast_key_for_session(sid)
    if env is not None:
        emit(_EV_BK_DELIVER, env)


@socketio.on(_EV_BK_ACK, namespace=TMC_NS)
def on_broadcast_key_ack(data=None):
    """Client confirms it stored BK version v. This is the SINGLE promotion action:
    set `bk_ver = v` on the session (the only delivery signal). Because the client
    stored BK before sending this ack, any future BK emit (bk_ver set) reaches a
    client that provably holds BK. Only promote if v matches the current version;
    a stale ack (e.g. BK rotated in between) re-sends the current BK instead."""
    if not Config.ENABLE_RSA_AUTH:
        return
    sid = request.sid
    if not get_session_by_sid(sid):
        return
    _, cur_ver = get_broadcast_key()
    try:
        acked = int((data or {}).get('v'))
    except (TypeError, ValueError):
        acked = None
    if acked != cur_ver:
        # Stale/mismatched version — don't promote; hand the client the current BK.
        env = wrap_broadcast_key_for_session(sid)
        if env is not None:
            emit(_EV_BK_DELIVER, env)
        return
    mark_session_bk_version(sid, cur_ver)


# ---------------------------------------------------------------------------
# Outbound helpers (used by /api/xr9k/lic/* internal routes)
# ---------------------------------------------------------------------------

def emit_drop_to_license(license_key: str, code: str, coupon_type: str = 'drop') -> int:
    """
    Emit 'fromTele' (task=drop) to the license room.

    coupon_type: 'drop' (default) for normal drop codes, or 'bonus' for
    weekly/monthly/forum bonus codes. Forwarded to the userscript as
    `couponType` so it can pick the correct claim path (ClaimConditionBonusCode
    vs ClaimBonusCode). Only 'bonus' is treated specially; any other value is
    normalized to 'drop' to keep the contract strict.

    Hybrid fanout:
      RSA off → one room-level emit (Socket.IO engine handles the fanout to
                every SID in the license room — O(1) at the application layer)
      RSA on  → per-SID encrypted loop (each SID needs its own AES envelope)
    Returns the count of SIDs the message was emitted to (best-effort).
    """
    room = _room(license_key)
    sids = license_sids(license_key)
    if not sids:
        return 0

    _ctype = 'bonus' if str(coupon_type).strip().lower() == 'bonus' else 'drop'
    if _ctype == 'bonus':
        # Remember this code as a bonus so claims for it are excluded from the
        # license total even from old scripts that don't echo couponType back.
        _mark_bonus_code(code)
    payload = {
        'task': 'drop',
        'code': code,
        'license': license_key,
        'source': 'telegram',
        'couponType': _ctype,
        'timestamp': _now_ms(),
    }

    if not Config.ENABLE_RSA_AUTH:
        try:
            socketio.emit('fromTele', payload, room=room, namespace=TMC_NS)
            delivered = len(sids)
        except Exception as exc:
            logger.warning(f"emit_drop_to_license room emit failed: {exc}")
            delivered = 0
        logger.info(
            f"TMC | DROP code={code[:32]} room={redact_room(room)} "
            f"delivered={delivered} mode=room"
        )
        return delivered

    # RSA on: ONE atomic snapshot of (sid, bk_ver); encrypt ONCE; one emit per sid,
    # choosing the shared BK envelope (bk_ver set) or a per-connection wrap (legacy).
    # Single delivery signal (bk_ver), read once per sid -> exactly-once, decryptable.
    #
    # fanout_ms below = the worker time from the first emit to the last (the O(N)
    # per-SID cost). It is the SERVER-side spread between the first and last client's
    # enqueue — NOT the clients' true received times (that needs per-client network
    # latency, measurable only client-side).
    _fan_t0 = time.monotonic()
    env = encrypt_broadcast(payload)
    rows = snapshot_license_delivery(license_key)
    delivered = bk_n = legacy_n = 0
    for sid, bk_ver in rows:
        if bk_ver:
            outbound = env
            bk_n += 1
        else:
            outbound = _wrap(payload, sid)
            legacy_n += 1
        try:
            socketio.emit('fromTele', outbound, to=sid, namespace=TMC_NS)
            delivered += 1
        except Exception as exc:
            logger.warning(f"emit_drop_to_license: sid={sid[:12]} failed: {exc}")
    _fan_ms = (time.monotonic() - _fan_t0) * 1000.0
    # Self-contained metric: clients = population in this license (bk + legacy);
    # delivered = successful emits; fanout_ms = worker time first->last emit.
    logger.info(
        f"TMC | DROP code={code[:32]} room={redact_room(room)} "
        f"clients={len(rows)} bk={bk_n} legacy={legacy_n} "
        f"delivered={delivered} mode=snapshot fanout_ms={_fan_ms:.1f}"
    )
    return delivered


def emit_drop_to_username(username: str, code: str, coupon_type: str = 'drop') -> int:
    """Emit 'fromTele' (task=drop) to EVERY live /_tmc socket whose username
    matches — global scope, across all licenses (mirror of emit_drop_to_license,
    keyed by username). Always per-SID (usernames have no Socket.IO room);
    `_wrap` is a pass-through when ENABLE_RSA_AUTH is off, so this is correct in
    both modes. Returns the count of SIDs delivered to (best-effort)."""
    rows = snapshot_username_delivery(username)   # [(lk, sid, bk_ver)] atomically
    if not rows:
        return 0

    _ctype = 'bonus' if str(coupon_type).strip().lower() == 'bonus' else 'drop'
    if _ctype == 'bonus':
        # Remember bonus codes so claims for them are excluded from license totals
        # even from old scripts that don't echo couponType back.
        _mark_bonus_code(code)

    delivered = 0
    for lk, sid, bk_ver in rows:
        payload = {
            'task': 'drop',
            'code': code,
            'license': lk,          # this SID's own license (informational for the client)
            'source': 'telegram',
            'couponType': _ctype,
            'timestamp': _now_ms(),
        }
        # Always per-SID (a username has no room; n = one user's tabs, tiny). The
        # bk_ver from the atomic snapshot is the single delivery signal: set -> BK
        # envelope, None -> per-connection wrap. RSA off -> plaintext.
        if not Config.ENABLE_RSA_AUTH:
            outbound = payload
        else:
            outbound = encrypt_broadcast(payload) if bk_ver else _wrap(payload, sid)
        try:
            socketio.emit('fromTele', outbound, to=sid, namespace=TMC_NS)
            delivered += 1
        except Exception as exc:
            logger.warning(f"emit_drop_to_username: sid={sid[:12]} failed: {exc}")
    logger.info(
        f"TMC | DROP code={code[:32]} username={username} "
        f"delivered={delivered} mode=per-user"
    )
    return delivered


def emit_reload_to_license(license_key: str) -> int:
    payload = {
        'task': 'reload',
        'license': license_key,
        'source': 'telegram',
        'timestamp': _now_ms(),
    }
    # One atomic snapshot; one emit per sid. RSA off -> plaintext; RSA on -> BK
    # envelope (encrypted once) for bk_ver-set sids, per-connection wrap otherwise.
    env = encrypt_broadcast(payload) if Config.ENABLE_RSA_AUTH else None
    delivered = 0
    for sid, bk_ver in snapshot_license_delivery(license_key):
        if not Config.ENABLE_RSA_AUTH:
            outbound = payload
        else:
            outbound = env if bk_ver else _wrap(payload, sid)
        try:
            socketio.emit('fromTele', outbound, to=sid, namespace=TMC_NS)
            delivered += 1
        except Exception:
            pass
    return delivered


def emit_get_browsers(license_key: str) -> int:
    sids = license_sids(license_key)
    delivered = 0
    for sid in sids:
        try:
            socketio.emit('getBrowsers', _wrap(False, sid), to=sid, namespace=TMC_NS)
            delivered += 1
        except Exception:
            pass
    return delivered


def emit_license_deleted(license_key: str) -> None:
    """Per spec §10.3: notify clients then close room."""
    payload = {
        'message': 'Your license has been removed. Contact @adityaofficial96.',
        'timestamp': _now_ms(),
    }
    sids = license_sids(license_key)
    for sid in sids:
        try:
            socketio.emit('license_deleted', _wrap(payload, sid), to=sid, namespace=TMC_NS)
        except Exception:
            pass

    import eventlet
    eventlet.spawn_after(0.5, _close_room_and_revoke, license_key)


def emit_license_key_changed(old_key: str, new_key: str) -> None:
    """v3.1 §A: notify old key's clients of the new key."""
    payload = {
        'old_key': old_key,
        'new_key': new_key,
        'message': 'Your license key has been updated by the admin.',
        'timestamp': _now_ms(),
    }
    sids = license_sids(old_key)
    for sid in sids:
        try:
            socketio.emit('license_key_changed', _wrap(payload, sid), to=sid, namespace=TMC_NS)
        except Exception:
            pass


def disconnect_license_room(license_key: str) -> None:
    """Revoke session JTIs and disconnect all SIDs in this license's room."""
    revoked = revoke_license_sessions(license_key)
    for sid, _tid in revoked:
        try:
            socketio.server.disconnect(sid, namespace=TMC_NS)
        except Exception:
            pass


def _close_room_and_revoke(license_key: str) -> None:
    try:
        socketio.close_room(_room(license_key), namespace=TMC_NS)
    except Exception:
        pass
    disconnect_license_room(license_key)


# ---------------------------------------------------------------------------
# Collectors — bot calls /api/xr9k/lic/rl + /api/xr9k/lic/browsers which
# emit the request and then wait briefly for replies.
# ---------------------------------------------------------------------------

def _add_reload_response(license_key: str, item: dict) -> None:
    with _collectors_lock:
        _reload_collectors[license_key].append(item)


def _add_browsers_response(license_key: str, item: dict) -> None:
    with _collectors_lock:
        _browsers_collectors[license_key].append(item)


def collect_reload_responses(license_key: str, wait_seconds: float = 5.0) -> list:
    # Reset collector, emit, sleep, return what arrived
    with _collectors_lock:
        _reload_collectors[license_key] = []
    delivered = emit_reload_to_license(license_key)
    if delivered == 0:
        return []
    import eventlet
    eventlet.sleep(wait_seconds)
    with _collectors_lock:
        items = list(_reload_collectors.get(license_key, []))
        _reload_collectors[license_key] = []
    return items


# ---------------------------------------------------------------------------
# Admin remote-management: push a config task to a claimer + collect its ack.
# Mirrors the reload emit/collect pattern. Token payloads ride the per-SID
# _wrap (RSA→AES) envelope when ENABLE_RSA_AUTH is on.
# ---------------------------------------------------------------------------
def _api_ckey(telegram_id: int, claimer_id: str) -> str:
    return f"{int(telegram_id or 0)}:{claimer_id}"


def emit_task_to_claimer(claimer_id: str, telegram_id: int, task: str,
                         payload: dict = None) -> int:
    """Emit a `fromTele {task, …}` to this claimer's live sid(s), scoped to the
    admin's telegram_id. Returns SIDs delivered to (0 = offline)."""
    from app.license_manager import sids_for_claimer
    pairs = sids_for_claimer(claimer_id, telegram_id)
    if not pairs:
        return 0
    body = {'task': task, 'timestamp': _now_ms()}
    if isinstance(payload, dict):
        body.update(payload)
    delivered = 0
    for lk, sid in pairs:
        try:
            socketio.emit('fromTele', _wrap(body, sid), to=sid, namespace=TMC_NS)
            delivered += 1
        except Exception as exc:
            logger.warning(f"emit_task_to_claimer task={task} sid={sid[:12]} failed: {exc}")
    return delivered


def _add_api_response(telegram_id: int, claimer_id: str, item: dict) -> None:
    ckey = _api_ckey(telegram_id, claimer_id)
    with _collectors_lock:
        # Only buffer when a synchronous admin action is waiting on this ckey.
        # Auto-reconcile acks (no waiter) are dropped here — they are still
        # folded into observed_* by the caller.
        if ckey in _api_armed:
            _api_collectors[ckey].append(item)


def collect_claimer_result(claimer_id: str, telegram_id: int, task: str,
                           payload: dict = None, wait_seconds: float = 6.0) -> list:
    """Push a task and wait (bounded) for the claimer's `apiResult` ack.
    Returns the collected ack list ([] when offline / no reply)."""
    ckey = _api_ckey(telegram_id, claimer_id)
    with _collectors_lock:
        _api_armed.add(ckey)
        _api_collectors[ckey] = []
    try:
        delivered = emit_task_to_claimer(claimer_id, telegram_id, task, payload)
        if delivered == 0:
            return []
        import eventlet
        eventlet.sleep(wait_seconds)
        with _collectors_lock:
            return list(_api_collectors.get(ckey, []))
    finally:
        # Always disarm + free the buffer, even on early return / exception.
        with _collectors_lock:
            _api_armed.discard(ckey)
            _api_collectors.pop(ckey, None)


def _reconcile_claimer(telegram_id: int, claimer_id: str, do_push: bool = True) -> int:
    """Compare DESIRED (authoritative) vs OBSERVED and push ONLY differing
    fields (API compared by fingerprint). do_push=False recomputes config_state
    only (used after an ack). Returns the number of differing fields."""
    from app import claimer_manager
    e = claimer_manager.get_claimer(telegram_id, claimer_id)
    if not e:
        return 0
    diffs = []
    if e.get('desired_token') and e.get('desired_token_fp') != e.get('observed_api_fp'):
        diffs.append(('setApi', {'token': e['desired_token']}))
    if e.get('desired_currency') and e['desired_currency'] != e.get('observed_currency'):
        diffs.append(('setCurrency', {'currency': e['desired_currency']}))
    if e.get('desired_filters') is not None and e['desired_filters'] != (e.get('observed_filters') or {}):
        diffs.append(('setFilters', {'filters': e['desired_filters']}))
    if not diffs:
        claimer_manager.set_config_state(telegram_id, claimer_id, 'synced')
        return 0
    if do_push:
        for task, payload in diffs:
            emit_task_to_claimer(claimer_id, telegram_id, task, payload)
        claimer_manager.set_config_state(telegram_id, claimer_id, 'needs_sync', stamp_push=True)
    else:
        claimer_manager.set_config_state(telegram_id, claimer_id, 'needs_sync')
    return len(diffs)


def _notify_admin_push_failed(telegram_id: int, claimer_id: str, reason: str) -> None:
    """DM the admin once when a config push fails/invalid. Best-effort; never logs the token."""
    try:
        from app import claimer_manager
        e = claimer_manager.get_claimer(telegram_id, claimer_id) or {}
        name = e.get('claimer_name') or claimer_id
        from app.utils.telegram import notify_bot_service
        notify_bot_service(int(telegram_id), (
            "⚠️ <b>Claimer config push failed</b>\n"
            f"Claimer <code>{safe_html(str(name))[:32]}</code>: {safe_html(reason)[:64]}\n"
            "It will re-sync automatically once fixed and refreshed."
        ))
    except Exception:
        pass


def _notify_claimer_offline(telegram_id: int, claimer_id: str) -> None:
    """DM the admin that a claimer went online->offline. Best-effort. Suppressed
    during worker shutdown so a deploy/restart never produces a notification
    storm."""
    if _shutting_down:
        return
    try:
        from app import claimer_manager
        e = claimer_manager.get_claimer(telegram_id, claimer_id) or {}
        name = e.get('claimer_name') or claimer_id
        username = e.get('stake_username') or '—'
        from app.utils.telegram import notify_bot_service
        notify_bot_service(int(telegram_id), (
            "🔴 <b>Claimer Offline</b>\n"
            f"Name: <code>{safe_html(str(name))[:48]}</code>\n"
            f"Username: <code>{safe_html(str(username))[:48]}</code>"
        ))
    except Exception:
        pass


def _decrypt_if_rsa(sid: str, data):
    """Mirror on_user_claim's RSA decrypt. Returns (data, error_or_None)."""
    if not Config.ENABLE_RSA_AUTH:
        return data, None
    aes_key = _get_session_aes(sid)
    if not aes_key:
        return None, 'no_session_key'
    try:
        return decrypt_payload(aes_key, data), None
    except Exception:
        return None, 'decrypt_failed'


@socketio.on('claimerStatus', namespace=TMC_NS)
def on_claimer_status(data):
    """Client reports OBSERVED state (informational). Session-bound: writes
    observed_* ONLY, then auto-reconciles (pushes differing desired fields)."""
    sid = request.sid
    session_info = get_session_by_sid(sid)
    if not session_info:
        return {'ok': False, 'error': 'not_authenticated'}
    if not _claimer_evt_rate_ok(session_info['license_key']):
        try:
            from app.utils.rate_limit_notify import notify_rate_limit
            notify_rate_limit(session_info['license_key'], 'claimer_events',
                              session_info.get('telegram_id'))
        except Exception:
            pass
        return {'ok': False, 'error': 'rate_limited'}
    data, err = _decrypt_if_rsa(sid, data)
    if err:
        return {'ok': False, 'error': err}
    if not isinstance(data, dict):
        return {'ok': False, 'error': 'bad_payload'}
    tid = int(session_info.get('telegram_id') or 0)
    cid = session_info.get('claimer_id')          # session-bound; payload ids ignored
    if not cid:
        return {'ok': True, 'ignored': True}
    from app import claimer_manager
    claimer_manager.ensure_claimer(tid, cid, session_info.get('claimer_name'))
    claimer_manager.record_observed(tid, cid, data)
    try:
        _reconcile_claimer(tid, cid, do_push=True)
    except Exception:
        pass
    return {'ok': True, 'received': True}


@socketio.on('apiResult', namespace=TMC_NS)
def on_api_result(data):
    """Ack for a pushed config task. Feeds the synchronous admin-change collector
    AND folds the applied value into observed_* + config_state. Session-bound."""
    sid = request.sid
    session_info = get_session_by_sid(sid)
    if not session_info:
        return {'ok': False, 'error': 'not_authenticated'}
    if not _claimer_evt_rate_ok(session_info['license_key']):
        try:
            from app.utils.rate_limit_notify import notify_rate_limit
            notify_rate_limit(session_info['license_key'], 'claimer_events',
                              session_info.get('telegram_id'))
        except Exception:
            pass
        return {'ok': False, 'error': 'rate_limited'}
    data, err = _decrypt_if_rsa(sid, data)
    if err:
        return {'ok': False, 'error': err}
    if not isinstance(data, dict):
        return {'ok': False, 'error': 'bad_payload'}
    tid = int(session_info.get('telegram_id') or 0)
    cid = session_info.get('claimer_id')
    if not cid:
        return {'ok': True}
    _add_api_response(tid, cid, data)             # unblocks collect_claimer_result
    from app import claimer_manager
    claimer_manager.apply_observed_after_push(tid, cid, data)
    try:
        if data.get('ok') is False or data.get('valid') is False:
            already = (claimer_manager.get_claimer(tid, cid) or {}).get('config_state')
            claimer_manager.set_config_state(tid, cid, 'push_failed', stamp_validation=('valid' in data))
            if already != 'push_failed':
                _notify_admin_push_failed(
                    tid, cid,
                    'invalid token' if data.get('valid') is False else 'apply failed')
        else:
            _reconcile_claimer(tid, cid, do_push=False)
            if 'valid' in data:
                st = (claimer_manager.get_claimer(tid, cid) or {}).get('config_state', 'synced')
                claimer_manager.set_config_state(tid, cid, st, stamp_validation=True)
    except Exception:
        pass
    return {'ok': True}


def collect_send_browsers(license_key: str, wait_seconds: float = 5.0) -> dict:
    with _collectors_lock:
        _browsers_collectors[license_key] = []
    delivered = emit_get_browsers(license_key)
    if delivered == 0:
        return {'browsers': 0, 'accounts': []}
    import eventlet
    eventlet.sleep(wait_seconds)
    with _collectors_lock:
        items = list(_browsers_collectors.get(license_key, []))
        _browsers_collectors[license_key] = []

    # Aggregate accounts across responses, dedup by username
    accounts = {}
    total_browsers = 0
    for item in items:
        if not isinstance(item, dict):
            continue
        if isinstance(item.get('browser'), dict):
            total_browsers += int(item['browser'].get('current') or 0)
        for acct in (item.get('accounts') or []):
            if isinstance(acct, dict) and acct.get('username'):
                accounts[acct['username']] = acct
    return {
        'browsers': total_browsers or len(items),
        'accounts': list(accounts.values()),
    }


# ---------------------------------------------------------------------------
# Notifications + persistence helpers
# ---------------------------------------------------------------------------

def _now_ist() -> str:
    """Best-effort IST timestamp without external deps."""
    import datetime
    return (datetime.datetime.utcnow() + datetime.timedelta(hours=5, minutes=30)).strftime(
        '%Y-%m-%d %H:%M:%S IST'
    )


def _format_duration(secs: int) -> str:
    if secs < 60:
        return f"{secs}s"
    if secs < 3600:
        return f"{secs // 60}m {secs % 60}s"
    h = secs // 3600
    m = (secs % 3600) // 60
    return f"{h}h {m}m"


def _record_claim_amount(license_key: str, username: str, code: str,
                         currency: str, amount, telegram_id: int = 0) -> str:
    """
    Queue a successful claim's amount for DB recording via the shared
    conversion worker (which writes licenses.usd_claim_amount for TMC claims).

    Idempotent per (username, code): the SAME user claiming the SAME code
    more than once (two tabs, a reconnect retry, or a corrected follow-up)
    is credited exactly once.

    Returns a status string (also surfaced in the userClaim ACK):
      'recorded'   — newly queued for the DB write
      'duplicate'  — already credited for this (username, code) within TTL
      'no_amount'  — claim succeeded but no usable amount was supplied
      'queue_full' — conversion queue saturated (amount lost; logged)
      'error'      — unexpected failure (logged)

    KEY INVARIANT: the per-(username, code) idempotency marker is consumed
    ONLY when a real, positive amount is queued. A claim that arrives without
    an amount (e.g. the verify query hadn't resolved yet on the client) does
    NOT consume the slot, so a later userClaim carrying the real amount can
    still be credited. This is what fixes "claimed but amount not recorded".
    """
    # Validate amount BEFORE touching the idempotency marker.
    if amount in (None, '', 0):
        logger.warning(
            f"CLAIM_NO_AMOUNT | user={username} | code={code} | "
            f"license={redact_key(license_key)} | reason=missing_or_zero"
        )
        return 'no_amount'
    try:
        amt_float = float(amount)
    except (TypeError, ValueError):
        logger.warning(
            f"CLAIM_NO_AMOUNT | user={username} | code={code} | "
            f"license={redact_key(license_key)} | reason=unparseable:{amount!r}"
        )
        return 'no_amount'
    if amt_float <= 0:
        logger.warning(
            f"CLAIM_NO_AMOUNT | user={username} | code={code} | "
            f"license={redact_key(license_key)} | reason=non_positive:{amt_float}"
        )
        return 'no_amount'
    if not (currency and username and code):
        logger.warning(
            f"CLAIM_NO_AMOUNT | user={username} | code={code} | "
            f"license={redact_key(license_key)} | reason=missing_field "
            f"currency={currency!r}"
        )
        return 'no_amount'

    try:
        # Lazy import — avoids module-load order coupling between blueprints.
        import queue as _queue_mod
        from app.routes.api import (
            _mark_converted, _unmark_converted, _conversion_queue,
            _warn_if_queue_pressured, _record_queue_full,
        )

        # Idempotency marker consumed here — ONLY for a valid positive amount.
        # Keep the rollback token so a queue.Full does NOT leave a false 12-hour
        # duplicate marker (which would otherwise block a client resend).
        tok = _mark_converted(username, code)
        if tok is None:
            return 'duplicate'

        try:
            _conversion_queue.put_nowait({
                'username': username,
                'target_currency': currency.upper(),
                'amount': amt_float,
                'code': code,               # original case — for the group notification
                'code_lower': code.lower(),  # dedup / DB / code_claims key
                'license_key': license_key,  # explicit, race-free
                'telegram_id': int(telegram_id) if telegram_id else 0,
            })
            _warn_if_queue_pressured()
            logger.info(
                f"CLAIM | user={username} | code={code} | amount={amt_float} | "
                f"currency={currency.upper()} | license={redact_key(license_key)} "
                f"| via=tmc"
            )
            return 'recorded'
        except _queue_mod.Full:
            # Roll the marker back (token-checked) so a resend can retry, and
            # CRITICAL-log the drop instead of a quiet warning.
            _unmark_converted(username, code, tok)
            _record_queue_full(username, code)
            return 'queue_full'
    except Exception as exc:
        # Must NEVER break the userClaim ACK.
        logger.warning(
            f"CLAIM | persist path failed user={username} code={code}: {exc}",
            exc_info=True,
        )
        return 'error'


def _persist_drop_claim(license_key: str, username: str, code: str,
                        currency: str, claimed: bool) -> None:
    """
    No-op DB write. The cumulative `theclaimers_count` column is no longer
    used; the bot reads live `active_now` (computed from active_sessions)
    instead. Audit trail lives in stdout CLAIM / CLAIM_COUNT log lines.
    """
    if not claimed:
        return
    try:
        from app.license_manager import get_unique_username_count
        from app.license_manager import get_license_cache_entry
        entry = get_license_cache_entry(license_key) or {}
        max_users = int(entry.get('maximum_usernames') or 0)
        active = get_unique_username_count(license_key)
        logger.info(
            f"LICENSE_ACTIVE | license={license_key} | active={active}/{max_users} | "
            f"user={username} | code={code}"
        )
    except Exception as exc:
        logger.warning(f"_persist_drop_claim log failed: {exc}")


def _add_drop_result(license_key: str, telegram_id: int, code: str,
                     result: dict) -> None:
    """
    Aggregate per-code drop results. The first result for a (license, code)
    pair opens a 5-second window; subsequent results join until the timer
    fires a single consolidated Telegram message.
    """
    if not telegram_id or not code:
        return
    key = (license_key, code)
    schedule_fire = False
    with _claim_collectors_lock:
        # bounded LRU — drop oldest if over cap
        if len(_claim_collectors) >= _CLAIM_COLLECTORS_MAX and key not in _claim_collectors:
            try:
                _claim_collectors.pop(next(iter(_claim_collectors)))
            except StopIteration:
                pass
        bucket = _claim_collectors.get(key)
        if bucket is None:
            bucket = []
            _claim_collectors[key] = bucket
            schedule_fire = True
        bucket.append(result)
        # F-report: fold this result into the per-code response tally in real
        # time, inside the lock already held (no new lock, no I/O, no yield). A
        # no-op unless a report window is open for this code. Fully guarded so a
        # fold error can never disturb the existing 5s summary / claim path.
        try:
            _fold_response_tally(license_key, code, result)
        except Exception:
            logger.exception("F-report fold failed (ignored)")

    if schedule_fire:
        import eventlet
        eventlet.spawn_after(5.0, _fire_consolidated_drop_summary,
                             telegram_id, license_key, code)


# Human-friendly labels for the failure categories the userscript reports in a
# drop result's `error` field (see _classifyClaimError in the userscript). The
# Telegram summary prints these so users can tell the outcomes apart — most
# importantly "Code not found" (invalid code) vs "Code limit reached" (inactive
# code), which previously both surfaced as a vague "unavailable".
_DROP_ERROR_LABELS = {
    'not_found':         'Code not found',
    'filtered':          'Filtered',
    'already_claimed':   'Already claimed',
    'wager_required':    'Wager required',
    'restricted':        'Account restricted',
    'geo_blocked':       'Not available in region',
    'requirements':      'Requirements not met',
    'unavailable':       'Unavailable',
    'timeout':           'Timed out',
    'no_result':         'No response',
    'bonus_disabled':    'Auto-bonus is off',
    'pipeline_missing':  'Claimer not ready',
}


def _humanize_drop_error(code) -> str:
    """Map a reported error category to a clean label. Unknown codes are
    prettified (snake_case → 'Sentence case') so nothing leaks raw."""
    c = str(code or '').strip().lower()
    if c in _DROP_ERROR_LABELS:
        return _DROP_ERROR_LABELS[c]
    if not c:
        return 'Unavailable'
    return c.replace('_', ' ').strip().capitalize()


def _fire_consolidated_drop_summary(telegram_id: int, license_key: str,
                                    code: str) -> None:
    """Send one Telegram message summarising all per-user drop results."""
    key = (license_key, code)
    with _claim_collectors_lock:
        results = _claim_collectors.pop(key, [])
    if not results:
        return

    # Deduplicate by username — if both a failed and a claimed result exist
    # for the same username (claimed result arrived after dedup upgrade),
    # keep only the claimed one.
    by_user: Dict[str, dict] = {}
    for r in results:
        uname = r.get('username') or ''
        existing = by_user.get(uname)
        if existing is None or (r.get('claimed') and not existing.get('claimed')):
            by_user[uname] = r
    results = list(by_user.values())

    success = [r for r in results if r.get('claimed')]
    failed = [r for r in results if not r.get('claimed')]

    lines = ["<b>⚡ CLAIM RESULT</b>", ""]
    lines.append(f"🎟  <code>{safe_html(code)}</code>")
    lines.append(
        f"📊  {len(success)}/{len(results)} claimed"
    )
    lines.append("")

    for r in success:
        amt = r.get('amount')
        amt_str = ''
        if amt not in (None, ''):
            try:
                amt_str = f"  •  {float(amt):.4f} {(r.get('currency') or '').upper()}"
            except Exception:
                amt_str = ''
        lines.append(
            f"✅  <code>{safe_html(r.get('username', ''))}</code>{amt_str}"
        )

    for r in failed:
        reason = _humanize_drop_error(r.get('error'))
        extra = ''
        if r.get('reloadAvailable') and r.get('timeLeft'):
            extra = f"  •  ⏳ reload in {_format_duration(int(r.get('timeLeft') or 0))}"
        lines.append(
            f"❌  <code>{safe_html(r.get('username', ''))}</code>  •  {safe_html(reason)}{extra}"
        )

    lines.append("")
    lines.append(f"<i>{_now_ist()}</i>")

    try:
        notify_bot_service(telegram_id, "\n".join(lines))
    except Exception as exc:
        logger.warning(f"_fire_consolidated_drop_summary: {exc}")


# ---------------------------------------------------------------------------
# Broadcast response report (F-report) helpers. See the store definition near
# the top of this module for the concurrency contract. None of the helpers do
# I/O or acquire a lock except where noted; the fan-out/claim hot paths are
# untouched.
# ---------------------------------------------------------------------------

def _report_norm(code) -> str:
    """Normalize a code for the response-report store. Stake codes are
    case-sensitive, so strip only (matches the value the userscript echoes back
    verbatim). Capped to mirror the on_user_claim code cap."""
    return str(code or '').strip()[:64]


def _report_sanitize_label(label: str) -> str:
    """Lowercase and collapse anything outside [a-z0-9_] to '_', capped — so an
    unknown/raw error category can never inject markup or grow unbounded."""
    s = ''.join(
        ch if ch in _REPORT_LABEL_CHARS else '_'
        for ch in str(label or '').strip().lower()
    )[:24]
    return s or 'unknown'


def _response_category(claimed: bool, error_code) -> str:
    """Map a drop result to a report category: 'claimed', a known
    _DROP_ERROR_LABELS key, a sanitized unknown error, or 'no_result'."""
    if claimed:
        return 'claimed'
    c = str(error_code or '').strip().lower()
    if not c:
        return 'no_result'
    if c in _DROP_ERROR_LABELS:
        return c
    return _report_sanitize_label(c)


def _report_prune(now: float) -> None:
    """Drop TTL-expired entries. MUST hold _claim_collectors_lock. Entries are
    LRU-ordered by last-touch (move_to_end on every touch), so the stale ones
    cluster at the front — pop from the front until a live one is seen."""
    while _response_tallies:
        k = next(iter(_response_tallies))
        if now - _response_tallies[k]['ts'] > _REPORT_TTL:
            _response_tallies.pop(k, None)
        else:
            break


def _schedule_or_extend(code) -> None:
    """Open (or extend) the response-report window for `code`. Called by the
    broadcaster BEFORE the fan-out, so a userClaim folded mid-fanout (separate
    greenlet) always finds an open window. No-op unless an admin is configured.
    Cheap: one dict op under the existing lock + at most one spawn_after made
    OUTSIDE the lock. A re-broadcast while pending only extends a float — no new
    timer is spawned."""
    if not _ADMIN_TELEGRAM_IDS:
        return
    global _report_gen_seq
    cn = _report_norm(code)
    if not cn:
        return
    now = time.monotonic()
    arm = False
    g = 0
    with _claim_collectors_lock:
        _report_prune(now)
        e = _response_tallies.get(cn)
        if e is None:
            _report_gen_seq += 1
            g = _report_gen_seq
            _response_tallies[cn] = {
                'gen': g,
                'counts': {},
                'total': 0,
                'reported': {},
                'reported_total': 0,
                'claimed_users': set(),
                'window_start': now,
                'deadline': now + _REPORT_WINDOW,
                'pending': True,
                'ts': now,
            }
            # bounded LRU — newest is at the end, so this only evicts old codes
            while len(_response_tallies) > _REPORT_MAX_CODES:
                _response_tallies.popitem(last=False)
            arm = True
        elif not e['pending']:
            # a fresh reporting window on an already-reported code: new gen +
            # fresh claimed-dedup set; counts/reported carry the delta baseline.
            _report_gen_seq += 1
            g = _report_gen_seq
            e['gen'] = g
            e['claimed_users'] = set()
            e['window_start'] = now
            e['deadline'] = now + _REPORT_WINDOW
            e['pending'] = True
            e['ts'] = now
            _response_tallies.move_to_end(cn)
            arm = True
        else:
            # pending → extend the single active timer's deadline (capped). The
            # live timer picks up the new deadline when it fires; no new spawn.
            e['deadline'] = min(now + _REPORT_WINDOW,
                                e['window_start'] + _REPORT_HARD_MAX)
            e['ts'] = now
            _response_tallies.move_to_end(cn)
    if arm:
        import eventlet
        eventlet.spawn_after(_REPORT_WINDOW, _fire_response_report, cn, g)


def _fold_response_tally(license_key: str, code: str, result: dict) -> None:
    """Fold ONE drop result into its code's response tally. MUST be called with
    _claim_collectors_lock ALREADY HELD (it runs inside _add_drop_result's
    critical section). Pure dict/set ops — no I/O, no lock, no yield. No-op
    unless a report window is open for this code."""
    e = _response_tallies.get(_report_norm(code))
    if e is None:
        return
    if bool(result.get('claimed')):
        # composite (license_key, username) identity — license_key is the
        # server-authoritative session identity; username is client-asserted but
        # now scoped under an authenticated license (same as the 90s dedup).
        uid = (license_key, result.get('username') or '')
        cu = e['claimed_users']
        if uid in cu:
            return  # same (license, user) already counted this window
        if len(cu) < _REPORT_MAX_CLAIMED_USERS:
            cu.add(uid)
        else:
            logger.warning("F-report claimed_users cap hit code=%s", _report_norm(code)[:32])
        cat = 'claimed'
    else:
        cat = _response_category(False, result.get('error'))
        if cat not in e['counts'] and len(e['counts']) >= _REPORT_MAX_CATS:
            cat = 'other'
    e['counts'][cat] = e['counts'].get(cat, 0) + 1
    e['total'] += 1


def _build_response_report(cn: str, delta: dict, delta_total: int,
                           cumulative_total: int) -> str:
    """Build the ONE aggregate HTML message: total new responses + per-category
    counts (claimed first, then by count desc), plus a cumulative footer."""
    lines = ["<b>📣 CLAIM REPORT</b>", ""]
    lines.append(f"🎟  <code>{safe_html(cn)}</code>")
    lines.append(f"📊  New responses: {delta_total}")
    lines.append("")
    ordered = sorted(
        delta.items(),
        key=lambda kv: (kv[0] != 'claimed', -kv[1], kv[0]),
    )
    for cat, n in ordered:
        icon = "✅" if cat == 'claimed' else "❌"
        label = "Claimed" if cat == 'claimed' else _humanize_drop_error(cat)
        lines.append(f"{icon}  {safe_html(label)}: {n}")
    lines.append("")
    lines.append(f"<i>Σ {cumulative_total} total · {_now_ist()}</i>")
    return "\n".join(lines)


def _fire_response_report(cn: str, g: int) -> None:
    """Spawned greenlet (off the hot path). Reschedules itself while the window
    is still being extended; otherwise finalizes and sends ONE aggregate report
    with the delta since the previous report. The (cn, g) pair is the
    orphan-timer guard: a timer only ever touches the exact window that armed
    it."""
    reschedule_after = None
    delta = None
    delta_total = 0
    cumulative_total = 0
    with _claim_collectors_lock:
        e = _response_tallies.get(cn)
        if e is None or e['gen'] != g:
            return  # orphan timer (evicted / re-created window): no-op
        now = time.monotonic()
        if now < e['deadline'] - 0.05:
            reschedule_after = e['deadline'] - now  # window was extended
        else:
            counts = e['counts']
            reported = e['reported']
            delta = {}
            for cat, n in counts.items():
                d = n - reported.get(cat, 0)
                if d > 0:
                    delta[cat] = d
            delta_total = e['total'] - e['reported_total']
            e['reported'] = dict(counts)
            e['reported_total'] = e['total']
            e['pending'] = False
            cumulative_total = e['total']
    if reschedule_after is not None:
        import eventlet
        eventlet.spawn_after(reschedule_after, _fire_response_report, cn, g)
        return
    if not delta or delta_total <= 0:
        return  # nothing new (e.g. undelivered broadcast) → no message
    msg = _build_response_report(cn, delta, delta_total, cumulative_total)
    for tid in list(_ADMIN_TELEGRAM_IDS):
        try:
            notify_bot_service(tid, msg)
        except Exception as exc:
            logger.warning(f"_fire_response_report notify {tid}: {exc}")


def _notify_reload_claimed(telegram_id: int, username: str,
                           amount=None, currency: str = '') -> None:
    """§9: reload notification fires immediately (no 5s delay).
    Single-line message: '<username> reload claimed <amount> <CURRENCY>'."""
    if not telegram_id:
        return
    try:
        amt_txt = ''
        if amount is not None:
            try:
                amt_txt = f"{float(amount):g} {safe_html(str(currency).upper().strip())}".strip()
            except (TypeError, ValueError):
                amt_txt = ''
        msg = f"🔄 <code>{safe_html(username)}</code> reload claimed"
        if amt_txt:
            msg += f" {amt_txt}"
        notify_bot_service(telegram_id, msg)
    except Exception as exc:
        logger.warning(f"_notify_reload_claimed: {exc}")


def _notify_account_deactivated(telegram_id: int, username: str) -> None:
    """Engaging 'you've been disconnected' alert sent when a user's Stake API key
    is deactivated. Fires immediately; client one-shot + server dedup keep it to
    one message per event."""
    if not telegram_id:
        return
    try:
        safe_user = safe_html(username or 'your account')
        notify_bot_service(
            telegram_id,
            "⚠️ <b>Disconnected</b>\n\n"
            f"The API key for <code>{safe_user}</code> has been deactivated, so the "
            "claimer just lost access to that Stake account — drops, reloads and "
            "auto-claiming are now paused.\n\n"
            "🔑 To get back online, open the panel → <b>Settings → Connection</b> and "
            "enter a fresh API key (or log back in). Claiming resumes automatically "
            "the moment a valid key is verified."
        )
    except Exception as exc:
        logger.warning(f"_notify_account_deactivated: {exc}")


# ---------------------------------------------------------------------------
# Encryption wrapper (§B) — applied on every emit when RSA mode is on.
# Pass-through when ENABLE_RSA_AUTH=false.
# ---------------------------------------------------------------------------

def _wrap(payload, sid: str):
    if not Config.ENABLE_RSA_AUTH:
        return payload
    aes_key = _get_session_aes(sid)
    if not aes_key:
        # Should not happen — disconnect handler would have removed sid.
        return payload
    if not isinstance(payload, dict):
        payload = {'value': payload}
    return encrypt_payload(aes_key, payload)


def _get_session_aes(sid: str):
    from app.license_manager import get_session_key
    return get_session_key(sid)
