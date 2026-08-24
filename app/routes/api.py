import queue
import threading
import time
import logging
import hashlib
import base64
import json as _json
import collections
import os

# ---------------------------------------------------------------------------
# Handshake rate limiter — max 15 unique usernames per IP per minute
# Standard Flask-Limiter cannot count unique values, so we track manually.
# ---------------------------------------------------------------------------
_handshake_lock = threading.Lock()
# {ip: deque([(username, timestamp), ...])}
_handshake_ip_usernames: dict = {}
_HANDSHAKE_WINDOW = 60      # seconds
_HANDSHAKE_MAX_UNIQUE = 11  # max unique usernames per IP per window


def _check_handshake_rate_limit(ip: str, username: str) -> bool:
    """
    Returns True if allowed, False if rate limit exceeded.
    Counts unique usernames seen from this IP in the last 60 seconds.
    The same username retried multiple times counts as 1 unique username.
    """
    now = time.time()
    cutoff = now - _HANDSHAKE_WINDOW

    with _handshake_lock:
        if ip not in _handshake_ip_usernames:
            _handshake_ip_usernames[ip] = collections.deque()

        dq = _handshake_ip_usernames[ip]

        # Remove entries older than the window
        while dq and dq[0][1] < cutoff:
            dq.popleft()

        # Count unique usernames in current window
        seen_usernames = {entry[0] for entry in dq}

        # If this username is already in the window, it's a retry — always allow
        if username in seen_usernames:
            return True

        # New username — check if limit reached
        if len(seen_usernames) >= _HANDSHAKE_MAX_UNIQUE:
            return False

        # Allow and record
        dq.append((username, now))

        # Cleanup old IPs periodically to prevent memory growth
        # Only do this 1% of the time to avoid lock contention
        import random
        if random.random() < 0.01:
            expired_ips = [
                k for k, v in _handshake_ip_usernames.items()
                if not v or v[-1][1] < cutoff
            ]
            for k in expired_ips:
                del _handshake_ip_usernames[k]

        return True


# ---------------------------------------------------------------------------
# Idempotency tracking — prevents double-counting same code claim
# ---------------------------------------------------------------------------
_claimed_codes: dict = {}
_claimed_codes_lock = threading.Lock()
CLAIMED_CODE_TTL = 43200


def _mark_converted(username: str, code: str):
    """
    Atomically check if already converted AND mark it.
    Returns the marker TOKEN (the time.time() timestamp just stored) when this is
    the FIRST time for (username, code) — the caller may hand that token to
    _unmark_converted() to roll the mark back if it fails to enqueue the amount.
    Returns None when already converted / empty code (caller should skip).
    """
    if not code:
        return None   # no code = treat as already processed, skip silently
    code = code.strip().upper()
    with _claimed_codes_lock:
        now = time.time()
        if username not in _claimed_codes:
            _claimed_codes[username] = {}
        user_codes = _claimed_codes[username]
        if code in user_codes and (now - user_codes[code]) < CLAIMED_CODE_TTL:
            return None  # Already converted
        user_codes[code] = now
        _claimed_codes[username] = {
            c: t for c, t in user_codes.items()
            if now - t < CLAIMED_CODE_TTL
        }
        return now  # First time — this timestamp is the rollback token


def _check_and_mark_converted(username: str, code: str) -> bool:
    """
    Backward-compatible wrapper (byte-identical bool semantics to the original):
    returns True if already converted / empty code (skip), False if first time.
    Prefer _mark_converted() when a rollback token is needed.
    """
    return _mark_converted(username, code) is None


def _unmark_converted(username: str, code: str, token) -> None:
    """
    Roll back a marker set by _mark_converted() when the amount could NOT be
    enqueued (queue.Full), so a client resend is not rejected as a false
    duplicate for CLAIMED_CODE_TTL. TOKEN-CHECKED: removes the entry ONLY if the
    stored value still equals `token`, so a concurrent successful attempt's
    (different-timestamp) marker can never be removed by mistake.
    """
    if not code or token is None:
        return
    code = code.strip().upper()
    with _claimed_codes_lock:
        u = _claimed_codes.get(username)
        if u is not None and u.get(code) == token:
            u.pop(code, None)


# ---------------------------------------------------------------------------
# AES-GCM decryption helper for new RSA flow
# ---------------------------------------------------------------------------
def _decrypt_convert_payload(body: dict, session_token: str):
    """
    Decrypt AES-GCM encrypted convert-to-usd payload.

    Body format from client (new flow):
        { "username": { "encDataX": "<b64>", "iv": "<b64>" } }

    AES key = SHA-256(session_token) — derived independently by both sides.
    No server-side key storage needed.

    Returns:
        Decrypted dict on success.
        Original body dict if not encrypted (handles transition).
        None if decryption fails (reject request).
    """
    username_key = None
    inner = None
    for key, value in body.items():
        if isinstance(value, dict) and 'encDataX' in value and 'iv' in value:
            username_key = key
            inner = value
            break

    if not inner:
        # Not encrypted — pass through (old clients during transition)
        return body

    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        iv = base64.b64decode(inner['iv'])
        ciphertext = base64.b64decode(inner['encDataX'])
        aes_key = hashlib.sha256(session_token.encode('utf-8')).digest()
        aesgcm = AESGCM(aes_key)
        plaintext = aesgcm.decrypt(iv, ciphertext, None)
        return _json.loads(plaintext.decode('utf-8'))
    except Exception:
        return None  # decryption failed — caller returns 400


import eventlet
from datetime import datetime, timezone, timedelta
from flask import Blueprint, jsonify, request
from sqlalchemy import select, func, text
from app.database import db_session
from app.models import User, ExchangeRate, License  # noqa: F401 (User/License kept for SQLAlchemy model registration)
from app.config import Config
from app.rate_limit import get_username_key, limiter
from app.utils import ist

api_bp = Blueprint('api', __name__, url_prefix='/api')


# ---------------------------------------------------------------------------
# Connected-user helpers
# ---------------------------------------------------------------------------

def _get_connected_usernames():
    """Return set of usernames currently connected via WebSocket, SSE, or /_v."""
    connected = set()
    try:
        from app.websocket_manager import websocket_manager
        clients_snapshot = dict(websocket_manager.clients)
        for sid, info in clients_snapshot.items():
            u = info.get('username')
            if u:
                connected.add(u.lower())
    except Exception:
        pass
    try:
        from app.sse_manager import sse_manager
        with sse_manager.lock:
            for username in sse_manager.connections.keys():
                if username:
                    connected.add(username.lower())
    except Exception:
        pass
    try:
        from app._v_manager import _v_manager
        for u in _v_manager.usernames():
            if u:
                connected.add(u.lower())
    except Exception:
        pass
    return connected


_IP_LIMIT = f"{Config.RATELIMIT_IP_USERNAME_PER_MINUTE} per minute"
_USERNAME_LIMIT = f"{Config.RATELIMIT_PER_USERNAME_PER_MINUTE} per minute"


# ---------------------------------------------------------------------------
# Background queue for convert-to-usd — prevents overwhelming Supabase/PgBouncer
# ---------------------------------------------------------------------------
def _validated_queue_max(default: int = 10000) -> int:
    """Never trust the env string. A non-int or <= 0 must NOT crash startup and
    must NOT create an unbounded queue (queue.Queue(maxsize<=0) is UNBOUNDED)."""
    raw = os.environ.get('CONVERSION_QUEUE_MAX', str(default))
    try:
        v = int(raw)
        if v <= 0:
            raise ValueError('non-positive')
        return v
    except (TypeError, ValueError):
        logging.warning(
            f"CONVERSION_QUEUE_MAX invalid ({raw!r}); using default {default}"
        )
        return default


_CONVERSION_QUEUE_MAX = _validated_queue_max(10000)
_conversion_queue = queue.Queue(maxsize=_CONVERSION_QUEUE_MAX)

# Backpressure observability (no Telegram / no synchronous outbound on the claim
# path). Separate WARN/ERR rate-limit timers so a 70% WARNING can never suppress
# a 90% ERROR; queue.Full is CRITICAL and is NEVER rate-limited.
_QUEUE_WARN_AT = max(1, (_CONVERSION_QUEUE_MAX * 70 + 99) // 100)  # ceil(0.70*MAX), min 1
_QUEUE_ERR_AT = max(1, (_CONVERSION_QUEUE_MAX * 90 + 99) // 100)   # ceil(0.90*MAX), min 1
_QUEUE_LOG_INTERVAL = 30.0
_last_warn_log = 0.0
_last_err_log = 0.0
_conversion_full_count = 0
_conversion_full_lock = threading.Lock()


def _warn_if_queue_pressured() -> None:
    """Rate-limited backpressure logging. ERROR (>=90%) and WARNING (>=70%) use
    INDEPENDENT timers, so entering the higher tier logs immediately even if the
    lower tier fired seconds ago. Best-effort; never raises."""
    global _last_warn_log, _last_err_log
    try:
        qs = _conversion_queue.qsize()
    except Exception:
        return
    if qs < _QUEUE_WARN_AT:
        return
    now = time.time()
    pct = round(qs * 100.0 / _CONVERSION_QUEUE_MAX, 1)
    if qs >= _QUEUE_ERR_AT:
        if now - _last_err_log >= _QUEUE_LOG_INTERVAL:
            _last_err_log = now
            logging.error(
                f"CONVERSION_QUEUE_PRESSURE | qsize={qs} | maxsize={_CONVERSION_QUEUE_MAX} "
                f"| pct={pct}% | cumulative_full={_conversion_full_count}"
            )
    else:
        if now - _last_warn_log >= _QUEUE_LOG_INTERVAL:
            _last_warn_log = now
            logging.warning(
                f"CONVERSION_QUEUE_PRESSURE | qsize={qs} | maxsize={_CONVERSION_QUEUE_MAX} "
                f"| pct={pct}% | cumulative_full={_conversion_full_count}"
            )


def _record_queue_full(username: str, code: str) -> None:
    """Count + CRITICAL-log a dropped claim on queue.Full. NEVER rate-limited —
    every drop is a potential accounting loss and must be visible. The caller has
    already rolled back the idempotency marker so a client resend can retry."""
    global _conversion_full_count
    with _conversion_full_lock:
        _conversion_full_count += 1
        cnt = _conversion_full_count
    try:
        qs = _conversion_queue.qsize()
        pct = round(qs * 100.0 / _CONVERSION_QUEUE_MAX, 1)
    except Exception:
        qs, pct = -1, -1
    logging.critical(
        f"CONVERSION_QUEUE_FULL | user={username} | code={code} | qsize={qs} "
        f"| maxsize={_CONVERSION_QUEUE_MAX} | pct={pct}% | cumulative_full={cnt} "
        f"| amount_dropped_unless_client_resends"
    )


def _conversion_worker():
    """
    Process convert-to-usd requests one by one from the queue.

    After a successful user.usd_claim_amount increment (the "amount
    increasing" signal = claim event), the same session atomically
    upserts the per-code claim counter. The upsert's RETURNING clause
    reports whether this invocation was the first-ever claim for that
    lowercased code, in which case a 2-second-delayed Telegram alert
    is scheduled via eventlet.spawn_after (non-blocking, eventlet-safe,
    does NOT touch the worker's DB session).
    """
    while True:
        try:
            data = _conversion_queue.get()
            if data is None:
                _conversion_queue.task_done()
                continue

            username = data.get('username')
            target_currency = data.get('target_currency')
            amount = data.get('amount')
            code_lower = data.get('code_lower') or ''
            # Original-case code for the group first-claim notification only.
            # All DB/dedup/history keys still use code_lower (unchanged).
            code_exact = data.get('code') or code_lower

            try:
                with db_session() as session:
                    # Exchange rate first — if absent, the increment is impossible
                    rate_row = session.execute(
                        select(ExchangeRate).where(
                            func.upper(func.trim(ExchangeRate.target_currency)) == target_currency.upper()
                        )
                    ).scalar_one_or_none()

                    if not rate_row or not rate_row.rate_from_usd:
                        logging.warning(f"CONVERSION | user={username} | SKIPPED: no exchange rate for {target_currency}")
                        continue

                    rate_from_usd = float(rate_row.rate_from_usd)
                    if rate_from_usd <= 0:
                        logging.warning(f"CONVERSION | user={username} | SKIPPED: bad rate {rate_from_usd} for {target_currency}")
                        continue

                    converted_usd = float(amount) / rate_from_usd

                    # ─── Transport-based storage routing (product spec) ────────
                    # License (TMC) claim  → licenses.usd_claim_amount  ONLY
                    # SSE claim            → app_users.usd_claim_amount  ONLY
                    #
                    # The two transports are mutually exclusive because the
                    # discriminator is the explicit `license_key` field that
                    # tmc_routes.on_user_claim passes in. The SSE conversion
                    # endpoint (POST /api/users/claims/convert-to-usd) does
                    # NOT pass license_key, so it falls into the SSE branch.
                    #
                    # No active_sessions fallback — under the new architecture
                    # SSE users never need a license attribution, so scanning
                    # active_sessions on every SSE claim was both unnecessary
                    # and a minor lock-contention source.
                    lic_key = (data.get('license_key') or '').strip() or None

                    # Single atomic CTE. Each UPDATE is gated by a constant
                    # predicate on the bind parameter, so PostgreSQL evaluates
                    # exactly ONE of them per row:
                    #   • SSE  (lic_key empty): u updates, l short-circuits FALSE
                    #   • TMC  (lic_key set):    l updates, u short-circuits FALSE
                    # code_claims upsert runs in EITHER case (we always want
                    # the per-code counter + first-claim alert).
                    # Effective per-claim deduction rate (see app.utils.ist):
                    #   • deduction_percentage IS NULL            → 0 (After-Claims)
                    #   • == DEFAULT_DEDUCTION_PERCENTAGE (default) → day schedule:
                    #         Saturday(IST) → DEDUCTION_RATE_SATURDAY, else weekday
                    #   • any other value (custom)                 → that exact value
                    # The day is resolved in IST so a Friday-night-UTC claim that
                    # is already Saturday in India is billed at the Saturday rate.
                    is_sat = ist.is_saturday_ist()
                    _ded_expr = (
                        "(CASE "
                        "  WHEN deduction_percentage IS NULL THEN 0 "
                        "  WHEN ABS(deduction_percentage - :default_pct) < 0.0001 "
                        "    THEN :converted * (CASE WHEN :is_sat THEN :sat_rate ELSE :wd_rate END) / 100.0 "
                        "  ELSE :converted * deduction_percentage / 100.0 "
                        "END)"
                    )
                    upsert_sql = (
                        "WITH u AS ("
                        "  UPDATE app_users SET usd_claim_amount = COALESCE(usd_claim_amount, 0) + :converted"
                        "  WHERE username = :username AND :lic_key = ''"   # SSE only
                        "  RETURNING usd_claim_amount"
                        "), l AS ("
                        "  UPDATE licenses SET"
                        "    usd_claim_amount = COALESCE(usd_claim_amount, 0) + :converted,"
                        "    available_balance = COALESCE(available_balance, 0) - " + _ded_expr +
                        "  WHERE license_key = :lic_key AND :lic_key <> ''"  # TMC only
                        "  RETURNING usd_claim_amount, available_balance, telegram_id, active, "
                        + _ded_expr + " AS deducted"
                        ")"
                    )
                    params = {
                        "converted": converted_usd,
                        "username": username,
                        "lic_key": lic_key or "",
                        "default_pct": float(Config.DEFAULT_DEDUCTION_PERCENTAGE),
                        "wd_rate": float(Config.DEDUCTION_RATE_WEEKDAY),
                        "sat_rate": float(Config.DEDUCTION_RATE_SATURDAY),
                        "is_sat": bool(is_sat),
                    }
                    if code_lower:
                        upsert_sql += (
                            ", c AS ("
                            "  INSERT INTO code_claims (code, total_claims_count) VALUES (:code, 1)"
                            "  ON CONFLICT (code) DO UPDATE"
                            "  SET total_claims_count = code_claims.total_claims_count + 1"
                            "  RETURNING total_claims_count, (xmax = 0) AS inserted"
                            ") "
                            "SELECT"
                            "  (SELECT usd_claim_amount FROM u) AS user_total,"
                            "  (SELECT usd_claim_amount FROM l) AS lic_total,"
                            "  (SELECT available_balance FROM l) AS lic_balance,"
                            "  (SELECT telegram_id FROM l) AS lic_tid,"
                            "  (SELECT active FROM l) AS lic_active,"
                            "  (SELECT deducted FROM l) AS lic_deducted,"
                            "  (SELECT total_claims_count FROM c) AS code_total,"
                            "  (SELECT inserted FROM c) AS first_claim"
                        )
                        params["code"] = code_lower
                    else:
                        upsert_sql += (
                            " SELECT"
                            "  (SELECT usd_claim_amount FROM u) AS user_total,"
                            "  (SELECT usd_claim_amount FROM l) AS lic_total,"
                            "  (SELECT available_balance FROM l) AS lic_balance,"
                            "  (SELECT telegram_id FROM l) AS lic_tid,"
                            "  (SELECT active FROM l) AS lic_active,"
                            "  (SELECT deducted FROM l) AS lic_deducted,"
                            "  NULL::int AS code_total,"
                            "  NULL::bool AS first_claim"
                        )

                    try:
                        row = session.execute(text(upsert_sql), params).one()
                    except Exception as exc:
                        logging.error(f"CONVERSION | user={username} | SQL: {exc}", exc_info=True)
                        continue

                    # Skip telemetry only when NEITHER table was updated, i.e.
                    # the matching row doesn't exist for the relevant transport:
                    #   • SSE: app_users.username row missing  → user_total NULL
                    #   • TMC: licenses.license_key row missing → lic_total NULL
                    # In normal operation exactly ONE of the two is set (gated
                    # by the CTE). If both are NULL, no credit was applied.
                    if row.user_total is None and row.lic_total is None:
                        reason = (
                            f"license '{lic_key}' not in DB" if lic_key
                            else f"user '{username}' not in app_users"
                        )
                        logging.warning(
                            f"CONVERSION | user={username} | code={code_lower} | "
                            f"SKIPPED: {reason}"
                        )
                        continue

                    # Audit log — distinguish which table got credited.
                    if lic_key:
                        logging.info(
                            f"LICENSE_CLAIM | license={lic_key} | user={username} | "
                            f"amount={converted_usd:.4f} | lic_total={row.lic_total}"
                        )
                        # Coalesced "balance changed" notification — only when a
                        # positive deduction was actually applied (i.e. a prepaid
                        # license on the percentage plan; After-Claims licenses
                        # deduct 0 and are never notified). The deduction itself
                        # already committed above; this only schedules a debounced
                        # summary and must never block the worker.
                        try:
                            _ded = float(row.lic_deducted) if row.lic_deducted is not None else 0.0
                            if _ded > 0:
                                # Effective per-claim rate actually applied (lets
                                # the notification show "≈ $X more claimable").
                                _eff_pct = (_ded / converted_usd * 100.0) if converted_usd else 0.0
                                from app.services import balance_notifier
                                balance_notifier.record(
                                    license_key=lic_key,
                                    telegram_id=int(row.lic_tid or 0),
                                    deducted=_ded,
                                    new_balance=(float(row.lic_balance) if row.lic_balance is not None else None),
                                    active=bool(row.lic_active),
                                    rate_pct=_eff_pct,
                                )
                        except Exception as _bn_exc:
                            logging.warning(f"balance_notifier.record failed license={lic_key}: {_bn_exc}")
                    else:
                        logging.info(
                            f"SSE_CLAIM | user={username} | "
                            f"amount={converted_usd:.4f} | user_total={row.user_total}"
                        )

                    # ----------------------------------------------------------
                    # 24-hour rolling history (for /count Telegram command).
                    # Recorded AFTER the DB update succeeded so we never log a
                    # claim that didn't actually credit. Best-effort: a history
                    # failure must NEVER break the worker loop.
                    # ----------------------------------------------------------
                    try:
                        from app import claim_history
                        claim_history.record_claim(
                            license_key=lic_key,
                            telegram_id=data.get('telegram_id') or 0,
                            username=username,
                            code=code_lower,
                            amount_usd=converted_usd,
                            currency=target_currency,
                            original_amount=float(amount),
                        )
                    except Exception as _hist_exc:
                        logging.warning(
                            f"claim_history.record_claim failed for "
                            f"user={username} code={code_lower}: {_hist_exc}"
                        )

                    was_first_claim = bool(row.first_claim) if row.first_claim is not None else False
                    total_claims = int(row.code_total) if row.code_total is not None else None
                    if code_lower and total_claims is not None:
                        logging.info(
                            f"CLAIM_COUNT | code={code_lower} | total={total_claims} | "
                            f"first={was_first_claim}"
                        )

                    # ----------------------------------------------------------
                    # First-claim Telegram alert — dispatched via a hub timer
                    # (eventlet.spawn_after), detached from THIS worker greenlet
                    # and from the DB session. The delay is admin-configurable at
                    # runtime (/claimdelay), default 0 s = instant. spawn_after
                    # only REGISTERS a timer and returns immediately, so the
                    # worker never blocks and the broadcast path is never touched,
                    # regardless of the delay value or how many codes coincide.
                    # ----------------------------------------------------------
                    if was_first_claim and code_lower:
                        IST = timezone(timedelta(hours=5, minutes=30))
                        now_utc = datetime.now(timezone.utc)
                        first_claimed_at = (
                            now_utc.strftime("%Y-%m-%d %H:%M:%S UTC") +
                            " / " +
                            now_utc.astimezone(IST).strftime("%Y-%m-%d %H:%M:%S IST")
                        )
                        from app.utils.telegram import notify_first_claim
                        from app.utils import runtime_settings
                        eventlet.spawn_after(
                            runtime_settings.get_first_claim_delay(),
                            notify_first_claim,
                            username,
                            code_exact,
                            float(amount),
                            target_currency,
                            first_claimed_at,
                        )

            except Exception as e:
                logging.error(f"CONVERSION | user={username} | DB ERROR: {e}", exc_info=True)
            finally:
                _conversion_queue.task_done()

        except Exception:
            pass


_worker_thread = threading.Thread(
    target=_conversion_worker,
    daemon=True,
    name="Conversion-Worker"
)
_worker_thread.start()
_worker_thread_start_pid = os.getpid()


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

def _legacy_disabled_response():
    """Decoy response for legacy endpoints when LEGACY_ENDPOINTS_ENABLED=False.
    Indistinguishable from any non-route, so a disabled endpoint reveals nothing.
    Default config keeps these ON, so this is a no-op unless explicitly disabled."""
    from app.utils.decoy import generate_decoy_response
    return generate_decoy_response()


@api_bp.route('/server-time')
def server_time():
    """Returns current server Unix timestamp. Used by old nonce flow only."""
    if not Config.LEGACY_ENDPOINTS_ENABLED:
        return _legacy_disabled_response()
    return jsonify({'t': int(time.time())}), 200


@api_bp.route('/ingest', methods=['POST', 'GET'])
def ingest():
    return jsonify({
        'error': 'HTTP ingest has been disabled',
        'next_steps': 'Connect to the /ws/ingest Socket.IO namespace and include the shared ingest token.'
    }), 410


@api_bp.route('/status')
def api_status():
    from app.utils.decoy import generate_decoy_response
    return generate_decoy_response()


@api_bp.route('/info')
def api_info():
    from app.utils.decoy import generate_decoy_response
    return generate_decoy_response()


@api_bp.route('/exchange-rates', methods=['GET'])
def get_exchange_rates():
    try:
        with db_session() as session:
            result = session.execute(
                select(
                    func.upper(func.trim(ExchangeRate.target_currency)).label('currency'),
                    ExchangeRate.rate_from_usd
                )
            ).mappings().all()
            rates = [dict(row) for row in result]
            return jsonify({'rates': rates, 'count': len(rates)}), 200
    except Exception:
        return jsonify({'error': 'Internal server error'}), 500


@api_bp.route('/users/claims/convert-to-usd', methods=['POST'])
@limiter.limit(_IP_LIMIT)
@limiter.limit(
    _USERNAME_LIMIT,
    key_func=get_username_key,
    exempt_when=lambda: get_username_key() is None,
)
def convert_to_usd():
    if not Config.LEGACY_ENDPOINTS_ENABLED:
        return _legacy_disabled_response()
    try:
        raw_data = request.get_json()
        if not raw_data:
            return jsonify({'error': 'Request body must be JSON'}), 400

        # ------------------------------------------------------------------
        # NEW FLOW (ENABLE_RSA_AUTH=true):
        # Body is AES-GCM encrypted: { username: { encDataX, iv } }
        # Authorization: Bearer <sessionToken>
        # AES key = SHA-256(sessionToken) — derived on both sides, no state
        # ------------------------------------------------------------------
        if Config.ENABLE_RSA_AUTH:
            auth_header = request.headers.get('Authorization', '')
            if not auth_header.startswith('Bearer '):
                return jsonify({'error': 'Authorization header required', 'code': 'auth_invalid'}), 401

            session_token = auth_header[7:].strip()
            if not session_token:
                return jsonify({'error': 'Empty session token', 'code': 'auth_invalid'}), 401

            data = _decrypt_convert_payload(raw_data, session_token)
            if data is None:
                return jsonify({'error': 'Decryption failed or invalid payload', 'code': 'auth_invalid'}), 401

            # SECURITY FIX: Reject plain (unencrypted) payloads when RSA is enabled
            if data is raw_data:
                return jsonify({'error': 'Encrypted payload required', 'code': 'auth_invalid'}), 401

            # Validate token belongs to the username inside decrypted payload
            username_from_payload = (data.get('username') or '').strip()
            if not username_from_payload:
                return jsonify({'error': 'username required in payload', 'code': 'bad_request'}), 400

            from app.routes.sse_routes import validate_iframe_token
            if not validate_iframe_token(session_token, username_from_payload):
                return jsonify({'error': 'Invalid or expired session token', 'code': 'auth_invalid'}), 401
        else:
            # OLD FLOW: plain JSON — no changes to existing behaviour
            data = raw_data

        # ------------------------------------------------------------------
        # Common validation (both flows)
        # ------------------------------------------------------------------
        username = data.get('username')
        target_currency = data.get('target_currency')
        amount = data.get('amount')

        if not username or not target_currency or amount is None:
            return jsonify({'error': 'username, target_currency, and amount are required'}), 400

        try:
            amount = float(amount)
            if amount < 0:
                return jsonify({'error': 'amount must be non-negative'}), 400
        except (ValueError, TypeError):
            return jsonify({'error': 'amount must be a valid number'}), 400

        if not isinstance(target_currency, str):
            return jsonify({'error': 'target_currency must be a string'}), 400

        currency = target_currency.strip().upper()
        if not currency or len(currency) < 3 or len(currency) > 10:
            return jsonify({'error': 'target_currency must be 3-10 characters'}), 400

        # Idempotency check — prevents double-counting. Keep the rollback token
        # so a queue.Full does NOT leave a false 12-hour duplicate marker.
        code = data.get('code', '').strip() if data.get('code') else ''
        _tok = _mark_converted(username, code)
        if _tok is None:
            return jsonify({'success': True, 'skipped': True}), 200

        # Lowercased form is what the DB layer uses (claim counter key).
        # The original case is preserved for logs and broadcast; broadcast
        # logic elsewhere still treats ABC29 and abc29 as distinct codes.
        code_lower = code.lower() if code else ''

        # Queue for async DB write + claim counter upsert + delayed Telegram.
        try:
            _conversion_queue.put_nowait({
                'username': username,
                'target_currency': currency,
                'amount': amount,
                'code': code,               # original case — for the group notification
                'code_lower': code_lower,
            })
            _warn_if_queue_pressured()
        except queue.Full:
            # Roll the marker back (token-checked) so a client resend can retry,
            # and CRITICAL-log the drop. Not silently ignored anymore.
            _unmark_converted(username, code, _tok)
            _record_queue_full(username, code)
            return jsonify({'success': False, 'queued': False, 'code': 'queue_full'}), 503

        logging.info(f"CLAIM | user={username} | code={code} | amount={amount} | currency={currency}")
        return jsonify({'success': True, 'queued': True}), 200

    except Exception:
        return jsonify({'error': 'Internal server error'}), 500


# ---------------------------------------------------------------------------
# /api/handshake — NEW RSA auth flow entry point
# Active only when ENABLE_RSA_AUTH=true
# ---------------------------------------------------------------------------

@api_bp.route('/handshake', methods=['POST'])
def handshake():
    """
    RSA handshake for new auth flow.

    Client sends:
        { "username": "...", "publicKey": "<spki-der-base64>" }

    Server:
        1. Checks username exists in app_users (subscription check)
        2. Generates a 120-minute session token
        3. RSA-OAEP encrypts it with client's public key
        4. Returns { "encryptedToken": "<b64>" }

    Client decrypts with its private key to get the session token.
    Only the genuine client who generated the keypair can decrypt.
    Zero calls to Stake — only app_users DB checked.
    """
    if not Config.LEGACY_ENDPOINTS_ENABLED:
        return _legacy_disabled_response()
    # SSE_BROADCAST_ENABLED=False disables username-based auth entirely.
    # Frontend detects 503 and switches to license_only mode.
    if not Config.SSE_BROADCAST_ENABLED:
        return jsonify({'error': 'Username auth disabled', 'code': 'mode_disabled'}), 503

    if not Config.ENABLE_RSA_AUTH:
        # Return 404 so old clients fail silently and fall back to nonce flow
        return jsonify({'error': 'Not available', 'code': 'rsa_disabled'}), 404

    data = request.get_json(silent=True)
    if not data:
        return jsonify({'error': 'JSON required', 'code': 'bad_request'}), 400

    username    = (data.get('username') or '').strip()
    pub_key_b64 = (data.get('publicKey') or '').strip()

    if not username or not pub_key_b64:
        return jsonify({'error': 'username and publicKey are required', 'code': 'bad_request'}), 400

    if len(username) > 64:
        return jsonify({'error': 'Invalid username', 'code': 'bad_request'}), 400

    # Rate limit: max 15 unique usernames per IP per minute
    from app.utils.cloudflare import get_real_client_ip
    client_ip = get_real_client_ip()
    if not _check_handshake_rate_limit(client_ip, username.lower()):
        return jsonify({'error': 'Too many authentication attempts', 'code': 'rate_limited'}), 429

    # Check subscription — YOUR database only, no Stake API call
    from app.services import user_service
    user_record = user_service.get_user(username)
    if user_record and user_record.get('_db_error'):
        # DB is under load — tell client to retry in 10s instead of hanging
        return jsonify({'error': 'Service temporarily unavailable', 'code': 'db_unavailable'}), 503
    if not user_record or not user_record.get('user_id'):
        return jsonify({'error': 'Authentication failed', 'code': 'user_not_found'}), 403

    # Generate session token (valid 120 minutes)
    from app.routes.sse_routes import generate_iframe_token
    try:
        session_token = generate_iframe_token(username, expiry_minutes=1440)
    except ValueError:
        return jsonify({'error': 'Server configuration error', 'code': 'server_error'}), 500

    # RSA-encrypt session token with client's public key
    try:
        from cryptography.hazmat.primitives import serialization, hashes
        from cryptography.hazmat.primitives.asymmetric import padding
        from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

        pub_key_bytes = base64.b64decode(pub_key_b64)
        public_key = serialization.load_der_public_key(pub_key_bytes)

        # Enforce minimum RSA key size
        if not isinstance(public_key, RSAPublicKey):
            return jsonify({'error': 'Only RSA public keys are accepted', 'code': 'bad_request'}), 400
        if public_key.key_size < 2048:
            return jsonify({'error': 'Minimum 2048-bit RSA key required', 'code': 'bad_request'}), 400

        encrypted = public_key.encrypt(
            session_token.encode('utf-8'),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return jsonify({
            'encryptedToken': base64.b64encode(encrypted).decode('utf-8')
        }), 200

    except (ValueError, TypeError, Exception):
        return jsonify({'error': 'Invalid public key format', 'code': 'bad_request'}), 400


# ---------------------------------------------------------------------------
# Public license endpoints — used by the on-load popup and /_tmc token fetch
# in claimers.js (gated behind LICENSE_FLOW_ENABLED in the script).
# ---------------------------------------------------------------------------

_LICENSE_NF_WINDOW = 600         # 10 minutes window for "not_found" tracking
_LICENSE_NF_THRESHOLD = 5        # 5 consecutive 404s → cooldown
_LICENSE_NF_COOLDOWN = 3600      # 1 hour cooldown
_license_nf_lock = threading.Lock()
_license_nf: dict = {}  # {ip: {'count': int, 'first_ts': float, 'cooldown_until': float}}


def _license_verify_cooldown_check(ip: str) -> tuple:
    """Returns (in_cooldown, retry_after) for an IP that hit too many 404s."""
    now = time.time()
    with _license_nf_lock:
        rec = _license_nf.get(ip)
        if not rec:
            return False, 0.0
        if rec.get('cooldown_until', 0) > now:
            return True, rec['cooldown_until'] - now
        return False, 0.0


def _license_verify_record_nf(ip: str) -> None:
    """Increment not-found counter; trigger cooldown after threshold."""
    now = time.time()
    with _license_nf_lock:
        rec = _license_nf.get(ip)
        if not rec or now - rec.get('first_ts', 0) > _LICENSE_NF_WINDOW:
            rec = {'count': 1, 'first_ts': now, 'cooldown_until': 0}
        else:
            rec['count'] = rec.get('count', 0) + 1
        if rec['count'] >= _LICENSE_NF_THRESHOLD:
            rec['cooldown_until'] = now + _LICENSE_NF_COOLDOWN
        _license_nf[ip] = rec
        # Cheap periodic prune
        if len(_license_nf) > 5000:
            cutoff = now - max(_LICENSE_NF_WINDOW, _LICENSE_NF_COOLDOWN)
            drop = [k for k, v in _license_nf.items()
                    if v.get('cooldown_until', 0) < now and v.get('first_ts', 0) < cutoff]
            for k in drop:
                _license_nf.pop(k, None)


def _license_verify_reset_nf(ip: str) -> None:
    with _license_nf_lock:
        _license_nf.pop(ip, None)


@api_bp.route('/license/verify', methods=['POST'])
@limiter.limit("20 per minute")
def verify_license():
    """
    Lightweight verification — active/inactive/not_found/banned. Does not
    issue a JWT. Called by the on-load popup and the stored-key recheck.
    """
    from app.utils.cloudflare import get_real_client_ip
    client_ip = get_real_client_ip() or 'unknown'

    in_cooldown, retry_after = _license_verify_cooldown_check(client_ip)
    if in_cooldown:
        resp = jsonify({
            'valid': False,
            'code': 'cooldown',
            'message': 'Too many invalid attempts; please retry later',
        })
        resp.status_code = 429
        resp.headers['Retry-After'] = str(int(retry_after))
        return resp

    data = request.get_json(silent=True) or {}
    license_key = (data.get('license_key') or '').strip()

    # API-Claimer: the credential is an api_accounts.license_key (any format).
    # is_license_active() resolves it from api_accounts and populates the cache.
    from app.config import Config as _Cfg
    if _Cfg.API_CLAIMER_MODE:
        if not license_key:
            return jsonify({'valid': False, 'code': 'bad_format',
                            'message': 'Account credential required'}), 400
        from app.license_manager import is_license_active, get_license_cache_entry
        ok = is_license_active(license_key)
        _license_verify_reset_nf(client_ip)
        entry = get_license_cache_entry(license_key) or {}
        if not entry:
            return jsonify({'valid': False, 'code': 'not_found',
                            'message': 'Account not found'}), 404
        if entry.get('banned'):
            return jsonify({'valid': False, 'code': 'banned',
                            'message': 'Account banned'}), 403
        if ok:
            return jsonify({'valid': True, 'active': True}), 200
        return jsonify({'valid': False, 'code': 'inactive',
                        'message': 'Account not active'}), 403

    if not license_key or not license_key.startswith('THECLAIMERS-'):
        return jsonify({
            'valid': False, 'code': 'bad_format',
            'message': 'Invalid license key format',
        }), 400

    from app.license_manager import get_license_cache_entry

    entry = get_license_cache_entry(license_key)
    if entry:
        _license_verify_reset_nf(client_ip)
        if entry.get('banned'):
            return jsonify({'valid': False, 'code': 'banned',
                            'message': 'License banned'}), 403
        if entry.get('active'):
            return jsonify({'valid': True, 'active': True}), 200
        return jsonify({'valid': False, 'code': 'license_inactive',
                        'message': 'License not active'}), 403

    # Cache miss — check DB so newly-registered-but-not-cached keys resolve
    try:
        from app.models import License
        with db_session() as session:
            lic = session.execute(
                select(License).where(License.license_key == license_key)
            ).scalar_one_or_none()
            if not lic:
                _license_verify_record_nf(client_ip)
                return jsonify({'valid': False, 'code': 'not_found',
                                'message': 'License not found'}), 404
            _license_verify_reset_nf(client_ip)
            if lic.banned:
                return jsonify({'valid': False, 'code': 'banned',
                                'message': 'License banned'}), 403
            if not lic.active:
                return jsonify({'valid': False, 'code': 'license_inactive',
                                'message': 'License not active. Contact @adityaofficial96'}), 403
            return jsonify({'valid': True, 'active': True}), 200
    except Exception:
        return jsonify({'valid': False, 'code': 'server_error'}), 500


@api_bp.route('/license/token', methods=['POST'])
@limiter.limit("10 per minute")
def license_token():
    """Issue a short-lived JWT for /_tmc connection. Mode-gate-safe."""
    data = request.get_json(silent=True) or {}
    license_key = (data.get('license_key') or '').strip()
    if not license_key:
        return jsonify({'error': 'license_key required', 'code': 'bad_request'}), 400

    from app.license_manager import get_license_cache_entry, issue_jwt
    entry = get_license_cache_entry(license_key)
    if not entry or not entry.get('active') or entry.get('banned'):
        return jsonify({'error': 'license_inactive', 'code': 'license_inactive'}), 403

    try:
        token, jti, exp = issue_jwt(license_key, entry.get('telegram_id') or 0)
    except RuntimeError:
        return jsonify({'error': 'server_misconfigured', 'code': 'server_error'}), 500

    return jsonify({
        'token': token,
        'jti': jti,
        'expires_at': exp,
        'license_key': license_key,
    }), 200
