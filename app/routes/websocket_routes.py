"""
WebSocket route handlers with username verification.
"""
import hashlib
import hmac
import logging
import threading
import time

logger = logging.getLogger(__name__)

from flask import Blueprint, request
from flask_socketio import ConnectionRefusedError, disconnect, emit, join_room, leave_room

from app import socketio
from app._v_manager import _v_manager
from app.config import Config
from app.services import user_service
from app.utils.validators import extract_username, validate_code_data
from app.websocket_manager import websocket_manager

ws_bp = Blueprint('ws', __name__)


def _resolve_user_from_request():
    """
    Resolve user with priority flow:
    1. Check in-memory cache (fastest)
    2. If not found, perform DB lookup (caches result)
    """
    username = request.args.get('username') or request.headers.get('X-Username')
    if not username:
        return None
    
    return user_service.get_user(username)


def _authorize_connection(namespace):
    """
    Authorize WebSocket connection.
    Returns user_record if authorized, None otherwise.
    """
    user_record = _resolve_user_from_request()
    if not user_record or not user_record.get('user_id'):
        emit('error', {'message': 'Unauthorized or unknown username'})
        disconnect(request.sid)
        return None

    websocket_manager.add_client(request.sid, namespace, user_record)
    return user_record


def _client_context():
    client = websocket_manager.get_client(request.sid)
    if not client or not client.get('username'):
        emit('error', {'message': 'Client context missing; please reconnect with username'})
        disconnect(request.sid)
        return None
    return client


def _validate_ingest_token(payload: dict) -> bool:
    server_token = Config.INGEST_SHARED_TOKEN
    if not server_token:
        # API-Claimer: if no ingest token is configured, allow (operator's own
        # page). Set INGEST_SHARED_TOKEN to require the token index.html sends.
        if Config.API_CLAIMER_MODE:
            return True
        emit('error', {'message': 'Ingest token not configured on server'})
        return False
    
    provided_token = None
    if isinstance(payload, dict):
        provided_token = payload.get('token')
    
    if not provided_token:
        emit('error', {'message': 'Ingest token is required'})
        return False
    
    if not hmac.compare_digest(str(provided_token), str(server_token)):
        emit('error', {'message': 'Invalid ingest token'})
        return False
    
    return True


def _handle_code_event(data):
    client = _client_context()
    if not client:
        return
    
    if not isinstance(data, dict):
        emit('error', {'message': 'Invalid payload'})
        return

    code_data = validate_code_data(data)
    if not code_data:
        emit('error', {'message': 'Invalid code data'})
        return

    # Strip all sender-identifying fields before broadcast
    code_data.pop('username', None)
    code_data.pop('user_id', None)
    code_data.pop('metadata', None)
    code_data.pop('source', None)

    # Ingest source (e.g. 'textarea-monitor') is NOT sent to clients, but is
    # surfaced in the admin broadcast alert for provenance. Capped + sanitized.
    _ingest_source = (str(data.get('source') or '')).strip()[:64]

    # Broadcast code (with deduplication check) - silent operation, no ack
    websocket_manager.broadcast_code(code_data, socketio, source=_ingest_source)


@socketio.on('connect', namespace='/ws/ingest')
def handle_ws_ingest_connect():
    """Handle connection to /ws/ingest WebSocket endpoint."""
    # API-Claimer: the ingest page is the operator's own broadcaster — there is
    # no per-user validation (no app_users in this DB). Accept the connection
    # with a synthetic client so the code event can broadcast.
    if Config.API_CLAIMER_MODE:
        websocket_manager.add_client(request.sid, 'ws/ingest',
                                     {'user_id': 'ingest', 'username': 'ingest'})
        logger.info(f"INGEST connect (api-claimer) sid={request.sid[:12]}")
        emit('connected', {'message': 'Connected to ingest endpoint'})
        return
    if not _authorize_connection('ws/ingest'):
        return False
    emit('connected', {'message': 'Connected to ingest endpoint'})


@socketio.on('disconnect', namespace='/ws/ingest')
def handle_ws_ingest_disconnect():
    """Handle disconnection from /ws/ingest."""
    websocket_manager.remove_client(request.sid)


@socketio.on('code', namespace='/ws/ingest')
def handle_ws_ingest_code(data):
    """Handle code received via /ws/ingest."""
    if not isinstance(data, dict):
        emit('error', {'message': 'Invalid payload'})
        return

    if not _validate_ingest_token(data):
        logger.warning("INGEST code REJECTED (bad/absent ingest token)")
        return

    # Visible receipt log so broadcasts are traceable in the Render logs.
    try:
        logger.info(
            "INGEST code recv | code=%s target_user=%s license=%s couponType=%s value=%s",
            str(data.get('code'))[:32], data.get('target_username') or '-',
            data.get('license') or '-', data.get('couponType') or 'drop',
            data.get('value'))
    except Exception:
        pass

    # Targeted-USERNAME broadcast: if the operator panel set `target_username`,
    # route ONLY to that user's live /_tmc socket(s), across all licenses, and
    # skip both the license branch and the global fanout. Checked FIRST so it
    # takes precedence and returns before anything else can run.
    # NOTE: the field is `target_username`, NOT `username` — the ingest payload
    # already carries a sender-identity `username`, so a distinct field avoids
    # every broadcast being misrouted to that sender.
    username_target = (data.get('target_username') or '').strip()
    if username_target:
        if len(username_target) > 64 or '\n' in username_target or '\r' in username_target:
            emit('error', {'message': 'Bad username format'})
            return
        code_data = validate_code_data(data)
        if not code_data:
            emit('error', {'message': 'Invalid code data'})
            return
        code_value = (code_data.get('code') or '').strip()
        if not code_value:
            emit('error', {'message': 'Code required'})
            return
        # Username targeting is INTENTIONALLY independent of the global
        # deduplication cache (websocket_manager._recent_codes): it neither
        # checks nor marks it. So a username-targeted send is never suppressed by
        # a prior global/license/username send, and never suppresses a later
        # one (e.g. send CODEX to a user, then CODEX globally — both succeed).
        # Double-delivery to a user is harmless (Stake returns "already claimed"
        # and the backend credits a (username,code) exactly once). License and
        # global dedup are left completely unchanged.
        coupon_type = 'bonus' if str(data.get('couponType') or '').strip().lower() == 'bonus' else 'drop'
        from app.routes.tmc_routes import emit_drop_to_username, _schedule_or_extend
        # F-report: open the window BEFORE fan-out (see internal.py hook).
        # Isolated so a report-hook failure can NEVER suppress the broadcast.
        try:
            _schedule_or_extend(code_value)
        except Exception:
            import logging as _lg
            _lg.getLogger(__name__).exception("F-report schedule failed (ignored)")
        delivered = emit_drop_to_username(username_target, code_value, coupon_type,
                                          value=code_data.get('value'))
        import logging
        logging.getLogger(__name__).info(
            f"BROADCAST | targeted username={username_target} code={code_value} "
            f"couponType={coupon_type} value={code_data.get('value')} delivered={delivered}"
        )
        return

    # Targeted-license broadcast: if the operator panel set `license`, route
    # ONLY to that license's /_tmc room and skip global fanout.
    license_target = (data.get('license') or '').strip()
    if license_target:
        # Strict format validation — prevent log injection and bogus targets.
        if (not license_target.startswith('THECLAIMERS-')
                or len(license_target) > 60
                or '\n' in license_target
                or '\r' in license_target):
            emit('error', {'message': 'Bad license format'})
            return
        from app.license_manager import is_license_active
        from app.routes.tmc_routes import emit_drop_to_license
        if not is_license_active(license_target):
            emit('error', {'message': 'License not active'})
            return
        code_data = validate_code_data(data)
        if not code_data:
            emit('error', {'message': 'Invalid code data'})
            return
        code_value = (code_data.get('code') or '').strip()
        if not code_value:
            emit('error', {'message': 'Code required'})
            return
        # Per-broadcast dedup so a panel double-click can't double-deliver.
        if websocket_manager.is_code_duplicate(code_value):
            emit('error', {'message': 'Duplicate code suppressed'})
            return
        # Bonus routing: the sender flags weekly/monthly/forum codes with
        # couponType "bonus"; forward it so the userscript claims via the
        # bonus API. Anything other than "bonus" is treated as a normal drop.
        coupon_type = 'bonus' if str(data.get('couponType') or '').strip().lower() == 'bonus' else 'drop'
        # F-report: open the window BEFORE fan-out, after the 2s dedup gate
        # above (so only a real, non-suppressed broadcast opens a window).
        # Isolated so a report-hook failure can NEVER suppress the broadcast.
        from app.routes.tmc_routes import _schedule_or_extend
        try:
            _schedule_or_extend(code_value)
        except Exception:
            import logging as _lg
            _lg.getLogger(__name__).exception("F-report schedule failed (ignored)")
        delivered = emit_drop_to_license(license_target, code_value, coupon_type,
                                         value=code_data.get('value'))
        import logging
        logging.getLogger(__name__).info(
            f"BROADCAST | targeted license={license_target} code={code_value} "
            f"couponType={coupon_type} value={code_data.get('value')} delivered={delivered}"
        )
        return

    _handle_code_event(data)


@socketio.on('connect', namespace='/embed')
def handle_embed_connect():
    """Handle connection to /embed WebSocket endpoint (replacement for /ws)."""
    if not _authorize_connection('embed'):
        return False
    emit('connected', {'message': 'Connected to embed endpoint'})


@socketio.on('disconnect', namespace='/embed')
def handle_embed_disconnect():
    """Handle disconnection from /embed."""
    websocket_manager.remove_client(request.sid)


@socketio.on('code', namespace='/embed')
def handle_embed_code(data):
    """Handle code received via /embed."""
    _handle_code_event(data)


@socketio.on('connect', namespace='/events')
def handle_events_connect():
    """Handle connection to /events WebSocket endpoint."""
    if not _authorize_connection('events'):
        return False
    join_room('code_listeners')
    emit('connected', {'message': 'Connected to events endpoint'})


@socketio.on('disconnect', namespace='/events')
def handle_events_disconnect():
    """Handle disconnection from /events."""
    leave_room('code_listeners')
    websocket_manager.remove_client(request.sid)


@socketio.on('subscribe', namespace='/events')
def handle_events_subscribe():
    """Handle subscription to code events."""
    if not _client_context():
        return
    join_room('code_listeners')
    emit('subscribed', {'message': 'Subscribed to code events'})


@socketio.on('connect')
def handle_default_connect():
    """Handle default WebSocket connection."""
    if not _authorize_connection('default'):
        return False
    emit('connected', {'message': 'Connected'})


@socketio.on('disconnect')
def handle_default_disconnect():
    """Handle default WebSocket disconnection."""
    websocket_manager.remove_client(request.sid)


# ---------------------------------------------------------------------------
# /_v namespace — broadcast transport replacing SSE. Isolated from ingest
# namespaces above; do not modify those.
# ---------------------------------------------------------------------------

def _v_ping_loop(sid, stop_event):
    # heartbeat — drives iframe -> parent iframe_pong_success @ 15s
    while not stop_event.is_set():
        if stop_event.wait(15):
            break
        if not _v_manager.get_client(sid):
            break
        try:
            socketio.emit(
                'ping',
                {'type': 'ping', 'timestamp': int(time.time())},
                to=sid,
                namespace='/_v',
            )
        except Exception:
            break


@socketio.on('connect', namespace='/_v')
def _v_connect():
    from app.routes.sse_routes import validate_iframe_token, is_origin_allowed

    # mode gate: username path disabled when SSE_BROADCAST_ENABLED=False
    if not Config.SSE_BROADCAST_ENABLED:
        raise ConnectionRefusedError({'code': 503, 'message': 'Username mode disabled'})

    # per-IP connect-flood guard (Phase A.3)
    client_ip = (request.headers.get('CF-Connecting-IP')
                 or request.environ.get('REMOTE_ADDR', ''))
    allowed, retry_after = _v_manager.check_connect_rate(client_ip)
    if not allowed:
        raise ConnectionRefusedError({
            'code': 429,
            'message': f'Too many connection attempts; retry in {int(retry_after)}s',
        })

    token = (request.args.get('token') or '').strip()
    user = (request.args.get('user') or '').strip()

    if not token or not user:
        raise ConnectionRefusedError({'code': 400, 'message': 'Missing credentials'})
    if not validate_iframe_token(token, user):
        # auth invalidation: parent maps connect_error.data.code=401 -> _invalidateSessionToken
        raise ConnectionRefusedError({'code': 401, 'message': 'Invalid or expired token'})

    origin = request.headers.get('Origin', '')
    referer = request.headers.get('Referer', '') or request.environ.get('HTTP_REFERER', '')
    if origin and not is_origin_allowed(origin):
        raise ConnectionRefusedError({'code': 403, 'message': 'Bad origin'})
    if not origin and not (referer and referer.startswith('https://kciade.online')):
        raise ConnectionRefusedError({'code': 403, 'message': 'Bad referer'})

    user_record = user_service.get_user(user)
    if user_record and user_record.get('_db_error'):
        raise ConnectionRefusedError({'code': 503, 'message': 'db_unavailable'})
    if not user_record or not user_record.get('user_id'):
        raise ConnectionRefusedError({'code': 403, 'message': 'Unknown username'})

    aes_key = hashlib.sha256(token.encode('utf-8')).digest()[:16]
    stop_event = threading.Event()
    _v_manager.add_client(request.sid, user, aes_key, stop_event)
    socketio.start_background_task(_v_ping_loop, request.sid, stop_event)

    emit('connected', {
        'type': 'connected',
        'username': user,
        'timestamp': int(time.time()),
    })


@socketio.on('disconnect', namespace='/_v')
def _v_disconnect():
    # websocket disconnect cleanup: stop ping greenlet before dropping record
    rec = _v_manager.remove_client(request.sid)
    if rec and rec.get('stop_event'):
        try:
            rec['stop_event'].set()
        except Exception:
            pass


@socketio.on('pong', namespace='/_v')
def _v_pong():
    pass
