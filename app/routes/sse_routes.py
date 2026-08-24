"""
SSE (Server-Sent Events) routes for embed-stream functionality.
Supports two auth flows gated by Config.ENABLE_RSA_AUTH:
  - False (old):  nonce-based  (/embed-stream?user=X&nonce=Y)
  - True  (new):  token-based  (/embed-stream?user=X&token=Y)
"""
import hmac
import hashlib
import json
import queue
import threading
import random
import time
import base64
import os
from typing import Optional
from urllib.parse import urlparse

from flask import Blueprint, Response, request, jsonify
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.config import Config
from app.rate_limit import get_embed_stream_user_key, limiter
from app.services import user_service
from app.sse_manager import sse_manager
from app.utils.validators import extract_username

sse_bp = Blueprint('sse', __name__)
_logger = __import__('logging').getLogger('sse')

NONCE_WINDOW_SECONDS = 60
_used_nonces: dict = {}
_used_nonces_lock = threading.Lock()


def _cleanup_used_nonces():
    """Remove expired nonces to prevent memory growth."""
    now = int(time.time())
    with _used_nonces_lock:
        expired = [n for n, exp in _used_nonces.items() if exp < now]
        for n in expired:
            del _used_nonces[n]


def validate_timed_nonce(nonce: str, username: str = '', record: bool = True) -> bool:
    """
    Validate nonce was generated within last 60 seconds using HMAC-SHA256.

    When `record=True` (default, used by the iframe GET) the nonce is also
    consumed in the single-use replay guard. The HEAD preflight passes
    `record=False` so a successful preflight does NOT burn the nonce — the
    immediate GET that follows is the one that consumes it. Without this,
    HEAD would mark the nonce used and the GET would always 401.
    """
    if not Config.NONCE_SECRET:
        return len(nonce) >= 8
    try:
        parts = nonce.split(':')
        if len(parts) != 2:
            return False
        timestamp_str, provided_hash = parts
        timestamp = int(timestamp_str)
        now = int(time.time())
        if abs(now - timestamp) > NONCE_WINDOW_SECONDS:
            return False
        message = f"{timestamp_str}:{Config.NONCE_SECRET}"
        expected_hash = hmac.new(
            Config.NONCE_SECRET.encode('utf-8'),
            message.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
        if not hmac.compare_digest(provided_hash, expected_hash):
            return False

        nonce_key = f"{nonce}:{username}"
        if record:
            _cleanup_used_nonces()
            with _used_nonces_lock:
                if nonce_key in _used_nonces:
                    return False
                _used_nonces[nonce_key] = now + NONCE_WINDOW_SECONDS
        else:
            # Peek-only: reject if already consumed, but do NOT consume.
            with _used_nonces_lock:
                if nonce_key in _used_nonces:
                    return False
        return True
    except (ValueError, IndexError):
        return False


_EMBED_STREAM_LIMIT = f"{Config.RATELIMIT_EMBED_STREAM_PER_USERNAME_PER_MINUTE} per minute"


class InvalidUsernameRateLimiter:
    """Rate limiter for invalid username attempts on /embed-stream."""

    def __init__(self, rate_limit_seconds: float = 3.0):
        self._failed_attempts: dict[str, float] = {}
        self._lock = threading.Lock()
        self._rate_limit_seconds = rate_limit_seconds
        self._max_entries = 10000

    def check_rate_limit(self, username: str) -> tuple[bool, float]:
        normalized = username.lower().strip() if username else ""
        if not normalized:
            return False, 0.0
        now = time.time()
        with self._lock:
            if len(self._failed_attempts) > self._max_entries:
                cutoff = now - self._rate_limit_seconds
                expired = [k for k, v in self._failed_attempts.items() if v < cutoff]
                for k in expired:
                    del self._failed_attempts[k]
            last_failed = self._failed_attempts.get(normalized, 0)
            if last_failed > 0:
                time_since_failed = now - last_failed
                if time_since_failed < self._rate_limit_seconds:
                    return True, self._rate_limit_seconds - time_since_failed
            return False, 0.0

    def record_failed_attempt(self, username: str) -> None:
        normalized = username.lower().strip() if username else ""
        if not normalized:
            return
        with self._lock:
            self._failed_attempts[normalized] = time.time()


invalid_username_rate_limiter = InvalidUsernameRateLimiter(rate_limit_seconds=3.0)


def _resolve_user_for_sse(user: str) -> Optional[dict]:
    normalized = extract_username({"username": user})
    if not normalized:
        return None
    return user_service.get_user(normalized)


def generate_iframe_token(user: str, expiry_minutes: int = 800) -> str:
    """Generate HMAC-signed token for iframe session."""
    if not Config.WS_SECRET:
        raise ValueError("WS_SECRET not configured")
    expiry = int(time.time()) + (expiry_minutes * 60)
    payload = f"{user}:{expiry}"
    signature = hmac.new(
        Config.WS_SECRET.encode('utf-8'),
        payload.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()
    return f"{payload}:{signature}"


def validate_iframe_token(token: str, user: str) -> bool:
    """Validate HMAC-signed iframe token."""
    if not Config.WS_SECRET:
        return False
    try:
        parts = token.split(':')
        if len(parts) != 3:
            return False
        user_part, expiry_str, signature = parts
        expiry = int(expiry_str)
        if user_part != user:
            return False
        if time.time() > expiry:
            return False
        payload = f"{user_part}:{expiry_str}"
        expected_signature = hmac.new(
            Config.WS_SECRET.encode('utf-8'),
            payload.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
        return hmac.compare_digest(signature, expected_signature)
    except (ValueError, IndexError):
        return False


def _encrypt_html(html: str, session_token: str) -> dict:
    """AES-GCM encrypt iframe HTML using session token as key."""
    aes_key = hashlib.sha256(session_token.encode()).digest()
    iv = os.urandom(12)
    aesgcm = AESGCM(aes_key)
    ciphertext = aesgcm.encrypt(iv, html.encode('utf-8'), None)

    return {
        'iv': base64.b64encode(iv).decode(),
        'data': base64.b64encode(ciphertext).decode()
    }


def extract_parent_origin(request) -> Optional[str]:
    origin = request.headers.get("Origin", "")
    referer = request.headers.get("Referer", "")
    candidate_origin = None
    if origin:
        candidate_origin = origin
    elif referer:
        try:
            parsed = urlparse(referer)
            if parsed.scheme and parsed.netloc:
                candidate_origin = f"{parsed.scheme}://{parsed.netloc}"
        except Exception:
            pass
    return candidate_origin


def is_origin_allowed(origin: str) -> bool:
    if not origin:
        return False
    return origin in Config.ALLOWED_ORIGINS


def _mode_gate_503():
    """Returns a Flask response if username-mode is disabled, else None."""
    if not Config.SSE_BROADCAST_ENABLED:
        return jsonify({
            'error': 'Username auth disabled',
            'code': 'mode_disabled',
        }), 503
    return None


@sse_bp.route('/embed-stream', methods=['HEAD'])
def embed_stream_head():
    """
    Cheap token-validity probe used by the Tampermonkey frontend before it
    attempts to load the iframe. Returns 200 if the session token is valid,
    401 otherwise. No DB access — HMAC validation only — so it cannot block
    the worker and cannot leak information beyond validity.
    """
    if not Config.SSE_BROADCAST_ENABLED:
        return ('', 503)
    user = request.args.get('user')
    if Config.ENABLE_RSA_AUTH:
        token = request.args.get('token')
        if not user or not token or not validate_iframe_token(token, user):
            return ('', 401)
    else:
        nonce = request.args.get('nonce')
        # Peek-only validation: do NOT consume the nonce here. The GET that
        # follows is what actually consumes it. Otherwise HEAD burns the
        # single-use slot and the iframe GET is always rejected.
        if not user or not nonce or not validate_timed_nonce(nonce, user, record=False):
            return ('', 401)
    return ('', 200)


@sse_bp.route('/embed-stream')
@limiter.limit(
    _EMBED_STREAM_LIMIT,
    key_func=get_embed_stream_user_key,
    exempt_when=lambda: get_embed_stream_user_key() is None,
)
def embed_stream():
    """
    Hidden iframe endpoint for cross-origin SSE streaming.

    Auth flow selection (ENABLE_RSA_AUTH env var):
      False → old nonce flow:  ?user=X&nonce=Y
      True  → new token flow:  ?user=X&token=Y
    """
    gated = _mode_gate_503()
    if gated is not None:
        return gated
    user = request.args.get('user')
    client_ip = request.headers.get('CF-Connecting-IP') or request.remote_addr
    _logger.info(f"EMBED_STREAM | ip={client_ip} | user={user or 'MISSING'}")

    if not user:
        _logger.warning(f"EMBED_STREAM | ip={client_ip} | REJECTED: missing user param")
        return jsonify({'error': 'user parameter required'}), 400

    # -----------------------------------------------------------------------
    # AUTH — either nonce (old) or session token (new)
    # auth_value is stored as messageNonce in the iframe HTML and is used
    # for postMessage validation between parent and iframe.
    # -----------------------------------------------------------------------
    if Config.ENABLE_RSA_AUTH:
        # New RSA flow — accept session token issued by /api/handshake
        token = request.args.get('token')
        if not token or not validate_iframe_token(token, user):
            return jsonify({'error': 'Invalid or expired token', 'code': 'auth_invalid'}), 401
        auth_value = token
        internal_token_expiry = 1440  # 24h — frontend reconnects at 22h, 2h buffer
    else:
        # Old nonce flow — backwards compatible
        nonce = request.args.get('nonce')
        if not nonce or not validate_timed_nonce(nonce, user):
            _logger.warning(f"EMBED_STREAM | user={user} | REJECTED: invalid nonce (nonce={'MISSING' if not nonce else 'BAD'})")
            return jsonify({'error': 'Invalid or expired nonce', 'code': 'auth_invalid'}), 401
        auth_value = nonce
        internal_token_expiry = 1440  # 24h — existing behaviour

    user_agent = request.headers.get('User-Agent', '')
    if not user_agent or 'Mozilla' not in user_agent:
        return jsonify({'error': 'Unauthorized'}), 403

    is_rate_limited, retry_after = invalid_username_rate_limiter.check_rate_limit(user)
    if is_rate_limited:
        response = jsonify({
            'error': 'Rate limit exceeded',
            'detail': 'Too many attempts with invalid username. Please try again later.'
        })
        response.status_code = 429
        response.headers['Retry-After'] = f"{int(retry_after) if retry_after else 10}"
        return response

    user_record = _resolve_user_for_sse(user)
    if user_record and user_record.get('_db_error'):
        _logger.warning(f"EMBED_STREAM | user={user} | DB unreachable — 503")
        return jsonify({'error': 'Service temporarily unavailable', 'code': 'db_unavailable'}), 503
    if not user_record or not user_record.get('user_id'):
        invalid_username_rate_limiter.record_failed_attempt(user)
        _logger.warning(f"EMBED_STREAM | user={user} | REJECTED: unknown username")
        return jsonify({'error': 'Unknown username', 'code': 'user_not_found'}), 403

    # Internal token used by the iframe for /events and /sse-pong
    try:
        iframe_token = generate_iframe_token(user, expiry_minutes=internal_token_expiry)
    except ValueError:
        _logger.error(f"EMBED_STREAM | user={user} | REJECTED: WS_SECRET not configured")
        return jsonify({'error': 'Server configuration error'}), 500

    broadcast_key_hex = hashlib.sha256(iframe_token.encode('utf-8')).digest()[:16].hex()

    parent_origin = extract_parent_origin(request)
    if not parent_origin:
        host = request.host
        if host.startswith('localhost') or host.startswith('127.0.0.1'):
            parent_origin = f"http://{host}"
        else:
            _logger.warning(f"EMBED_STREAM | user={user} | REJECTED: no origin/referer header")
            return jsonify({'error': 'Unauthorized origin - iframe access only'}), 403
    if not is_origin_allowed(parent_origin):
        _logger.warning(f"EMBED_STREAM | user={user} | REJECTED: bad origin={parent_origin}")
        return jsonify({'error': 'Unauthorized origin - iframe access only'}), 403

    # ------------------------------------------------------------------
    # iframe HTML
    # messageNonce = auth_value (nonce OR sessionToken depending on flow)
    # This value is used to validate every postMessage exchanged between
    # the parent Tampermonkey script and this iframe.
    # ------------------------------------------------------------------
    enable_rsa = 'true' if Config.ENABLE_RSA_AUTH else 'false'

    html_content = f"""<!DOCTYPE html>
<html>
<head>
    <title>SSE Relay</title>
    <meta charset="utf-8">
    <style>
        body {{ margin: 0; padding: 0; background: transparent; }}
        #status {{ font-family: monospace; font-size: 10px; color: #666; padding: 2px; }}
    </style>
</head>
<body>
    <div id="status">Connecting...</div>
    <script>
        var eventSource = null;
        var reconnectAttempts = 0;
        var maxReconnectAttempts = 5;
        var reconnectDelay = 2000;
        var parentOrigin = '{parent_origin}';
        var messageNonce = '{auth_value}';
        var enableRSAAuth = {enable_rsa};
        var broadcastKeyHex = '{broadcast_key_hex}';

        // Notify parent that iframe is ready
        if (window.parent && window.parent !== window) {{
            window.parent.postMessage({{
                type: 'iframe_ready',
                nonce: messageNonce,
                timestamp: Date.now()
            }}, parentOrigin);
        }}

        function connectSSE() {{
            var sseUrl = '/events?user={user}&token={iframe_token}';

            if (eventSource) {{
                eventSource.close();
            }}

            try {{
                eventSource = new EventSource(sseUrl);
                document.getElementById('status').textContent = 'Connecting to SSE...';

                eventSource.onopen = function(event) {{
                    document.getElementById('status').textContent = 'Connected';
                    reconnectAttempts = 0;
                    reconnectDelay = 2000;
                    if (window.parent && window.parent !== window) {{
                        window.parent.postMessage({{
                            type: 'iframe_sse_connected',
                            nonce: messageNonce,
                            bk: broadcastKeyHex,
                            timestamp: Date.now()
                        }}, parentOrigin);
                    }}
                }};

                eventSource.onmessage = function(event) {{
                    try {{
                        var data = JSON.parse(event.data);

                        if (data.type === 'ping' && data.connection_id) {{
                            fetch('/sse-pong?connection_id=' + data.connection_id + '&token={iframe_token}', {{
                                method: 'POST',
                                headers: {{ 'Content-Type': 'application/json' }}
                            }}).then(function(response) {{
                                if (response.ok) {{
                                    if (window.parent && window.parent !== window) {{
                                        window.parent.postMessage({{
                                            type: 'iframe_pong_success',
                                            nonce: messageNonce,
                                            timestamp: Date.now()
                                        }}, parentOrigin);
                                    }}
                                }} else if (response.status === 404) {{
                                    if (window.parent && window.parent !== window) {{
                                        window.parent.postMessage({{
                                            type: 'iframe_sse_error',
                                            attempt: 0,
                                            maxAttempts: 5,
                                            nonce: messageNonce,
                                            timestamp: Date.now()
                                        }}, parentOrigin);
                                    }}
                                }}
                            }}).catch(function() {{}});
                        }}

                        if (window.parent && window.parent !== window) {{
                            window.parent.postMessage({{
                                type: 'iframe_sse_message',
                                data: data,
                                nonce: messageNonce,
                                timestamp: Date.now()
                            }}, parentOrigin);
                        }}

                        if (data.type === 'connected') {{
                            document.getElementById('status').textContent = 'SSE Ready';
                        }} else if (data.type === 'ping') {{
                            document.getElementById('status').textContent = 'Connected (ping)';
                        }} else {{
                            document.getElementById('status').textContent = 'Message received';
                        }}
                    }} catch (e) {{}}
                }};

                eventSource.onerror = function(event) {{
                    document.getElementById('status').textContent = 'Connection error';

                    if (window.parent && window.parent !== window) {{
                        window.parent.postMessage({{
                            type: 'iframe_sse_error',
                            attempt: reconnectAttempts,
                            maxAttempts: maxReconnectAttempts,
                            nonce: messageNonce,
                            timestamp: Date.now()
                        }}, parentOrigin);
                    }}

                    fetch(sseUrl, {{ method: 'HEAD' }}).then(function(response) {{
                        var errorDetails = {{
                            type: 'iframe_sse_error',
                            attempt: reconnectAttempts,
                            maxAttempts: maxReconnectAttempts,
                            nonce: messageNonce,
                            timestamp: Date.now()
                        }};
                        if (response.status === 401) {{
                            errorDetails.statusCode = 401;
                            errorDetails.error = 'Unauthorized - token expired';
                        }} else if (response.status === 403) {{
                            errorDetails.statusCode = 403;
                            errorDetails.error = 'Forbidden';
                        }} else if (response.status === 402) {{
                            errorDetails.statusCode = 402;
                            errorDetails.error = 'Payment Required - Insufficient credits';
                        }}
                        if (window.parent && window.parent !== window) {{
                            window.parent.postMessage(errorDetails, parentOrigin);
                        }}
                    }}).catch(function() {{
                        if (window.parent && window.parent !== window) {{
                            window.parent.postMessage({{
                                type: 'iframe_sse_error',
                                attempt: reconnectAttempts,
                                maxAttempts: maxReconnectAttempts,
                                nonce: messageNonce,
                                timestamp: Date.now()
                            }}, parentOrigin);
                        }}
                    }});

                    if (reconnectAttempts < maxReconnectAttempts) {{
                        reconnectAttempts++;
                        var delay = reconnectAttempts === 1 ? 0 : reconnectDelay;
                        setTimeout(function() {{ connectSSE(); }}, delay);
                        reconnectDelay = Math.min(reconnectDelay * 1.5, 30000);
                    }} else {{
                        if (window.parent && window.parent !== window) {{
                            window.parent.postMessage({{
                                type: 'iframe_sse_failed',
                                nonce: messageNonce,
                                timestamp: Date.now()
                            }}, parentOrigin);
                        }}
                    }}
                }};

            }} catch (error) {{
                document.getElementById('status').textContent = 'Connection failed';
                if (window.parent && window.parent !== window) {{
                    window.parent.postMessage({{
                        type: 'iframe_sse_failed',
                        error: error.message,
                        nonce: messageNonce,
                        timestamp: Date.now()
                    }}, parentOrigin);
                }}
            }}
        }}

        // ----------------------------------------------------------------
        // convert_usd message handler
        // Old flow: receives plain fields, builds + sends plain JSON
        // New flow: receives pre-encrypted body, sends encrypted + Auth header
        // ----------------------------------------------------------------
        window.addEventListener('message', function(event) {{
            var allowedOrigins = [
                'https://stake.com', 'https://stake.ac', 'https://stake.games',
                'https://stake.bet', 'https://stake.pet', 'https://stake.mba',
                'https://stake.jp', 'https://stake.bz', 'https://stake.ceo',
                'https://stake.krd', 'https://staketr.com', 'https://stake.us',
                'https://stake.br', 'https://stake1001.com', 'https://stake1002.com',
                'https://stake1003.com', 'https://stake1021.com', 'https://stake1022.com'
            ];
            if (!allowedOrigins.includes(event.origin)) return;
            if (!event.data || event.data.type !== 'convert_usd') return;
            if (event.data.nonce !== messageNonce) return;

            var d = event.data;

            function doFetch(retryCount) {{
                if (enableRSAAuth && d.encrypted) {{
                    // New flow — body already AES-encrypted by Tampermonkey script
                    // Pass through as-is with session token in Authorization header
                    fetch('https://kciade.online/api/users/claims/convert-to-usd', {{
                        method: 'POST',
                        headers: {{
                            'Content-Type': 'application/json',
                            'Authorization': 'Bearer ' + messageNonce
                        }},
                        body: d.body
                    }}).catch(function() {{
                        if (retryCount < 1) {{
                            setTimeout(function() {{ doFetch(retryCount + 1); }}, 3000);
                        }}
                    }});
                }} else {{
                    // Old flow — plain JSON
                    if (!d.username || !d.amount || !d.target_currency) return;
                    fetch('https://kciade.online/api/users/claims/convert-to-usd', {{
                        method: 'POST',
                        headers: {{ 'Content-Type': 'application/json' }},
                        body: JSON.stringify({{
                            username: d.username,
                            target_currency: d.target_currency,
                            amount: parseFloat(d.amount),
                            code: d.code || ''
                        }})
                    }}).catch(function() {{
                        if (retryCount < 1) {{
                            setTimeout(function() {{ doFetch(retryCount + 1); }}, 3000);
                        }}
                    }});
                }}
            }}
            doFetch(0);
        }});

        connectSSE();
    </script>
</body>
</html>"""

    if Config.ENABLE_RSA_AUTH:
        # Encrypt the HTML — only client with valid session token can decrypt
        encrypted = _encrypt_html(html_content, auth_value)

        bootstrap = f"""<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body>
<script>
(async function() {{
    const token = '{auth_value}';
    const iv = Uint8Array.from(atob('{encrypted['iv']}'), c => c.charCodeAt(0));
    const data = Uint8Array.from(atob('{encrypted['data']}'), c => c.charCodeAt(0));

    const keyData = new TextEncoder().encode(token);
    const hashBuffer = await crypto.subtle.digest('SHA-256', keyData);
    const aesKey = await crypto.subtle.importKey(
        'raw', hashBuffer, {{name: 'AES-GCM'}}, false, ['decrypt']
    );

    const decrypted = await crypto.subtle.decrypt(
        {{name: 'AES-GCM', iv}}, aesKey, data
    );

    const html = new TextDecoder().decode(decrypted);
    document.open();
    document.write(html);
    document.close();
}})();
</script>
</body>
</html>"""

        response = Response(bootstrap, mimetype='text/html')
    else:
        response = Response(html_content, mimetype='text/html')

    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['X-Accel-Buffering'] = 'no'
    response.headers['Surrogate-Control'] = 'no-store'
    return response


@sse_bp.route('/events')
def stream_events():
    """Server-Sent Events endpoint for real-time code streaming."""
    if not Config.SSE_BROADCAST_ENABLED:
        return jsonify({'error': 'Service disabled', 'code': 'mode_disabled'}), 503
    user = request.args.get('user')
    token = request.args.get('token')
    origin = request.headers.get('Origin', '')
    referer = request.headers.get('Referer', '')

    _logger.info(
        f"EVENTS | user={user or 'MISSING'} | has_token={bool(token)} | "
        f"origin={origin or 'NONE'} | referer={referer[:60] if referer else 'NONE'}"
    )

    if not user or not token:
        _logger.warning(f"EVENTS | REJECTED: missing user/token | user={user}")
        return jsonify({'error': 'user and token parameters required', 'code': 'bad_request'}), 400
    if not validate_iframe_token(token, user):
        _logger.warning(f"EVENTS | user={user} | REJECTED: invalid/expired token")
        return jsonify({'error': 'Invalid or expired token', 'code': 'auth_invalid'}), 401

    user_record = _resolve_user_for_sse(user)
    if user_record and user_record.get('_db_error'):
        _logger.warning(f"EVENTS | user={user} | DB unreachable — 503")
        return jsonify({'error': 'Service temporarily unavailable', 'code': 'db_unavailable'}), 503
    if not user_record or not user_record.get('user_id'):
        _logger.warning(f"EVENTS | user={user} | REJECTED: unknown username")
        return jsonify({'error': 'Unknown username', 'code': 'user_not_found'}), 403
    # Cross-origin request with wrong origin — block immediately
    if origin and origin != 'https://kciade.online':
        _logger.warning(f"EVENTS | user={user} | REJECTED: bad origin={origin}")
        return jsonify({'error': 'Direct access not permitted'}), 403
    # No origin (same-origin or direct browser) — check referer
    if not origin and not referer.startswith('https://kciade.online'):
        _logger.warning(f"EVENTS | user={user} | REJECTED: bad referer={referer[:60]}")
        return jsonify({'error': 'Direct access not permitted'}), 403

    import string
    random_suffix = ''.join(random.choices(string.ascii_letters + string.digits, k=6))
    connection_id = f"{user}_{int(time.time())}_{random_suffix}"
    _aes_key = hashlib.sha256(token.encode('utf-8')).digest()[:16]
    sse_manager.add_connection(user, connection_id, aes_key=_aes_key)
    sse_manager.add_connection(user, connection_id)
    _logger.info(
        f"EVENTS | user={user} | ACCEPTED | conn_id={connection_id} | "
        f"total_sse_conns={sse_manager.get_connection_count()} | "
        f"sse_mgr_id={id(sse_manager)} | pid={os.getpid()}"
    )

    def event_generator():
        try:
            initial_message = {
                'type': 'connected',
                'message': 'SSE stream connected',
                'username': user,
                'timestamp': int(time.time()),
                'connection_id': connection_id
            }
            yield f"data: {json.dumps(initial_message)}\n\n"

            message_queue = sse_manager.get_message_queue(connection_id)
            if not message_queue:
                yield f"data: {json.dumps({'type': 'error', 'message': 'Failed to initialize message queue'})}\n\n"
                return

            last_ping_sent = time.time()
            last_keepalive_sent = time.time()
            last_auth_check = time.time()
            SSE_PING_INTERVAL = 15.0
            KEEPALIVE_INTERVAL = 15.0
            AUTH_CHECK_INTERVAL = 240.0 + random.uniform(0, 120.0)
            auth_fail_count = 0

            while True:
                if not sse_manager.get_message_queue(connection_id):
                    break

                current_time = time.time()
                if not Config.AUTH_DISABLED and current_time - last_auth_check > AUTH_CHECK_INTERVAL:
                    last_auth_check = current_time
                    user_record = _resolve_user_for_sse(user)
                    if user_record is None:
                        auth_fail_count += 1
                        if auth_fail_count >= 2:
                            break
                    else:
                        auth_fail_count = 0

                try:
                    try:
                        message = message_queue.get(timeout=5.0)
                        yield f"data: {json.dumps(message)}\n\n"
                        message_queue.task_done()
                    except queue.Empty:
                        current_time = time.time()

                        if current_time - last_ping_sent > SSE_PING_INTERVAL:
                            ping_message = {
                                'type': 'ping',
                                'timestamp': int(current_time),
                                'connection_id': connection_id
                            }
                            yield f"data: {json.dumps(ping_message)}\n\n"
                            last_ping_sent = current_time
                            if connection_id in sse_manager.connection_health:
                                sse_manager.connection_health[connection_id]['last_ping'] = current_time
                                sse_manager.connection_health[connection_id]['ping_count'] += 1

                        if current_time - last_keepalive_sent > KEEPALIVE_INTERVAL:
                            yield ": SSE keepalive\n\n"
                            last_keepalive_sent = current_time
                            if connection_id in sse_manager.connection_health:
                                sse_manager.connection_health[connection_id]['last_pong'] = current_time

                except Exception:
                    break

        finally:
            sse_manager.remove_connection(user, connection_id)

    return Response(
        event_generator(),
        mimetype='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'Connection': 'keep-alive',
            'X-Accel-Buffering': 'no',
            'Access-Control-Allow-Origin': 'https://kciade.online',
            'Access-Control-Allow-Headers': 'Cache-Control'
        }
    )


@sse_bp.route('/sse-pong', methods=['POST'])
def sse_pong():
    """Handle SSE heartbeat pong response."""
    if not Config.SSE_BROADCAST_ENABLED:
        return jsonify({'error': 'Service disabled', 'code': 'mode_disabled'}), 503
    connection_id = request.args.get('connection_id')
    token = request.args.get('token')

    if not connection_id or not token:
        return jsonify({'error': 'connection_id and token required'}), 400

    connection_owner = sse_manager.get_connection_username(connection_id)
    if not connection_owner:
        return jsonify({'error': 'Unknown connection_id', 'code': 'connection_unknown'}), 404

    if not validate_iframe_token(token, connection_owner):
        return jsonify({'error': 'Invalid or expired token', 'code': 'auth_invalid'}), 401

    allowed, retry_after = sse_manager.update_pong(connection_id, rate_limit_seconds=5.0)
    if not allowed:
        response = jsonify({
            'error': 'Rate limit exceeded',
            'detail': 'Only one pong is allowed every 10 seconds'
        })
        response.status_code = 429
        response.headers['Retry-After'] = f"{int(retry_after) if retry_after else 10}"
        return response

    return jsonify({'status': 'pong_received'}), 200


# ---------------------------------------------------------------------------
# /r2 — WebSocket transport iframe. Sibling of /embed-stream; identical
# auth/origin/rate-limit envelope, different inner transport.
# ---------------------------------------------------------------------------


@sse_bp.route('/r2', methods=['HEAD'])
def _r2_head():
    if not Config.SSE_BROADCAST_ENABLED:
        return ('', 503)
    user = request.args.get('user')
    if Config.ENABLE_RSA_AUTH:
        token = request.args.get('token')
        if not user or not token or not validate_iframe_token(token, user):
            return ('', 401)
    else:
        nonce = request.args.get('nonce')
        if not user or not nonce or not validate_timed_nonce(nonce, user, record=False):
            return ('', 401)
    return ('', 200)


@sse_bp.route('/r2')
@limiter.limit(
    _EMBED_STREAM_LIMIT,
    key_func=get_embed_stream_user_key,
    exempt_when=lambda: get_embed_stream_user_key() is None,
)
def _r2():
    gated = _mode_gate_503()
    if gated is not None:
        return gated
    user = request.args.get('user')
    client_ip = request.headers.get('CF-Connecting-IP') or request.remote_addr
    _logger.info(f"R2 | ip={client_ip} | user={user or 'MISSING'}")

    if not user:
        return jsonify({'error': 'user parameter required'}), 400

    if Config.ENABLE_RSA_AUTH:
        token = request.args.get('token')
        if not token or not validate_iframe_token(token, user):
            return jsonify({'error': 'Invalid or expired token', 'code': 'auth_invalid'}), 401
        auth_value = token
        internal_token_expiry = 1440
    else:
        nonce = request.args.get('nonce')
        if not nonce or not validate_timed_nonce(nonce, user):
            return jsonify({'error': 'Invalid or expired nonce', 'code': 'auth_invalid'}), 401
        auth_value = nonce
        internal_token_expiry = 1440

    user_agent = request.headers.get('User-Agent', '')
    if not user_agent or 'Mozilla' not in user_agent:
        return jsonify({'error': 'Unauthorized'}), 403

    is_rate_limited, retry_after = invalid_username_rate_limiter.check_rate_limit(user)
    if is_rate_limited:
        response = jsonify({
            'error': 'Rate limit exceeded',
            'detail': 'Too many attempts with invalid username. Please try again later.'
        })
        response.status_code = 429
        response.headers['Retry-After'] = f"{int(retry_after) if retry_after else 10}"
        return response

    user_record = _resolve_user_for_sse(user)
    if user_record and user_record.get('_db_error'):
        return jsonify({'error': 'Service temporarily unavailable', 'code': 'db_unavailable'}), 503
    if not user_record or not user_record.get('user_id'):
        invalid_username_rate_limiter.record_failed_attempt(user)
        return jsonify({'error': 'Unknown username', 'code': 'user_not_found'}), 403

    try:
        iframe_token = generate_iframe_token(user, expiry_minutes=internal_token_expiry)
    except ValueError:
        return jsonify({'error': 'Server configuration error'}), 500

    broadcast_key_hex = hashlib.sha256(iframe_token.encode('utf-8')).digest()[:16].hex()

    parent_origin = extract_parent_origin(request)
    if not parent_origin:
        host = request.host
        if host.startswith('localhost') or host.startswith('127.0.0.1'):
            parent_origin = f"http://{host}"
        else:
            return jsonify({'error': 'Unauthorized origin - iframe access only'}), 403
    if not is_origin_allowed(parent_origin):
        return jsonify({'error': 'Unauthorized origin - iframe access only'}), 403

    enable_rsa = 'true' if Config.ENABLE_RSA_AUTH else 'false'

    # postMessage contract preserved verbatim from /embed-stream:
    # iframe_ready, iframe_sse_connected (with bk), iframe_sse_message (data),
    # iframe_pong_success, iframe_sse_error (statusCode/error), iframe_sse_failed,
    # plus the convert_usd handler. Additive: iframe_disconnect teardown branch.
    html_content = f"""<!DOCTYPE html>
<html>
<head>
    <title>Relay</title>
    <meta charset="utf-8">
    <style>
        body {{ margin: 0; padding: 0; background: transparent; }}
        #status {{ font-family: monospace; font-size: 10px; color: #666; padding: 2px; }}
    </style>
    <script src="https://cdn.socket.io/4.5.4/socket.io.min.js" onerror="
        if (window.parent && window.parent !== window) {{
            window.parent.postMessage({{
                type: 'iframe_sse_failed',
                error: 'socket.io client load failed',
                nonce: '{auth_value}',
                timestamp: Date.now()
            }}, '{parent_origin}');
        }}
    "></script>
</head>
<body>
    <div id="status">Connecting...</div>
    <script>
        var socket = null;
        var reconnectAttempts = 0;
        var maxReconnectAttempts = 5;
        var reconnectDelay = 2000;
        var parentOrigin = '{parent_origin}';
        var messageNonce = '{auth_value}';
        var enableRSAAuth = {enable_rsa};
        var broadcastKeyHex = '{broadcast_key_hex}';
        var manualClose = false;

        if (window.parent && window.parent !== window) {{
            window.parent.postMessage({{
                type: 'iframe_ready',
                nonce: messageNonce,
                timestamp: Date.now()
            }}, parentOrigin);
        }}

        function postFailure(message) {{
            if (window.parent && window.parent !== window) {{
                window.parent.postMessage({{
                    type: 'iframe_sse_failed',
                    error: message || '',
                    nonce: messageNonce,
                    timestamp: Date.now()
                }}, parentOrigin);
            }}
        }}

        function connectWS() {{
            if (typeof io !== 'function') {{
                postFailure('io is not loaded');
                return;
            }}

            if (socket) {{
                try {{ socket.disconnect(); }} catch (e) {{}}
                socket = null;
            }}

            try {{
                socket = io('/_v', {{
                    transports: ['websocket'],
                    query: {{ user: '{user}', token: '{iframe_token}' }},
                    reconnection: false,
                    forceNew: true
                }});
                document.getElementById('status').textContent = 'Connecting...';

                socket.on('connect', function() {{
                    reconnectAttempts = 0;
                    reconnectDelay = 2000;
                    document.getElementById('status').textContent = 'Connected';
                    if (window.parent && window.parent !== window) {{
                        window.parent.postMessage({{
                            type: 'iframe_sse_connected',
                            nonce: messageNonce,
                            bk: broadcastKeyHex,
                            timestamp: Date.now()
                        }}, parentOrigin);
                    }}
                }});

                socket.on('connected', function(data) {{
                    if (window.parent && window.parent !== window) {{
                        window.parent.postMessage({{
                            type: 'iframe_sse_message',
                            data: data,
                            nonce: messageNonce,
                            timestamp: Date.now()
                        }}, parentOrigin);
                    }}
                }});

                socket.on('new_code', function(data) {{
                    if (window.parent && window.parent !== window) {{
                        window.parent.postMessage({{
                            type: 'iframe_sse_message',
                            data: data,
                            nonce: messageNonce,
                            timestamp: Date.now()
                        }}, parentOrigin);
                    }}
                }});

                socket.on('ping', function(data) {{
                    document.getElementById('status').textContent = 'Connected (ping)';
                    if (window.parent && window.parent !== window) {{
                        window.parent.postMessage({{
                            type: 'iframe_sse_message',
                            data: data || {{ type: 'ping', timestamp: Date.now() }},
                            nonce: messageNonce,
                            timestamp: Date.now()
                        }}, parentOrigin);
                        window.parent.postMessage({{
                            type: 'iframe_pong_success',
                            nonce: messageNonce,
                            timestamp: Date.now()
                        }}, parentOrigin);
                    }}
                }});

                socket.on('connect_error', function(err) {{
                    // auth invalidation: surface err.data.code (401/403/503) to parent
                    var code = (err && err.data && err.data.code) ? err.data.code : 0;
                    var message = (err && err.data && err.data.message)
                        ? err.data.message
                        : ((err && err.message) ? err.message : '');
                    var errorDetails = {{
                        type: 'iframe_sse_error',
                        attempt: reconnectAttempts,
                        maxAttempts: maxReconnectAttempts,
                        nonce: messageNonce,
                        timestamp: Date.now()
                    }};
                    if (code) errorDetails.statusCode = code;
                    if (message) errorDetails.error = message;
                    if (window.parent && window.parent !== window) {{
                        window.parent.postMessage(errorDetails, parentOrigin);
                    }}
                }});

                // reconnect handling: matches SSE iframe cadence (5 attempts, expo backoff)
                socket.on('disconnect', function(reason) {{
                    document.getElementById('status').textContent = 'Disconnected';
                    if (manualClose) return;
                    if (reason === 'io client disconnect') return;

                    if (reconnectAttempts < maxReconnectAttempts) {{
                        reconnectAttempts++;
                        var delay = reconnectAttempts === 1 ? 0 : reconnectDelay;
                        setTimeout(function() {{ connectWS(); }}, delay);
                        reconnectDelay = Math.min(reconnectDelay * 1.5, 30000);
                    }} else {{
                        postFailure('max reconnect attempts');
                    }}
                }});

            }} catch (error) {{
                document.getElementById('status').textContent = 'Connection failed';
                postFailure(error && error.message ? error.message : 'init failed');
            }}
        }}

        // iframe cleanup: parent signals graceful teardown via these types; must
        // run BEFORE the Stake-origin allowlist gate because these come from
        // kciade.online (IFRAME_ORIGIN), not a Stake origin.
        window.addEventListener('message', function(event) {{
            if (event.data && event.data.nonce === messageNonce && (
                event.data.type === 'iframe_disconnect' ||
                event.data.type === 'terminate_connection' ||
                event.data.type === 'close_sse' ||
                event.data.type === 'shutdown' ||
                event.data.type === 'stop_heartbeat'
            )) {{
                manualClose = true;
                try {{ if (socket) {{ socket.disconnect(); socket = null; }} }} catch (e) {{}}
                return;
            }}

            var allowedOrigins = [
                'https://stake.com', 'https://stake.ac', 'https://stake.games',
                'https://stake.bet', 'https://stake.pet', 'https://stake.mba',
                'https://stake.jp', 'https://stake.bz', 'https://stake.ceo',
                'https://stake.krd', 'https://staketr.com', 'https://stake.us',
                'https://stake.br', 'https://stake1001.com', 'https://stake1002.com',
                'https://stake1003.com', 'https://stake1021.com', 'https://stake1022.com'
            ];
            if (!allowedOrigins.includes(event.origin)) return;
            if (!event.data || event.data.type !== 'convert_usd') return;
            if (event.data.nonce !== messageNonce) return;

            var d = event.data;

            function doFetch(retryCount) {{
                if (enableRSAAuth && d.encrypted) {{
                    fetch('https://kciade.online/api/users/claims/convert-to-usd', {{
                        method: 'POST',
                        headers: {{
                            'Content-Type': 'application/json',
                            'Authorization': 'Bearer ' + messageNonce
                        }},
                        body: d.body
                    }}).catch(function() {{
                        if (retryCount < 1) {{
                            setTimeout(function() {{ doFetch(retryCount + 1); }}, 3000);
                        }}
                    }});
                }} else {{
                    if (!d.username || !d.amount || !d.target_currency) return;
                    fetch('https://kciade.online/api/users/claims/convert-to-usd', {{
                        method: 'POST',
                        headers: {{ 'Content-Type': 'application/json' }},
                        body: JSON.stringify({{
                            username: d.username,
                            target_currency: d.target_currency,
                            amount: parseFloat(d.amount),
                            code: d.code || ''
                        }})
                    }}).catch(function() {{
                        if (retryCount < 1) {{
                            setTimeout(function() {{ doFetch(retryCount + 1); }}, 3000);
                        }}
                    }});
                }}
            }}
            doFetch(0);
        }});

        if (typeof io === 'function') {{
            connectWS();
        }} else {{
            // socket.io client tag still loading; wait one tick
            setTimeout(function() {{
                if (typeof io === 'function') connectWS();
                else postFailure('io did not load');
            }}, 100);
        }}
    </script>
</body>
</html>"""

    if Config.ENABLE_RSA_AUTH:
        encrypted = _encrypt_html(html_content, auth_value)

        bootstrap = f"""<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body>
<script>
(async function() {{
    const token = '{auth_value}';
    const iv = Uint8Array.from(atob('{encrypted['iv']}'), c => c.charCodeAt(0));
    const data = Uint8Array.from(atob('{encrypted['data']}'), c => c.charCodeAt(0));

    const keyData = new TextEncoder().encode(token);
    const hashBuffer = await crypto.subtle.digest('SHA-256', keyData);
    const aesKey = await crypto.subtle.importKey(
        'raw', hashBuffer, {{name: 'AES-GCM'}}, false, ['decrypt']
    );

    const decrypted = await crypto.subtle.decrypt(
        {{name: 'AES-GCM', iv}}, aesKey, data
    );

    const html = new TextDecoder().decode(decrypted);
    document.open();
    document.write(html);
    document.close();
}})();
</script>
</body>
</html>"""

        response = Response(bootstrap, mimetype='text/html')
    else:
        response = Response(html_content, mimetype='text/html')

    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['X-Accel-Buffering'] = 'no'
    response.headers['Surrogate-Control'] = 'no-store'
    return response
