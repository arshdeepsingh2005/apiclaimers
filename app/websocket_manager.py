"""
WebSocket connection and code broadcasting manager.
"""
import hashlib
import logging
import threading
import time
from datetime import datetime
from typing import Optional

# Module-level (not per-broadcast) — value_override has no app dependencies, so
# there is no circular-import reason to import it inline on the hot path.
from app.value_override import value_for_code
# runtime_settings imports only app.config (no cycle); module-level keeps the
# /everycodesame read off the inline-import path, same rationale as above.
from app.utils import runtime_settings

logger = logging.getLogger(__name__)


class WebSocketManager:
    """Manages WebSocket connections and code broadcasting."""
    
    def __init__(self, deduplication_window_seconds: int = 2):
        self.clients = {}  # {sid: {'namespace': str, 'username': str, 'connected_at': datetime}}
        self.code_history = []  # Store recent codes
        self.max_history = 100
        
        # Deduplication: track recently broadcast codes to prevent duplicates
        # Format: {code_hash: timestamp}
        self._recent_codes: dict[str, float] = {}
        self._deduplication_window = deduplication_window_seconds
        self._deduplication_lock = threading.Lock()
    
    def add_client(self, sid, namespace='default', user=None):
        """Add a client to the manager."""
        self.clients[sid] = {
            'namespace': namespace,
            'username': user.get('username') if isinstance(user, dict) else None,
            'user_id': user.get('user_id') if isinstance(user, dict) else None,
            'connected_at': datetime.now()
        }
    
    def remove_client(self, sid):
        """Remove a client from the manager."""
        if sid in self.clients:
            del self.clients[sid]

    def get_client(self, sid) -> Optional[dict]:
        """Return client metadata if connected."""
        return self.clients.get(sid)
    
    def _generate_code_hash(self, code_value: str) -> str:
        """Generate a hash for the code value for deduplication."""
        return hashlib.sha256(code_value.encode('utf-8')).hexdigest()
    
    def _cleanup_old_codes(self, current_time: float):
        """
        Remove codes older than deduplication window.
        Efficiently removes expired entries to prevent memory growth.
        
        Args:
            current_time: Current timestamp to use for comparison
        """
        cutoff_time = current_time - self._deduplication_window
        
        with self._deduplication_lock:
            # Efficiently remove expired entries
            expired_keys = [
                code_hash for code_hash, timestamp in self._recent_codes.items()
                if timestamp < cutoff_time
            ]
            for key in expired_keys:
                del self._recent_codes[key]
    
    def is_code_duplicate(self, code_value: str) -> bool:
        """
        Check if a code was recently broadcast (within deduplication window).
        Automatically cleans up expired entries on every check to prevent memory growth.
        
        Args:
            code_value: The code string to check
            
        Returns:
            True if code is a duplicate (within window), False otherwise
        """
        if not code_value:
            return False

        # Admin /everycodesame toggle: when ON, dedup case-insensitively by hashing
        # a casefolded copy (ABC123 == abc123). The dedup KEY is normalized here
        # only — `broadcast_code` still sends the original `code_data['code']`
        # untouched, so users receive the exact casing as detected. Default OFF ->
        # raw `code_value` -> identical to the prior case-sensitive behavior. The
        # same normalized key is used for both the lookup and the store below.
        key_value = code_value.casefold() if runtime_settings.get_every_code_same() else code_value

        code_hash = self._generate_code_hash(key_value)
        current_time = time.time()
        
        # Clean up expired entries on every check (prevents memory growth)
        self._cleanup_old_codes(current_time)
        
        with self._deduplication_lock:
            if code_hash in self._recent_codes:
                last_broadcast_time = self._recent_codes[code_hash]
                time_since_broadcast = current_time - last_broadcast_time
                
                if time_since_broadcast < self._deduplication_window:
                    return True
            
            # Mark code as broadcast (update timestamp)
            self._recent_codes[code_hash] = current_time
            return False
    
    def broadcast_code(self, code_data, socketio_instance=None, source=None):
        """
        Broadcast code to all connected clients (both Socket.IO and SSE).
        Includes deduplication check to prevent duplicate broadcasts within the window.
        
        Args:
            code_data: Dictionary containing code information
            socketio_instance: SocketIO instance to use for broadcasting
            
        Returns:
            bool: True if code was broadcast, False if it was a duplicate
        """
        # Extract code value for deduplication
        code_value = code_data.get('code', '')
        if not code_value:
            return False
        
        # Check for duplicates (within deduplication window)
        if self.is_code_duplicate(code_value):
            return False

        # Persistent admin "value for next code" override (isolated feature; see
        # app/value_override.py). Single decision point: inject a default `value`
        # into eligible codes only — never overwrites an existing value, never
        # touches stakecom/stakepy/staketr codes, no-op when disabled. Mutates
        # this request-local code_data in place so every transport below sees it.
        try:
            _inj = value_for_code(code_value, code_data.get('value'))
            if _inj is not None:
                code_data['value'] = _inj
        except Exception:
            logger.exception(
                "value_override injection failed; broadcasting code unchanged")

        # Exact broadcast instant on the server clock — reported to the admin in
        # IST (millisecond precision) once the dispatch below completes.
        _broadcast_epoch = time.time()

        # Add timestamp if not present
        if 'timestamp' not in code_data:
            code_data['timestamp'] = datetime.now().isoformat()
        
        # Store in history
        self.code_history.append(code_data)
        if len(self.code_history) > self.max_history:
            self.code_history.pop(0)
        
        from app.config import Config

        # Track /_tmc deliveries for the unified BROADCAST log line below
        tmc_delivered = 0

        # Broadcast to Socket.IO clients
        if socketio_instance:
            # /_tmc license fanout — required so panel broadcasts reach
            # licensed users when SSE is off. Reuses the existing
            # `fromTele` / task=drop event the client already handles.
            #
            # Hybrid path:
            #   RSA off → ONE namespace-wide emit (O(1), <1ms for 1000 clients)
            #   RSA on  → per-SID encrypted loop (correctness over speed)
            if Config.V_BROADCAST_ENABLED:
                try:
                    from app.routes.tmc_routes import _mark_bonus_code, _schedule_or_extend
                    # F-report: open the response-report window BEFORE the global
                    # fan-out below, so a fast client's userClaim (folded in a
                    # separate greenlet while the per-SID loop is still running)
                    # is not lost. No-op unless an admin is configured. Isolated
                    # so a report-hook failure can NEVER suppress the broadcast.
                    try:
                        _schedule_or_extend(code_value)
                    except Exception:
                        logger.exception("F-report schedule failed (ignored)")
                    _bcast_bonus = str(code_data.get('couponType') or '').strip().lower() == 'bonus'
                    if _bcast_bonus:
                        # Remember broadcast bonus codes so claims for them are
                        # excluded from license totals even from old scripts.
                        _mark_bonus_code(code_value)
                    base_payload = {
                        'task': 'drop',
                        'code': code_value,
                        'couponType': 'bonus' if _bcast_bonus else 'drop',
                        'value': code_data.get('value'),
                    }
                    if not Config.ENABLE_RSA_AUTH:
                        try:
                            socketio_instance.emit(
                                'fromTele', base_payload, namespace='/_tmc'
                            )
                            tmc_delivered = -1  # sentinel: namespace-wide
                        except Exception:
                            pass
                    else:
                        # RSA on: ONE atomic snapshot of (lk, sid, bk_ver); encrypt
                        # ONCE with the shared BK; one emit per sid. bk_ver (read once
                        # per sid) is the single delivery signal: set -> the shared BK
                        # envelope (identical for all, no per-SID field, matching the
                        # RSA-off namespace emit); None -> a per-connection wrap.
                        from app.license_manager import (
                            encrypt_broadcast, snapshot_global_delivery,
                        )
                        from app.routes.tmc_routes import _wrap
                        # fanout_ms = worker time first->last emit (the O(N) cost /
                        # server-side spread; NOT clients' true received times).
                        # monotonic (not time.time) so a clock/NTP step can't yield
                        # a negative duration.
                        _fan_t0 = time.monotonic()
                        env = encrypt_broadcast(base_payload)
                        rows = snapshot_global_delivery()
                        bk_n = legacy_n = 0
                        for lk, sid, bk_ver in rows:
                            if bk_ver:
                                outbound = env
                                bk_n += 1
                            else:
                                outbound = _wrap({**base_payload, 'license': lk}, sid)
                                legacy_n += 1
                            try:
                                socketio_instance.emit(
                                    'fromTele', outbound,
                                    to=sid, namespace='/_tmc'
                                )
                                tmc_delivered += 1
                            except Exception:
                                pass
                        logger.info(
                            f"TMC | GLOBAL DROP code={code_value[:32]} "
                            f"clients={len(rows)} bk={bk_n} legacy={legacy_n} "
                            f"delivered={tmc_delivered} mode=snapshot "
                            f"fanout_ms={(time.monotonic() - _fan_t0) * 1000.0:.1f}"
                        )
                except Exception:
                    pass

            # Broadcast to /events namespace (code listeners)
            socketio_instance.emit('new_code', code_data, room='code_listeners', namespace='/events')

            # Also broadcast to default namespace
            socketio_instance.emit('new_code', code_data)

            # /_v broadcast — per-SID, per-connection AES-128-GCM encryption
            if Config.V_BROADCAST_ENABLED:
                try:
                    from app._v_manager import _v_manager
                    for sid, outbound in _v_manager.build_per_client_payloads(code_data):
                        try:
                            socketio_instance.emit('new_code', outbound, to=sid, namespace='/_v')
                        except Exception:
                            pass
                except Exception:
                    pass

        # rollback flag: SSE_BROADCAST_ENABLED gates the legacy SSE transport
        if Config.SSE_BROADCAST_ENABLED:
            from app.sse_manager import sse_manager
            sse_manager.broadcast_code(code_data)

        # Logging + admin alert are deferred OFF the broadcast hot path.
        #
        # Both are pure observability: the unified BROADCAST log line and the
        # admin "code broadcast" Telegram alert. The alert goes through
        # notify_broadcast -> detached curl, whose subprocess.Popen is a real
        # os.fork (eventlet is monkey_patch(os=False)) that would otherwise run
        # synchronously in THIS greenlet — ~1-5ms blocking the dispatch and the
        # next ingested code. Running them in a background task lets this
        # greenlet return immediately after the emits/SSE puts above.
        #
        # _broadcast_epoch is captured at the true broadcast instant (above) and
        # passed through, so the alert's reported IST time stays exact even
        # though it is sent a few ms later. tmc_delivered already holds its final
        # value here. Both blocks keep their original try/except so they can
        # never raise into the scheduler.
        def _admin_alert_task():
            # Admin alert: tell the operator this code was broadcast to all users,
            # with the exact broadcast time in IST (millisecond precision). Sent
            # FIRST and on its OWN task so it never waits behind the lock-heavy
            # log-count gathering below (that ordering was the "very delayed"
            # cause). Best-effort; can never raise into the scheduler.
            try:
                from app.utils.telegram import notify_broadcast
                _coupon_type = (code_data.get('couponType') or '').strip().lower() or None
                # Value as actually broadcast (post-override-injection); None when
                # the code carried no value. Read here on the deferred task, so it
                # adds nothing to the broadcast fan-out.
                _value = code_data.get('value')
                notify_broadcast(code_value, _broadcast_epoch, source,
                                 coupon_type=_coupon_type, value=_value)
            except Exception:
                pass

        def _broadcast_log_task():
            # Unified broadcast log — one line per dispatch covering all transports
            try:
                import logging
                from app.sse_manager import sse_manager as _sse
                from app._v_manager import _v_manager as _vm
                from app.license_manager import active_sessions, _sessions_lock
                sse_n = _sse.get_connection_count()
                ws_n = self.get_client_count()
                v_n = _vm.get_connection_count()
                if tmc_delivered == -1:
                    # Namespace-wide emit — count is the size of the /_tmc session registry
                    with _sessions_lock:
                        tmc_count = sum(len(b) for b in active_sessions.values())
                    tmc_field = f"ns-broadcast({tmc_count})"
                    tmc_total = tmc_count
                else:
                    tmc_field = str(tmc_delivered if Config.V_BROADCAST_ENABLED else 0)
                    tmc_total = tmc_delivered if Config.V_BROADCAST_ENABLED else 0
                logging.getLogger(__name__).info(
                    f"BROADCAST | code={code_value} | "
                    f"SSE={sse_n} | WS={ws_n} | V={v_n} | TMC={tmc_field} | "
                    f"TOTAL={sse_n + ws_n + v_n + tmc_total}"
                )
            except Exception:
                pass

        # Both scheduled OFF the hot path (0 ms added to the fan-out). The admin
        # alert is scheduled FIRST and independently so it fires instantly rather
        # than queuing behind the log task's lock. start_background_task is
        # async-mode-safe (eventlet in prod, threading in dev). Fall back to
        # inline only when no socketio instance was provided.
        if socketio_instance:
            socketio_instance.start_background_task(_admin_alert_task)
            socketio_instance.start_background_task(_broadcast_log_task)
        else:
            _admin_alert_task()
            _broadcast_log_task()

        return True
    
    def get_client_count(self):
        """Get the number of connected clients."""
        return len(self.clients)
    
    def get_code_history(self, limit=10):
        """Get recent code history."""
        return self.code_history[-limit:]


# Global instance
websocket_manager = WebSocketManager()
