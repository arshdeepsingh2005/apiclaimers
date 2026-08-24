import os
import base64
import queue
import threading
import time
from collections import defaultdict
from typing import Dict, List, Optional
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

"""
SSE (Server-Sent Events) connection and message broadcasting manager.
"""


class SSEManager:
    """Manages SSE connections and code broadcasting."""
    
    def __init__(self, max_connections: Optional[int] = None):
        # username -> list of connection IDs
        self.connections: Dict[str, List[str]] = defaultdict(list)
        # connection_id -> message queue (each connection has its own queue)
        self.message_queues: Dict[str, queue.Queue] = {}
        # connection_id -> health tracking
        self.connection_health: Dict[str, dict] = {}
        self.suspended_connections: set = set()
        self.connection_keys: Dict[str, bytes] = {}
        self.lock = threading.Lock()
        self.max_queue_size = 100
        self.max_connections = max_connections
    
    def add_connection(self, username: str, connection_id: str, aes_key: bytes = b'') -> None:
        """
        Add a new SSE connection for a user.
        Allows multiple connections per username - all will receive broadcasted codes.
        Username must exist in database (validated before calling this method).
        Each connection gets its own message queue for independent message delivery.
        """
        with self.lock:
            # Check connection limit (if set)
            if self.max_connections is not None:
                current_count = sum(len(conns) for conns in self.connections.values())
                if current_count >= self.max_connections:
                    raise RuntimeError(f"Maximum SSE connections ({self.max_connections}) reached")
            
            # Create dedicated message queue for this connection
            if connection_id not in self.message_queues:
                self.message_queues[connection_id] = queue.Queue(maxsize=self.max_queue_size)
            
            # Add new connection (allow multiple connections per username)
            if connection_id not in self.connections[username]:
                self.connections[username].append(connection_id)
            
            # Initialize health tracking
            self.connection_health[connection_id] = {
                'username': username,
                'last_ping': 0,
                'last_pong': time.time(),
                'last_rate_limited_pong': 0,
                'ping_count': 0
            }
            
            if aes_key:
                self.connection_keys[connection_id] = aes_key
    
    def remove_connection(self, username: str, connection_id: str) -> None:
        """Remove an SSE connection."""
        with self.lock:
            if username in self.connections:
                if connection_id in self.connections[username]:
                    self.connections[username].remove(connection_id)
                
                # Clean up if no more connections for this username
                if not self.connections[username]:
                    del self.connections[username]
            
            # Clean up connection-specific message queue
            if connection_id in self.message_queues:
                del self.message_queues[connection_id]
            
            # Clean up health tracking
            if connection_id in self.connection_health:
                del self.connection_health[connection_id]

            self.suspended_connections.discard(connection_id)
            self.connection_keys.pop(connection_id, None)
    
    def suspend_connection(self, connection_id: str) -> None:
        with self.lock:
            self.suspended_connections.add(connection_id)

    def _encrypt_for_connection(self, payload: dict, aes_key: bytes) -> dict:
        """AES-128-GCM encrypt the 'code' field. All other fields pass through."""
        msg = payload.copy()
        code = msg.pop('code', None)
        if not code:
            return msg
        try:
            iv = os.urandom(12)
            ciphertext = AESGCM(aes_key).encrypt(iv, code.encode('utf-8'), None)
            msg['kod'] = base64.b64encode(ciphertext).decode('ascii')
            msg['iv']  = base64.b64encode(iv).decode('ascii')
        except Exception:
            msg['code'] = code  # fallback: plaintext rather than silent drop
        return msg

    def broadcast_code(self, code_data: dict) -> None:
        """
        Broadcast code to ALL connected SSE clients (regardless of username).
        Admin sends code and all connected users receive it.
        Username in code_data is only for tracking/logging, not for filtering.

        Logging is intentionally absent here — websocket_manager.broadcast_code
        emits a unified BROADCAST line covering SSE + WS + V counts so a single
        broadcast cycle produces exactly one log entry.
        """
        message = code_data.copy()

        with self.lock:
            all_connection_ids = []
            for username, conn_ids in self.connections.items():
                all_connection_ids.extend(conn_ids)

            if not all_connection_ids:
                return

            for connection_id in all_connection_ids:
                if connection_id in self.suspended_connections:
                    continue
                if connection_id not in self.message_queues:
                    continue
                aes_key = self.connection_keys.get(connection_id)
                outbound = self._encrypt_for_connection(message, aes_key) if aes_key else message
                try:
                    self.message_queues[connection_id].put_nowait(outbound)
                except queue.Full:
                    pass
    
    def get_message_queue(self, connection_id: str) -> Optional[queue.Queue]:
        """Get message queue for a specific connection."""
        with self.lock:
            return self.message_queues.get(connection_id)
    
    def update_pong(self, connection_id: str, rate_limit_seconds: float = 10.0):
        """
        Update last pong time while enforcing a minimum interval between pongs.
        
        Returns:
            (allowed: bool, retry_after: float)
        """
        with self.lock:
            health = self.connection_health.get(connection_id)
            if not health:
                return False, rate_limit_seconds
            
            now = time.time()
            health['last_pong'] = now
            last_rate_limited = health.get('last_rate_limited_pong', 0)
            
            if last_rate_limited and (now - last_rate_limited) < rate_limit_seconds:
                retry_after = rate_limit_seconds - (now - last_rate_limited)
                return False, max(retry_after, 0.0)
            
            health['last_rate_limited_pong'] = now
            health['last_pong'] = now
            return True, 0.0

    def get_connection_username(self, connection_id: str) -> Optional[str]:
        """Return the username that owns the given connection id."""
        with self.lock:
            health = self.connection_health.get(connection_id)
            if health:
                return health.get('username')
            return None
    
    def get_connection_count(self) -> int:
        """Get total number of active SSE connections."""
        with self.lock:
            return sum(len(conns) for conns in self.connections.values())
    
    def cleanup_stale_connections(self, timeout_seconds: int = 120) -> int:
        """
        Remove connections that haven't responded to pings.
        
        Args:
            timeout_seconds: Time in seconds since last pong before considering connection stale
            
        Returns:
            Number of connections cleaned up
        """
        current_time = time.time()
        stale_connections = []
        
        with self.lock:
            for connection_id, health in list(self.connection_health.items()):
                time_since_pong = current_time - health.get('last_pong', 0)
                if time_since_pong > timeout_seconds:
                    stale_connections.append((health.get('username'), connection_id))
        
        # Remove stale connections
        for username, conn_id in stale_connections:
            self.remove_connection(username, conn_id)
        
        return len(stale_connections)
    
    def get_stats(self) -> dict:
        """Get statistics about SSE connections."""
        with self.lock:
            total_queued = sum(
                q.qsize() for q in self.message_queues.values()
            )
            # Count connections per user
            connections_per_user = {user: len(conns) for user, conns in self.connections.items()}
            return {
                'active_connections': self.get_connection_count(),
                'users_with_connections': len(self.connections),
                'total_queued_messages': total_queued,
                'total_health_tracked': len(self.connection_health),
                'connections_per_user': connections_per_user
            }


# Global instance - unlimited connections
sse_manager = SSEManager(max_connections=None)
