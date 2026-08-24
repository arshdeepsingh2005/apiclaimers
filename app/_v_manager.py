import os
import base64
import threading
import time
from collections import deque
from typing import Deque, Dict, List, Optional, Tuple
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


_CONNECT_RATE_MAX = 10        # per-IP attempts allowed
_CONNECT_RATE_WINDOW = 60.0   # seconds
_CONNECT_RATE_MAX_IPS = 20000 # hard cap on tracked IPs


class _VManager:
    """Per-SID broadcast clients on the /_v namespace."""

    def __init__(self):
        self._clients: Dict[str, dict] = {}
        self._lock = threading.Lock()
        # per-IP sliding window for /_v connect-flood protection
        self._connect_attempts: Dict[str, Deque[float]] = {}
        self._connect_attempts_lock = threading.Lock()

    def add_client(self, sid: str, username: str, aes_key: bytes, stop_event=None) -> None:
        with self._lock:
            self._clients[sid] = {
                'username': username,
                'aes_key': aes_key,
                'stop_event': stop_event,
                'connected_at': time.time(),
            }

    def remove_client(self, sid: str) -> Optional[dict]:
        # websocket disconnect cleanup: return record so caller can signal stop_event
        with self._lock:
            return self._clients.pop(sid, None)

    def get_client(self, sid: str) -> Optional[dict]:
        with self._lock:
            return self._clients.get(sid)

    def usernames(self) -> set:
        with self._lock:
            return {rec['username'] for rec in self._clients.values() if rec.get('username')}

    def all_sids(self) -> List[Tuple[str, str]]:
        with self._lock:
            return [(sid, rec.get('username', '')) for sid, rec in self._clients.items()]

    def _encrypt_for_client(self, payload: dict, aes_key: bytes) -> dict:
        msg = payload.copy()
        code = msg.pop('code', None)
        if not code:
            return msg
        try:
            iv = os.urandom(12)
            ciphertext = AESGCM(aes_key).encrypt(iv, code.encode('utf-8'), None)
            msg['kod'] = base64.b64encode(ciphertext).decode('ascii')
            msg['iv'] = base64.b64encode(iv).decode('ascii')
        except Exception:
            msg['code'] = code
        return msg

    def build_per_client_payloads(self, code_data: dict) -> List[Tuple[str, dict]]:
        with self._lock:
            snapshot = list(self._clients.items())
        out: List[Tuple[str, dict]] = []
        for sid, rec in snapshot:
            aes_key = rec.get('aes_key')
            if not aes_key:
                continue
            out.append((sid, self._encrypt_for_client(code_data, aes_key)))
        return out

    def get_connection_count(self) -> int:
        with self._lock:
            return len(self._clients)

    def check_connect_rate(self, client_ip: str) -> Tuple[bool, float]:
        """Sliding-window per-IP connect rate limit. Returns (allowed, retry_after)."""
        if not client_ip:
            return True, 0.0
        now = time.time()
        cutoff = now - _CONNECT_RATE_WINDOW
        with self._connect_attempts_lock:
            # Periodic global trim if the map grows unbounded under abuse
            if len(self._connect_attempts) > _CONNECT_RATE_MAX_IPS:
                drop = [ip for ip, dq in self._connect_attempts.items()
                        if not dq or dq[-1] < cutoff]
                for ip in drop:
                    self._connect_attempts.pop(ip, None)

            dq = self._connect_attempts.get(client_ip)
            if dq is None:
                dq = deque()
                self._connect_attempts[client_ip] = dq

            while dq and dq[0] < cutoff:
                dq.popleft()

            if len(dq) >= _CONNECT_RATE_MAX:
                retry_after = max(0.0, _CONNECT_RATE_WINDOW - (now - dq[0]))
                return False, retry_after

            dq.append(now)
            return True, 0.0


_v_manager = _VManager()
