"""
License lifecycle, JWT issuance/validation, /_tmc session bookkeeping,
and AES-128-GCM payload encryption helpers for v3.1 §B.

Single-worker eventlet only. All state is in-process. Thread-safe via
RLocks. JWT uses HS256 with a jti for revocation before expiry.
"""
import base64
import itertools
import json
import logging
import os
import threading
import time
import uuid
from collections import deque
from typing import Deque, Dict, Optional, Tuple

import jwt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.config import Config

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Active license cache — loaded at startup from DB and kept current by the
# License-Activation-Scanner. Keys are license_key strings.
# ---------------------------------------------------------------------------
active_license_cache: Dict[str, dict] = {}
_cache_lock = threading.RLock()


# ---------------------------------------------------------------------------
# Active /_tmc sessions — {license_key: {sid: {username, telegram_id, jti,
# connected_at}}}. add/remove must keep the inner dict consistent under lock.
# ---------------------------------------------------------------------------
active_sessions: Dict[str, Dict[str, dict]] = {}
_sessions_lock = threading.RLock()


# ---------------------------------------------------------------------------
# JTI denylist — revoke tokens before their natural expiry (S-02). Keyed by
# jti string; value is the original token exp ts so we can prune.
# ---------------------------------------------------------------------------
_jti_denylist: Dict[str, float] = {}
_jti_lock = threading.Lock()


# ---------------------------------------------------------------------------
# Per-SID AES-128 session keys for /_tmc payload encryption (§B). Populated
# only when ENABLE_RSA_AUTH=true. Cleared on disconnect.
# ---------------------------------------------------------------------------
_tmc_session_keys: Dict[str, bytes] = {}
_tmc_session_keys_lock = threading.Lock()

# ---------------------------------------------------------------------------
# Shared broadcast key (BK) — one AES-128-GCM key held by every /_tmc client, so
# an encrypted broadcast is encrypted ONCE and reused for every BK-capable sid
# (per-SID emit driven by a single snapshot; no Socket.IO rooms), instead of a
# per-client AES encryption. Only used when ENABLE_RSA_AUTH=true. Delivered to each
# client wrapped in that client's per-connection key (never in cleartext).
#
# NONCE INVARIANT (critical for AES-GCM): the broadcast nonce is a strictly-
# increasing counter that is NEVER reset for the life of the process. next() on an
# itertools.count is a single atomic C call under the cooperative single eventlet
# worker, so every encrypt_broadcast() gets a distinct 96-bit nonce and no
# (BK, nonce) pair can ever recur — even across a BK rotation (the counter keeps
# climbing). This is why we do NOT rely on random-IV birthday bounds here.
# ---------------------------------------------------------------------------
_broadcast_key: bytes = os.urandom(16)
_broadcast_key_version: int = 1
_bk_nonce_ctr = itertools.count()          # never reset; see NONCE INVARIANT above


# ---------------------------------------------------------------------------
# Global connect token bucket (R-03) — caps server-wide /_tmc connect rate
# regardless of which IP. Single-worker only; resets each second.
# ---------------------------------------------------------------------------
_GLOBAL_CONNECT_PER_SEC = 50
_global_bucket_lock = threading.Lock()
_global_bucket: Deque[float] = deque()


def _try_global_connect() -> bool:
    """True if a global connect slot is available this 1-second window."""
    now = time.time()
    with _global_bucket_lock:
        while _global_bucket and _global_bucket[0] < now - 1.0:
            _global_bucket.popleft()
        if len(_global_bucket) >= _GLOBAL_CONNECT_PER_SEC:
            return False
        _global_bucket.append(now)
        return True


# ---------------------------------------------------------------------------
# Public surface
# ---------------------------------------------------------------------------

def rebuild_cache_from_db() -> int:
    """Load all active + non-banned licenses into the cache. Returns count."""
    from app.database import SessionLocal, ensure_license_columns, ensure_payments_table
    from app.models import License
    from sqlalchemy import select

    # Ensure the prepaid-balance columns exist before we SELECT them. This runs
    # at boot (all three entrypoints call rebuild_cache_from_db before starting
    # the scanner), so every later balance read/write is safe. Best-effort.
    ensure_license_columns()
    # Ensure the OxaPay payments table exists before any top-up/webhook request.
    ensure_payments_table()

    loaded = 0
    try:
        with SessionLocal() as session:
            rows = session.execute(
                select(
                    License.license_key, License.telegram_id,
                    License.maximum_usernames, License.theclaimers_count, License.banned,
                    License.manager_id, License.available_balance,
                    License.deduction_percentage,
                ).where(License.active.is_(True), License.banned.is_(False))
            ).all()
            with _cache_lock:
                active_license_cache.clear()
                for lic in rows:
                    active_license_cache[lic.license_key] = {
                        'active': True,
                        'telegram_id': int(lic.telegram_id),
                        'maximum_usernames': int(lic.maximum_usernames or Config.MAX_CONNECTIONS_PER_LICENSE),
                        'theclaimers_count': int(lic.theclaimers_count or 0),
                        'banned': bool(lic.banned),
                        'manager_id': (lic.manager_id or ''),
                        'available_balance': (float(lic.available_balance) if lic.available_balance is not None else 0.0),
                        'deduction_percentage': (float(lic.deduction_percentage) if lic.deduction_percentage is not None else None),
                    }
                    loaded += 1
    except Exception as exc:
        logger.warning(f"rebuild_cache_from_db: {exc}")
    return loaded


def is_license_active(license_key: str) -> bool:
    with _cache_lock:
        entry = active_license_cache.get(license_key)
        if entry is not None:
            return bool(entry.get('active') and not entry.get('banned'))

    # Cache miss — defensive one-shot DB lookup. Closes the race during the
    # brief window between worker boot and rebuild_cache_from_db() completing,
    # so legitimate clients reconnecting during a backend restart don't get
    # a false 403 and lock into terminal state.
    if not license_key or not license_key.startswith('THECLAIMERS-'):
        return False
    try:
        from app.database import SessionLocal
        from app.models import License
        from sqlalchemy import select
        with SessionLocal() as session:
            lic = session.execute(
                select(License).where(License.license_key == license_key)
            ).scalar_one_or_none()
            if not lic:
                return False
            entry = {
                'active': bool(lic.active),
                'telegram_id': int(lic.telegram_id),
                'maximum_usernames': int(lic.maximum_usernames or Config.MAX_CONNECTIONS_PER_LICENSE),
                'theclaimers_count': int(lic.theclaimers_count or 0),
                'banned': bool(lic.banned),
                'manager_id': (getattr(lic, 'manager_id', '') or ''),
                'available_balance': (float(getattr(lic, 'available_balance', 0) or 0)),
                'deduction_percentage': (float(lic.deduction_percentage) if getattr(lic, 'deduction_percentage', None) is not None else None),
            }
            with _cache_lock:
                active_license_cache[license_key] = entry
            return entry['active'] and not entry['banned']
    except Exception as exc:
        logger.warning(f"is_license_active DB fallback failed: {exc}")
        return False


def get_license_cache_entry(license_key: str) -> Optional[dict]:
    with _cache_lock:
        entry = active_license_cache.get(license_key)
        return dict(entry) if entry else None


def upsert_license_cache(license_key: str, entry: dict) -> None:
    with _cache_lock:
        active_license_cache[license_key] = entry


def remove_license_cache(license_key: str) -> None:
    with _cache_lock:
        active_license_cache.pop(license_key, None)


def revoke_license_sessions(license_key: str) -> list:
    """
    Revoke all JTIs for a license's active sessions (adds to denylist).
    Returns the list of (sid, telegram_id) pairs caller should disconnect.
    """
    out = []
    now = time.time()
    with _sessions_lock:
        sessions = dict(active_sessions.get(license_key, {}))
    for sid, info in sessions.items():
        jti = info.get('jti')
        if jti:
            add_to_denylist(jti, now + Config.LICENSE_TOKEN_EXPIRY_SECONDS)
        out.append((sid, info.get('telegram_id')))
    return out


# ---------------------------------------------------------------------------
# Sessions
# ---------------------------------------------------------------------------

def add_session(license_key: str, sid: str, username: str,
                telegram_id: int, jti: str, ip: str = None,
                version: str = None, claimer_id: str = None,
                claimer_name: str = None) -> None:
    with _sessions_lock:
        bucket = active_sessions.setdefault(license_key, {})
        bucket[sid] = {
            'username': username,
            'telegram_id': telegram_id,
            'jti': jti,
            'connected_at': time.time(),
            'ip': ip,
            'version': version,
            'claimer_id': claimer_id,
            'claimer_name': claimer_name,
            'bk_ver': None,        # shared-broadcast-key version this sid holds (None = legacy)
        }


def remove_session(sid: str) -> Optional[dict]:
    """Remove session by sid; returns the stored record including license_key."""
    with _sessions_lock:
        for license_key, bucket in list(active_sessions.items()):
            if sid in bucket:
                record = bucket.pop(sid)
                record['license_key'] = license_key
                if not bucket:
                    active_sessions.pop(license_key, None)
                return record
    return None


def get_session_by_sid(sid: str) -> Optional[dict]:
    with _sessions_lock:
        for license_key, bucket in active_sessions.items():
            if sid in bucket:
                rec = dict(bucket[sid])
                rec['license_key'] = license_key
                return rec
    return None


def get_session_count(license_key: str) -> int:
    with _sessions_lock:
        return len(active_sessions.get(license_key, {}))


def get_unique_username_count(license_key: str) -> int:
    with _sessions_lock:
        sessions = active_sessions.get(license_key, {})
        return len({s.get('username') for s in sessions.values() if s.get('username')})


def has_username_session(license_key: str, username: str) -> bool:
    with _sessions_lock:
        sessions = active_sessions.get(license_key, {})
        return any(s.get('username') == username for s in sessions.values())


def get_username_connection_count(license_key: str, username: str) -> int:
    """Number of live connections (sids) for `username` on this license.

    Used by the connect handler to enforce a per-username tab cap (at most
    N simultaneous connections for the same username on one license).
    """
    with _sessions_lock:
        sessions = active_sessions.get(license_key, {})
        return sum(1 for s in sessions.values() if s.get('username') == username)


def can_admit(license_key: str, username: str, max_usernames: int) -> bool:
    """True if a new connection for `username` would fit within max_usernames.

    Multiple tabs of the same username count as 1 toward the cap (spec §6.5).
    """
    if max_usernames <= 0:
        return False
    if has_username_session(license_key, username):
        return True  # already counted
    return get_unique_username_count(license_key) < max_usernames


def license_sids(license_key: str) -> list:
    with _sessions_lock:
        return list(active_sessions.get(license_key, {}).keys())


def sids_for_username(username: str) -> list:
    """Return [(license_key, sid), …] for every live /_tmc session whose username
    matches. GLOBAL scope: spans all licenses. Exact match, consistent with
    has_username_session/can_admit (the stored username is the connect-time `user`
    arg, whitespace-stripped, case-preserved). Only holds _sessions_lock for the
    scan (dict iteration, no I/O); the caller emits OUTSIDE this lock."""
    if not username:
        return []
    with _sessions_lock:
        return [(lk, sid)
                for lk, bucket in active_sessions.items()
                for sid, info in bucket.items()
                if info.get('username') == username]


def sids_for_claimer(claimer_id: str, telegram_id: int) -> list:
    """Return [(license_key, sid), …] for live /_tmc session(s) matching this
    claimer_id, SCOPED to the authenticated telegram_id (admin's own claimers
    only — a claimer can never be targeted across owners). Lock held only for
    the scan; the caller emits OUTSIDE the lock."""
    if not claimer_id:
        return []
    tid = int(telegram_id or 0)
    with _sessions_lock:
        return [(lk, sid)
                for lk, bucket in active_sessions.items()
                for sid, info in bucket.items()
                if info.get('claimer_id') == claimer_id
                and int(info.get('telegram_id') or 0) == tid]


def try_update_session_username(sid: str, new_username: str, max_usernames: int,
                                uname_cap: int, admin_ids=None,
                                telegram_id: int = 0) -> Tuple[bool, Optional[str]]:
    """Atomically relabel a live session's username in place (unknown→real, or an
    account switch alice→bob) after re-validating the SAME limits a fresh connect
    checks. The whole check-and-set runs under ONE _sessions_lock acquisition, so
    it is race-free; the SID never changes. Returns (ok, reason):
      reason None on success; 'idempotent' handled as success; 'username_limit'
      if the new username would exceed a limit; 'no_session'/'bad_username' else.

    'unknown' is a pending placeholder and is never accepted as a real username.
    Counting excludes THIS sid's current label, so it works whether the session
    is currently 'unknown' or a previous real username. Because every derived
    view reads the username field live, the move's decrement(old)/increment(new)
    is reflected immediately with no extra bookkeeping.
    """
    new_username = (new_username or '').strip()
    if not new_username or new_username == 'unknown':
        return False, 'bad_username'
    admin_ids = admin_ids or set()
    is_admin = bool(telegram_id and int(telegram_id) in admin_ids)
    with _sessions_lock:
        bucket = None
        for lk, b in active_sessions.items():
            if sid in b:
                bucket = b
                break
        if bucket is None:
            return False, 'no_session'
        if bucket[sid].get('username') == new_username:
            return True, None                       # idempotent fast-path

        # Per-username cap (admin-exempt like connect), excluding this sid.
        if uname_cap > 0 and not is_admin:
            others = sum(1 for s, info in bucket.items()
                         if s != sid and info.get('username') == new_username)
            if others >= uname_cap:
                return False, 'username_limit'

        # License distinct-username limit, computed for the state AFTER the move.
        if max_usernames > 0:
            names = {info.get('username') for s, info in bucket.items()
                     if s != sid and info.get('username')
                     and info.get('username') != 'unknown'}
            names.add(new_username)
            if len(names) > max_usernames:
                return False, 'username_limit'

        bucket[sid]['username'] = new_username       # atomic commit
        return True, None


# ---------------------------------------------------------------------------
# JWT — HS256 with jti for revocation (S-02)
# ---------------------------------------------------------------------------

def issue_jwt(license_key: str, telegram_id: int) -> Tuple[str, str, int]:
    """Returns (token, jti, exp_ts)."""
    if not Config.LICENSE_JWT_SECRET:
        raise RuntimeError('LICENSE_JWT_SECRET not configured')
    now = int(time.time())
    exp = now + Config.LICENSE_TOKEN_EXPIRY_SECONDS
    jti = uuid.uuid4().hex
    payload = {
        'license_id': license_key,
        'tid': int(telegram_id),
        'jti': jti,
        'iat': now,
        'exp': exp,
    }
    token = jwt.encode(payload, Config.LICENSE_JWT_SECRET, algorithm='HS256')
    return token, jti, exp


def validate_jwt(token: str) -> Optional[dict]:
    """Decode token, verify signature/exp, ensure jti not denylisted."""
    if not Config.LICENSE_JWT_SECRET or not token:
        return None
    try:
        payload = jwt.decode(token, Config.LICENSE_JWT_SECRET, algorithms=['HS256'])
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None
    jti = payload.get('jti')
    if not jti:
        return None
    with _jti_lock:
        if jti in _jti_denylist:
            return None
    return payload


def add_to_denylist(jti: str, exp_ts: float) -> None:
    if not jti:
        return
    with _jti_lock:
        _jti_denylist[jti] = exp_ts


def prune_denylist() -> int:
    """Drop expired entries. Called by the scanner."""
    now = time.time()
    with _jti_lock:
        expired = [j for j, exp in _jti_denylist.items() if exp < now]
        for j in expired:
            _jti_denylist.pop(j, None)
        return len(expired)


# ---------------------------------------------------------------------------
# Global connect rate (R-03) — exposed via try_global_connect helper above.
# ---------------------------------------------------------------------------

def try_global_connect() -> bool:
    return _try_global_connect()


# ---------------------------------------------------------------------------
# Per-SID AES session keys (§B encryption when ENABLE_RSA_AUTH=true)
# ---------------------------------------------------------------------------

def store_session_key(sid: str, aes_key: bytes) -> None:
    with _tmc_session_keys_lock:
        _tmc_session_keys[sid] = aes_key


def pop_session_key(sid: str) -> Optional[bytes]:
    with _tmc_session_keys_lock:
        return _tmc_session_keys.pop(sid, None)


def get_session_key(sid: str) -> Optional[bytes]:
    with _tmc_session_keys_lock:
        return _tmc_session_keys.get(sid)


# ---------------------------------------------------------------------------
# RSA + AES helpers
# ---------------------------------------------------------------------------

def rsa_encrypt_session_key(client_rsa_pub_pem: str, aes_key: bytes) -> str:
    """Encrypt AES-128 session key with client's RSA-OAEP public key. Returns base64."""
    pub = serialization.load_pem_public_key(
        client_rsa_pub_pem.encode('utf-8'), backend=default_backend()
    )
    ciphertext = pub.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return base64.b64encode(ciphertext).decode('ascii')


def encrypt_payload(aes_key: bytes, plaintext_dict: dict) -> dict:
    """AES-GCM encrypt a payload dict. Returns {__enc, iv, ct}."""
    if not aes_key:
        return plaintext_dict
    iv = os.urandom(12)
    ct = AESGCM(aes_key).encrypt(iv, json.dumps(plaintext_dict).encode('utf-8'), None)
    return {
        '__enc': True,
        'iv': base64.b64encode(iv).decode('ascii'),
        'ct': base64.b64encode(ct).decode('ascii'),
    }


def decrypt_payload(aes_key: bytes, envelope: dict) -> dict:
    """Inverse of encrypt_payload. Raises on tamper (InvalidTag)."""
    if not aes_key or not isinstance(envelope, dict) or not envelope.get('__enc'):
        return envelope if isinstance(envelope, dict) else {}
    iv = base64.b64decode(envelope['iv'])
    ct = base64.b64decode(envelope['ct'])
    pt = AESGCM(aes_key).decrypt(iv, ct, None)
    return json.loads(pt.decode('utf-8'))


# ---------------------------------------------------------------------------
# Shared broadcast key (BK) helpers
# ---------------------------------------------------------------------------

def get_broadcast_key() -> Tuple[bytes, int]:
    """Return (current BK bytes, version)."""
    return _broadcast_key, _broadcast_key_version


def encrypt_broadcast(payload: dict) -> dict:
    """AES-GCM encrypt a broadcast payload ONCE with the shared BK. Returns
    {__enc, iv, ct, q}. The `q` field is the broadcast-key version and also MARKS the
    envelope as a broadcast so the client decrypts it with BK (not its per-connection
    key). `q` is deliberately opaque on the wire (Network-tab hiding); the client must
    read the SAME key. It only appears on RSA-on broadcasts, so old clients (per-conn,
    plaintext) never see it.

    NONCE: a strictly-increasing, never-reset counter (see NONCE INVARIANT) — each
    call consumes one distinct 96-bit nonce, so no (BK, nonce) reuse is possible.
    """
    n = next(_bk_nonce_ctr)
    nonce = n.to_bytes(12, 'big')
    ct = AESGCM(_broadcast_key).encrypt(nonce, json.dumps(payload).encode('utf-8'), None)
    return {
        '__enc': True,
        'iv': base64.b64encode(nonce).decode('ascii'),
        'ct': base64.b64encode(ct).decode('ascii'),
        'q': _broadcast_key_version,     # opaque broadcast marker (was 'bkv')
    }


def wrap_broadcast_key_for_session(sid: str) -> Optional[dict]:
    """Wrap BK in this session's per-connection AES key for the connect handoff.
    Returns an encrypt_payload envelope of {bk, bkv}, or None if the session has no
    per-connection key (i.e. RSA/AES not established for this sid)."""
    aes_key = get_session_key(sid)
    if not aes_key:
        return None
    return encrypt_payload(aes_key, {
        'bk': base64.b64encode(_broadcast_key).decode('ascii'),
        'bkv': _broadcast_key_version,
    })


def mark_session_bk_version(sid: str, version: int) -> bool:
    """Record that `sid` holds BK version `version` (None = legacy). Pure in-memory
    dict mutation under _sessions_lock; scan-by-sid like try_update_session_username."""
    with _sessions_lock:
        for bucket in active_sessions.values():
            info = bucket.get(sid)
            if info is not None:
                info['bk_ver'] = version
                return True
    return False


# ---------------------------------------------------------------------------
# Broadcast delivery snapshots — the SINGLE source of truth for BK-vs-legacy.
#
# Each returns, atomically under _sessions_lock, one row per live sid in scope
# carrying that sid's `bk_ver`. This one field, read exactly once per broadcast,
# is the ONLY delivery signal: there is no Socket.IO room, no second state, and
# therefore no cross-signal race. The caller emits per-sid: `bk_ver` set -> the
# shared BK envelope (encrypted once, reused); `bk_ver` None -> a per-connection
# `_wrap`. Because each sid appears once and its bk_ver is read once, every sid
# gets exactly one, decryptable delivery.
# ---------------------------------------------------------------------------

def snapshot_license_delivery(license_key: str) -> list:
    """[(sid, bk_ver), …] for one license, atomically."""
    with _sessions_lock:
        bucket = active_sessions.get(license_key, {})
        return [(sid, info.get('bk_ver')) for sid, info in bucket.items()]


def snapshot_global_delivery() -> list:
    """[(license_key, sid, bk_ver), …] for ALL live sessions, atomically."""
    with _sessions_lock:
        return [(lk, sid, info.get('bk_ver'))
                for lk, bucket in active_sessions.items()
                for sid, info in bucket.items()]


def snapshot_username_delivery(username: str) -> list:
    """[(license_key, sid, bk_ver), …] for every sid whose username matches
    (global scope, across licenses), atomically."""
    if not username:
        return []
    with _sessions_lock:
        return [(lk, sid, info.get('bk_ver'))
                for lk, bucket in active_sessions.items()
                for sid, info in bucket.items()
                if info.get('username') == username]


# ---------------------------------------------------------------------------
# Logging helpers
# ---------------------------------------------------------------------------

def redact_room(room_name: str) -> str:
    """Redact license key in a room name for safe logging."""
    if not room_name or not room_name.startswith('license:'):
        return room_name
    key = room_name[len('license:'):]
    if len(key) > 16:
        return f"license:{key[:12]}...{key[-4:]}"
    return room_name


def redact_key(license_key: str) -> str:
    if not license_key or len(license_key) <= 16:
        return license_key or ''
    return f"{license_key[:12]}...{license_key[-4:]}"
