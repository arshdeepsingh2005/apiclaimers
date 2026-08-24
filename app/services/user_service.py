"""
In-memory cache for all users with DB fallback.
Database is the source of truth.
"""
from __future__ import annotations

import logging
import threading
import time
from typing import Dict, FrozenSet, Optional

import eventlet
from sqlalchemy import select

from app.config import Config
from app.database import SessionLocal
from app.models import User

logger = logging.getLogger(__name__)


class UserService:
    """
    In-memory cache for all users with TTL.

    Pinned users (from Config.PINNED_USERS) never expire.
    All other users expire after TTL seconds and are re-fetched on next request.

    Two background workers consume this cache:

    1. Active-Disconnect-Worker (every 10s)
       Checks only CONNECTED users against DB.
       Fast — only queries the usernames that actually have open sockets.

    2. Cache-Sweep-Worker (every 5 min)
       Checks ALL cached usernames against DB via get_all_cached_usernames().
       Catches deleted users who are currently offline so they can't
       reconnect using a stale cache hit.

    Negative cache:
       When a username is looked up in DB and genuinely not found, the result
       is cached as "not found" for NEGATIVE_TTL seconds (30s).
       This prevents unknown usernames from hammering the DB on every attempt.
       Without this, each connection attempt for an unknown username triggers
       3 DB queries indefinitely.

    Thread-safety:
      - self._lock is a single threading.Lock guarding both _cache and
        _negative_cache. No re-entrant calls exist so plain Lock is correct.
      - All DB IO is performed OUTSIDE the lock so we never hold an open
        DB connection while waiting to acquire the lock.
    """

    _TTL: int          = 10800  # 3 hours TTL for non-pinned users
    _MAX_SIZE: int     = 5000   # max positive cache entries before eviction
    _NEGATIVE_TTL: int = 30     # 30s TTL for "not found" results

    def __init__(self):
        # Positive cache: normalized_username -> {user_id, username, expires_at}
        self._cache: Dict[str, dict] = {}

        # Negative cache: normalized_username -> expiry_timestamp (float)
        # Populated when a DB lookup confirms the username does not exist.
        # Prevents repeat DB hits for the same unknown username for 30s.
        self._negative_cache: Dict[str, float] = {}

        self._lock = threading.Lock()
        self._pinned_users: FrozenSet[str] = frozenset(Config.PINNED_USERS)

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Preload pinned users into cache on startup."""
        try:
            self._preload_pinned_users()
        except Exception as e:
            logger.warning(f"UserService: failed to preload pinned users: {e}")

    def stop(self) -> None:
        pass

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get_user(self, username: str) -> Optional[dict]:
        """
        Return user dict from cache, falling back to DB if not cached.

        Lookup order:
          1. Positive cache  → return user dict immediately (zero DB)
          2. Negative cache  → return None immediately (zero DB)
          3. DB lookup       → cache result (positive or negative), return

        Returns:
            dict {user_id, username}   — valid user
            None                       — user not found (or negative cached)
            {'_db_error': True}        — DB unreachable; all callers guard
                                         with .get('user_id') so this is
                                         safely treated as a rejection.
        """
        normalized = self._normalize(username)
        if not normalized:
            return None

        with self._lock:
            # 1. Positive cache hit
            entry = self._cache.get(normalized)
            if entry is not None:
                # Pinned users never expire
                if normalized in self._pinned_users:
                    return entry
                # Non-pinned: check TTL
                if entry.get("expires_at", 0) >= time.time():
                    return entry
                # Expired — remove so _lookup_and_cache fetches fresh
                del self._cache[normalized]

            # 2. Negative cache hit — already confirmed not in DB recently
            neg_expiry = self._negative_cache.get(normalized, 0)
            if neg_expiry > time.time():
                return None  # Blocked from memory — zero DB hit

        # 3. Not in either cache — go to DB
        return self._lookup_and_cache(normalized)

    def evict_user(self, username: str) -> None:
        """
        Remove a user from positive cache immediately.

        Called by both background workers after confirming a user has been
        deleted from DB, so that the next connection attempt goes back to
        the DB and is correctly rejected rather than hitting a stale entry.

        Safe to call even if the user is not currently cached.
        """
        normalized = self._normalize(username)
        if not normalized:
            return
        with self._lock:
            self._cache.pop(normalized, None)

    def get_all_cached_usernames(self) -> frozenset:
        """
        Return an immutable snapshot of every username in the POSITIVE cache.

        Used by the Cache-Sweep-Worker to batch-validate ALL cached users
        against the DB, catching deleted users who are currently offline
        (i.e. not visible to the Active-Disconnect-Worker).

        Returns a frozenset — immutable copy, no reference to internal dict.
        """
        with self._lock:
            return frozenset(self._cache.keys())

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _lookup_and_cache(self, normalized: str) -> Optional[dict]:
        """
        Single-user DB lookup with up to 2 attempts for transient failures.

        On success (user found):
          → writes to positive cache
          → returns user dict

        On genuine not-found (both attempts returned empty):
          → writes to negative cache for NEGATIVE_TTL seconds
          → returns None
          → next call within NEGATIVE_TTL hits memory, not DB

        On DB error (exception on both attempts):
          → nothing cached (will retry on next call)
          → returns {'_db_error': True}

        Thread-safety / resource notes:
          - Session opens, queries, and closes BEFORE lock is acquired.
            Never holds an open DB connection while waiting for the lock.
          - eventlet.sleep() retries are outside the session so the
            connection is released back to the pool before we wait and
            the hub keeps scheduling other greenlets.
        """
        last_exception = None

        for attempt in range(3):
            row = None
            try:
                # --- DB IO: session opens and closes here ---
                # psycogreen yields libpq's wait to the eventlet hub, so this
                # roundtrip never blocks the worker process.
                with SessionLocal() as session:
                    row = session.execute(
                        select(User).where(User.username == normalized)
                    ).scalar_one_or_none()
                # Session is closed — safe to sleep or acquire lock below

            except Exception as e:
                last_exception = e
                if attempt < 2:
                    # Exponential backoff via eventlet so the hub keeps
                    # servicing other greenlets while we wait.
                    eventlet.sleep(0.2 * (2 ** attempt))
                continue

            # --- Session closed — handle result ---

            if row is None:
                # With pool_pre_ping=True the pool never hands out a dead
                # socket, so a None result is genuinely "not in DB" on the
                # first successful roundtrip. Write to the negative cache so
                # subsequent attempts are blocked from memory for
                # NEGATIVE_TTL seconds (zero DB hits).
                with self._lock:
                    self._negative_cache[normalized] = (
                        time.time() + self._NEGATIVE_TTL
                    )
                    # Opportunistically clean expired negative cache entries
                    # to prevent unbounded growth from many unique bad usernames.
                    now = time.time()
                    expired_neg = [
                        k for k, exp in self._negative_cache.items()
                        if exp < now
                    ]
                    for k in expired_neg:
                        del self._negative_cache[k]

                logger.debug(
                    f"UserService: '{normalized}' not found — "
                    f"negative cached for {self._NEGATIVE_TTL}s"
                )
                return None

            # User found — build entry dict before acquiring lock
            # (no DB connection held at this point)
            expires_at = (
                float('inf')
                if normalized in self._pinned_users
                else time.time() + self._TTL
            )
            entry = {
                "user_id":    row.id,
                "username":   row.username,
                "expires_at": expires_at,
            }

            with self._lock:
                # Evict up to 100 expired non-pinned entries if at capacity
                if len(self._cache) >= self._MAX_SIZE:
                    now = time.time()
                    expired = [
                        k for k, v in self._cache.items()
                        if k not in self._pinned_users
                        and v.get("expires_at", 0) < now
                    ]
                    for k in expired[:100]:
                        self._cache.pop(k, None)

                self._cache[normalized] = entry

                # If this username was previously negatively cached
                # (e.g. user was just added to DB), clear that entry.
                self._negative_cache.pop(normalized, None)

            return entry

        # All 3 attempts raised exceptions — DB is unreachable.
        # Do NOT cache — let the next call retry fresh.
        logger.warning(
            f"UserService: DB lookup failed for '{normalized}' "
            f"after 3 attempts: {last_exception}"
        )
        return {"_db_error": True}

    def _preload_pinned_users(self) -> None:
        """
        Fetch all pinned users in a single DB session and populate cache.
        Session closes before the lock is acquired (same principle as above).
        """
        entries: Dict[str, dict] = {}
        try:
            with SessionLocal() as session:
                for username in self._pinned_users:
                    try:
                        row = session.execute(
                            select(User).where(User.username == username)
                        ).scalar_one_or_none()
                        if row:
                            entries[username] = {
                                "user_id":    row.id,
                                "username":   row.username,
                                "expires_at": float('inf'),
                            }
                    except Exception:
                        pass
            # Session closed — safe to acquire lock
        except Exception:
            pass

        if entries:
            with self._lock:
                self._cache.update(entries)

    def _normalize(self, username: Optional[str]) -> Optional[str]:
        if username is None:
            return None
        username = str(username).strip()
        if not username or len(username) > 64:
            return None
        return username


user_service = UserService()
