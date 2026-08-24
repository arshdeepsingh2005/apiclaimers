"""
In-memory, admin-toggleable runtime settings.

These are deliberately NOT persisted: they initialize from their env defaults at
process start and can be flipped at runtime by the admin via the bot
(`/maskcode`, `/claimdelay` → `POST /api/xr9k/settings`). A restart/redeploy
resets them to the env defaults — that is the intended behavior.

Everything here is trivial in-process state guarded by one lock; there is no I/O,
no DB, and nothing on the broadcast or claim hot path.
"""
from __future__ import annotations

import threading

from app.config import Config

_lock = threading.Lock()

# Initialize from env defaults.
_mask_code_enabled: bool = (str(Config.MASK_CODE).lower() == 'yes')
try:
    _first_claim_delay: float = max(0.0, min(300.0, float(Config.FIRST_CLAIM_DELAY_SEC)))
except (TypeError, ValueError):
    _first_claim_delay = 0.0

# Case-insensitive broadcast duplicate detection (admin /everycodesame).
# In-memory only; a restart resets to OFF — the exact pre-feature behavior. This
# ONLY affects the broadcast dedup key in websocket_manager.is_code_duplicate;
# nothing else (claims, storage, notifications) reads it.
_every_code_same: bool = False


# ── Mask code ────────────────────────────────────────────────────────────────
def get_mask_code() -> bool:
    with _lock:
        return _mask_code_enabled


def set_mask_code(enabled: bool) -> bool:
    global _mask_code_enabled
    with _lock:
        _mask_code_enabled = bool(enabled)
        return _mask_code_enabled


# ── First-claim notification delay (seconds) ─────────────────────────────────
def get_first_claim_delay() -> float:
    with _lock:
        return _first_claim_delay


def set_first_claim_delay(seconds: float) -> float:
    """Clamp to [0, 300] s. Returns the applied value."""
    global _first_claim_delay
    try:
        val = float(seconds)
    except (TypeError, ValueError):
        raise ValueError("first_claim_delay must be a number")
    if val != val or val in (float("inf"), float("-inf")):
        raise ValueError("first_claim_delay must be finite")
    val = max(0.0, min(300.0, val))
    with _lock:
        _first_claim_delay = val
        return _first_claim_delay


# ── Every-code-same (case-insensitive broadcast dedup) ───────────────────────
def get_every_code_same() -> bool:
    # LOCK-FREE by design: this is read on the broadcast hot path
    # (websocket_manager.is_code_duplicate), which must add NO locking. Reading a
    # single module-level bool is atomic under the GIL (a lone LOAD_GLOBAL), and
    # there is no read-modify-write here — a concurrent toggle is observed as
    # either the old or the new value, never torn. Same rationale as
    # app.value_override, which is also read lock-free on this path.
    return _every_code_same


def set_every_code_same(enabled: bool) -> bool:
    # Write side (cold path: admin toggles /everycodesame). The assignment itself
    # is a single atomic STORE_GLOBAL; the lock only serializes concurrent admin
    # writes and keeps snapshot() consistent. It never blocks the getter above.
    global _every_code_same
    with _lock:
        _every_code_same = bool(enabled)
        return _every_code_same


def snapshot() -> dict:
    """Current settings for API responses."""
    with _lock:
        return {
            "maskcode": _mask_code_enabled,
            "first_claim_delay": _first_claim_delay,
            "every_code_same": _every_code_same,
        }
