"""Persistent admin "value for next code" override.

When enabled (via /valuefornextcode <n>), a default `value` is injected into
every *eligible* broadcast code — one that has no value of its own and whose
code does not start with an excluded prefix. It stays active until reset
(/valuefornextcode reset).

Isolated on purpose: the whole feature is this module + three call sites
(the injection in websocket_manager.broadcast_code, the internal endpoint, and
the bot command). Delete those to remove it.

Concurrency: the state is ONE module-level reference (`None` = disabled, else a
number). CPython reads/rebinds a single name atomically under the GIL, and there
is no read-modify-write, so reads are lock-free and writes are atomic. An admin
changing or resetting the value during concurrent broadcasts can only ever
observe the old value, the new value, or None — never a torn state. No lock.

In-memory only: a process restart resets it to disabled (fails safe to the
exact pre-feature behavior).
"""
import math
from typing import Optional, Union

Number = Union[int, float]

# Code prefixes that must NEVER receive an injected value (compared against a
# stripped+lowercased copy of the code — the code itself is never mutated).
_EXCLUDED_PREFIXES = ('stakecom', 'stakepy', 'staketr')

# Upper bound for a sane override value (dollar-ish amounts; guards against
# absurd input even though only admins can set it).
_MAX_OVERRIDE_VALUE = 1_000_000

# None = disabled. Otherwise an int (whole) or float (fractional).
_override_value: Optional[Number] = None


def is_valid_override(value) -> bool:
    """True only for a real, finite, positive, bounded number.

    Rejects bool (a subclass of int), non-numeric, NaN, +/-Infinity, negative,
    zero, and values above _MAX_OVERRIDE_VALUE.
    """
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    f = float(value)
    if math.isnan(f) or math.isinf(f):
        return False
    return 0 < f <= _MAX_OVERRIDE_VALUE


def _canonical(value: Number) -> Number:
    """Store a whole number as int, a fractional as float (4.0 -> 4, 12.5 stays
    12.5) so payloads/logs stay consistent with real senders and filter keys."""
    f = float(value)
    return int(f) if f.is_integer() else f


def set_override(value: Number) -> Number:
    """Enable/replace the override (atomic single assignment). Raises ValueError
    on an invalid value. Returns the stored (canonical) value."""
    if not is_valid_override(value):
        raise ValueError('invalid override value')
    global _override_value
    _override_value = _canonical(value)
    return _override_value


def clear_override() -> None:
    """Disable the override (atomic single assignment)."""
    global _override_value
    _override_value = None


def get_override() -> Optional[Number]:
    return _override_value


def value_for_code(code: str, existing_value) -> Optional[Number]:
    """The single decision point. Returns the value to inject, or None to leave
    the payload unchanged.

    Rules (in order):
      * override disabled                         -> None
      * payload already has a (truthy) value      -> None (never overwrite)
      * code starts with an excluded prefix       -> None
      * otherwise                                 -> the override value

    "Has a value" == a truthy `existing_value` (`if existing_value:`), matching
    the userscript's parseCodeValue (`codeData.value || ...` + `if (value)`),
    which treats None/0/"" as no-value. Python bool() matches JS truthiness for
    these scalars, so backend and client agree.
    """
    ov = _override_value          # single lock-free atomic snapshot
    if ov is None:
        return None
    if existing_value:            # truthy -> sender provided a value; keep it
        return None
    norm = (code or '').strip().lower()   # comparison-only; code is not mutated
    if norm.startswith(_EXCLUDED_PREFIXES):
        return None
    return ov
