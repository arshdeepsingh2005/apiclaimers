"""
Canonical Indian Standard Time (IST / Asia/Kolkata) helpers.

ALL weekday / Saturday business logic in the application must go through this
module so day boundaries are computed consistently and never against the
server's local timezone or UTC.

India observes a single fixed offset of UTC+05:30 year-round (no DST), so a
fixed-offset tzinfo is exactly equivalent to the Asia/Kolkata zone and is both
dependency-free and immune to DST/boundary edge cases.
"""
from __future__ import annotations

from datetime import datetime, timezone, timedelta

# UTC+05:30 — equivalent to Asia/Kolkata (India has no daylight saving time).
IST = timezone(timedelta(hours=5, minutes=30))

# Python's weekday(): Monday=0 .. Saturday=5, Sunday=6.
_SATURDAY = 5


def now_ist() -> datetime:
    """Current wall-clock time in IST."""
    return datetime.now(IST)


def to_ist(dt: datetime) -> datetime:
    """Convert any (aware) datetime to IST. Naive datetimes are assumed UTC."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(IST)


def is_saturday_ist(dt: datetime | None = None) -> bool:
    """True iff the given instant (default: now) falls on a Saturday in IST.

    Using IST here is what prevents incorrect rate selection around midnight:
    a claim at 23:00 UTC Friday is already 04:30 Saturday IST and must be
    billed at the Saturday rate.
    """
    ref = to_ist(dt) if dt is not None else now_ist()
    return ref.weekday() == _SATURDAY
