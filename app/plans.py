"""
Slot subscription plan catalog (config-driven).

Pricing is filled later via env (PLAN_PRICE_*). A plan with price_usd == None is
shown in the Mini App as "coming soon" and is NOT purchasable (order/begin rejects
it), so labels/durations can ship before prices are decided.

Durations are fixed here; prices come from Config so they can change without a
code deploy.
"""
from app.config import Config


def _price(raw):
    """Parse an env price string → float USD, or None when unset/invalid."""
    if raw is None:
        return None
    try:
        v = float(str(raw).strip())
        return v if v > 0 else None
    except (TypeError, ValueError):
        return None


# Ordered catalog. `code` is the stable identifier stored on the order + slot.
def _catalog():
    return [
        {
            "code": "stream_special",
            "label": "Stream Special",
            "duration_days": 1,   # 24 hours
            "price_usd": _price(Config.PLAN_PRICE_STREAM_SPECIAL),
            "features": ["Weekly Stream & Secret Codes"],
            "badge": "SPECIAL",
            "no_per_day": True,   # special/event plan — don't show a ≈/day rate
        },
        {
            "code": "d7",
            "label": "7 Days",
            "duration_days": 7,
            "price_usd": _price(Config.PLAN_PRICE_D7),
            "features": ["Daily Bonus + Reload + Stream & Secret Codes"],
            "badge": "FLEXIBLE",
        },
        {
            "code": "d14",
            "label": "14 Days",
            "duration_days": 14,
            "price_usd": _price(Config.PLAN_PRICE_D14),
            "features": ["Daily Bonus + Reload + Stream & Secret Codes"],
            "badge": "MID-TERM",
        },
        {
            "code": "d30",
            "label": "30 Days",
            "duration_days": 30,
            "price_usd": _price(Config.PLAN_PRICE_D30),
            "features": ["Daily Bonus + Reload + Stream & Secret Codes"],
            "badge": "POPULAR",
        },
        {
            "code": "d90",
            "label": "90 Days",
            "duration_days": 90,
            "price_usd": _price(Config.PLAN_PRICE_D90),
            "features": ["Daily Bonus + Reload + Stream & Secret Codes"],
            "badge": "BEST VALUE",
        },
    ]


def all_plans():
    """Full catalog (prices may be None = coming soon). Adds ≈/day for the UI."""
    out = []
    for p in _catalog():
        q = dict(p)
        if q["price_usd"] and q["duration_days"] and not q.get("no_per_day"):
            q["per_day_usd"] = round(q["price_usd"] / q["duration_days"], 2)
        else:
            q["per_day_usd"] = None   # stream_special (and unpriced) → no ≈/day
        out.append(q)
    return out


def get_plan(code):
    """One plan by code, or None if unknown."""
    for p in _catalog():
        if p["code"] == code:
            return p
    return None


def is_purchasable(code):
    """True only if the plan exists AND has a configured price."""
    p = get_plan(code)
    return bool(p and p["price_usd"])
