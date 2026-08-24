"""
Coalesced per-license "balance changed" notifications.

Why this exists
---------------
When the admin drops a code, many connected claimers (e.g. 11 of 13) report a
successful claim within a second or two. Each successful claim deducts the
configured percentage from the license balance IMMEDIATELY and independently
(in the conversion worker's atomic CTE). Sending one Telegram message per
deduction would spam the user and hit Telegram rate limits.

So the *deduction* is always per-claim and exact, but the *notification* is
aggregated per license with an ACTIVITY-BASED debounce: every successful claim
resets a short timer; once the burst goes quiet, ONE summary is sent with the
total number of claims, the total deducted, and the resulting balance. A lone
claim simply produces a single, normal balance update.

Design notes
------------
* This runs inside Service 1 (eventlet). The flush timer is an eventlet
  GreenThread scheduled via spawn_after and cancelled/rescheduled on each new
  claim — that is the activity-based debounce.
* record() never blocks and never does network I/O, so it cannot slow the
  conversion worker or the deduction. The actual send happens later, in the
  flush greenlet.
* Only SUCCESSFUL, balance-affecting claims are ever recorded (the caller only
  invokes record() when a positive deduction was actually applied). Failed,
  duplicate or rejected claims never reach here.
* If the balance has gone negative, the summary is suppressed: the scanner's
  negative-balance deactivation notice already tells the user, with the exact
  (negative) figure, so a second "balance" message would be redundant.
"""
from __future__ import annotations

import logging
import threading
import time

logger = logging.getLogger(__name__)

# license_key -> {count, total_deducted, latest_balance, telegram_id, rate_pct,
#                 first_ts, timer}
_pending: dict = {}
_lock = threading.Lock()  # monkey-patched to a green lock under eventlet

# Hard cap on how long a single coalesced burst may keep growing. The debounce
# timer resets on every claim, so a license that claims with NO gap could
# otherwise defer its summary forever; this guarantees a summary goes out at
# least this often during sustained activity. (Real code-drops are discrete, so
# this is a safety bound, not the normal path.)
_MAX_COALESCE_WINDOW = 30.0


def _debounce_seconds() -> float:
    try:
        from app.config import Config
        return max(0.5, float(Config.BALANCE_NOTIFY_DEBOUNCE_SEC))
    except Exception:
        return 3.0


def record(license_key: str, telegram_id: int, deducted: float,
           new_balance: float, active: bool, rate_pct: float = 0.0) -> None:
    """Register one successful, balance-affecting claim and (re)arm the flush
    timer. Returns immediately; the summary is sent after the burst quiets.

    rate_pct is the EFFECTIVE per-claim deduction rate that was applied (the
    worker derives it from deducted/claimed). It's used only to show the user
    roughly how much more they can still claim — pure display, no logic."""
    if not license_key or not telegram_id:
        return
    try:
        import eventlet
    except Exception:
        eventlet = None

    now = time.time()
    flush_now = False
    with _lock:
        agg = _pending.get(license_key)
        if agg is None:
            agg = {
                "count": 0,
                "total_deducted": 0.0,
                "latest_balance": new_balance,
                "telegram_id": int(telegram_id),
                "rate_pct": float(rate_pct or 0.0),
                "first_ts": now,
                "timer": None,
            }
            _pending[license_key] = agg
        agg["count"] += 1
        agg["total_deducted"] += float(deducted or 0.0)
        agg["latest_balance"] = new_balance          # most recent wins
        agg["telegram_id"] = int(telegram_id)
        if rate_pct:
            agg["rate_pct"] = float(rate_pct)         # most recent effective rate

        # Reset the debounce timer: cancel the previous one, then either schedule
        # a fresh one — or, if the burst has been open longer than the max
        # window, flush immediately so a sustained stream still gets summaries.
        old_timer = agg.get("timer")
        if old_timer is not None:
            try:
                old_timer.cancel()
            except Exception:
                pass
        capped = (now - float(agg.get("first_ts", now))) >= _MAX_COALESCE_WINDOW
        if eventlet is not None and not capped:
            agg["timer"] = eventlet.spawn_after(_debounce_seconds(), _flush, license_key)
        else:
            # Max window reached (or no eventlet hub) → flush outside the lock.
            agg["timer"] = None
            flush_now = True

    # _flush() re-acquires _lock, so it MUST run outside the `with _lock` block
    # above — otherwise the non-reentrant lock would self-deadlock.
    if flush_now:
        _flush(license_key)


def _flush(license_key: str) -> None:
    """Send the coalesced summary for one license, then clear its accumulator."""
    with _lock:
        agg = _pending.pop(license_key, None)
    if not agg:
        return

    count = int(agg["count"])
    total = float(agg["total_deducted"])
    balance = agg["latest_balance"]
    telegram_id = int(agg["telegram_id"])
    rate_pct = float(agg.get("rate_pct") or 0.0)
    if count <= 0 or not telegram_id:
        return

    # Suppress when the balance is negative — the deactivation notice (sent by
    # the scanner, with the exact negative figure) covers this case.
    try:
        if balance is not None and float(balance) < 0:
            return
    except (TypeError, ValueError):
        pass

    bal_val = None
    try:
        bal_val = float(balance) if balance is not None else None
    except (TypeError, ValueError):
        bal_val = None
    bal_str = f"${bal_val:,.2f}" if bal_val is not None else "—"

    # "Roughly how much more can I claim?" = balance / (effective_rate/100).
    claimable_line = ""
    if bal_val is not None and bal_val > 0 and rate_pct > 0:
        claimable = bal_val * 100.0 / rate_pct
        claimable_line = (
            f"\n🎯 You can still claim ~<b>${claimable:,.0f}</b> more in codes."
        )

    header = (
        "✅ <b>Code claimed successfully</b>" if count == 1
        else f"✅ <b>{count} codes claimed successfully</b>"
    )
    deducted_label = "💰 Deducted" if count == 1 else "💰 Total deducted"
    msg = (
        f"{header}\n"
        f"{deducted_label}: <b>${total:,.2f}</b>\n"
        f"💳 Available balance: <b>{bal_str}</b>"
        f"{claimable_line}"
    )

    try:
        from app.utils.telegram import notify_bot_service
        notify_bot_service(telegram_id, msg)
    except Exception as exc:
        logger.warning(f"balance_notifier flush failed license={license_key}: {exc}")
