"""
OxaPay balance top-up — business logic (Service 1 only; owns the DB).

This module is deliberately the ONLY place that touches money. It is isolated
from the broadcast / claim / scanner hot paths: it is invoked exclusively from
the internal top-up endpoints (user-initiated) and the OxaPay webhook route.
Nothing here runs on the code-broadcast or claim-credit path.

Guarantees:
  * Amounts are validated server-side (the bot's check is not trusted).
  * An audit row is written BEFORE the provider call, so a crash never loses an
    invoice.
  * Money is credited ONLY after re-fetching the authoritative status from the
    OxaPay API (webhook data is a trigger, never a source of truth).
  * Credit + license-reactivation happen in ONE transaction, behind a
    SELECT ... FOR UPDATE row lock and a `credited` latch, so duplicate /
    concurrent / replayed webhooks credit exactly once.
"""
from __future__ import annotations

import logging
import os
import threading
import time
import uuid
from datetime import datetime, timezone, timedelta
from typing import Optional

from sqlalchemy import select, text, update

from app import oxapay
from app.config import Config
from app.database import SessionLocal, db_session
from app.models import Payment

logger = logging.getLogger(__name__)

_MAX_WEBHOOK_PAYLOAD = 4000  # chars of raw body we retain for audit


# ---------------------------------------------------------------------------
# Debounced admin alerts (anti-spam; one alert per category per cooldown)
# ---------------------------------------------------------------------------
_alert_lock = threading.Lock()
_last_alert: dict = {}
_ALERT_COOLDOWN = 300.0  # seconds


def _admin_alert(category: str, message: str, *, force: bool = False) -> None:
    admin_raw = (os.environ.get("ADMIN_TELEGRAM_ID") or "").strip()
    if not admin_raw:
        return
    try:
        admin_id = int(admin_raw)
    except (TypeError, ValueError):
        return
    if not force:
        now = time.time()
        with _alert_lock:
            if now - _last_alert.get(category, 0) < _ALERT_COOLDOWN:
                return
            _last_alert[category] = now
    try:
        from app.utils.telegram import notify_bot_service
        notify_bot_service(admin_id, message)
    except Exception:
        pass


def _notify_user(telegram_id: int, message: str) -> None:
    if not telegram_id:
        return
    try:
        from app.utils.telegram import notify_bot_service
        notify_bot_service(int(telegram_id), message)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------
def validate_amount(amount) -> tuple:
    """
    Returns (ok, value, error_key). Enforces the $1..$50 (configurable) band.
    Rejects non-numeric, NaN/inf, and out-of-range. This runs on the BACKEND so
    the bot's check cannot be bypassed.
    """
    try:
        val = float(amount)
    except (TypeError, ValueError):
        return False, 0.0, "amount_not_number"
    if val != val or val in (float("inf"), float("-inf")):
        return False, 0.0, "amount_not_number"
    val = round(val, 2)
    if val < Config.TOPUP_MIN_USD:
        return False, 0.0, "amount_too_small"
    if val > Config.TOPUP_MAX_USD:
        return False, 0.0, "amount_too_large"
    return True, val, ""


# ---------------------------------------------------------------------------
# License resolution
# ---------------------------------------------------------------------------
def _resolve_license(telegram_id: int) -> Optional[tuple]:
    """Current license for a telegram_id: active preferred, else most recent.
    Returns (license_key, banned) or None when the user has no license."""
    from app.models import License
    try:
        with db_session() as s:
            row = s.execute(
                select(License.license_key, License.banned)
                .where(License.telegram_id == int(telegram_id))
                .order_by(License.active.desc(), License.created_at.desc())
                .limit(1)
            ).first()
            return (row[0], bool(row[1])) if row else None
    except Exception as exc:
        logger.warning(f"_resolve_license failed tg={telegram_id}: {exc}")
        return None


# ---------------------------------------------------------------------------
# Begin / record a top-up
#
# Split across the bot ↔ main boundary so the OxaPay network call lives on the
# BOT (Service 2), keeping the payment-provider load off the main backend:
#   1. bot → main  begin_topup()  : validate, reuse-or-allocate an order, return
#   2. bot → OxaPay create invoice (only when begin said reuse=False)
#   3. bot → main  record_topup()  : persist the provider's track_id / pay_url
# Main owns the DB and is the system of record; the bot owns provider I/O.
# ---------------------------------------------------------------------------
def begin_topup(telegram_id: int, amount) -> dict:
    """Validate + either reuse the user's existing open invoice or allocate a
    fresh order row (status 'new') for the bot to turn into an OxaPay invoice.

    Returns one of:
      {ok:True, reuse:True,  order_id, pay_url, amount, currency}   ← existing
      {ok:True, reuse:False, order_id, amount, currency}            ← create new
      {ok:False, error:<key>}
    """
    ok, amt, err = validate_amount(amount)
    if not ok:
        return {"ok": False, "error": err}

    resolved = _resolve_license(telegram_id)
    if not resolved:
        # No license at all → the user must /start first. (A user CAN top up an
        # inactive license; that is exactly how a depleted license is revived.)
        return {"ok": False, "error": "no_license"}
    license_key, is_banned = resolved
    if is_banned:
        # Never take money from a banned license — it would credit a balance
        # that can never reactivate (credit is gated on NOT banned).
        logger.info(f"TOPUP_REFUSED_BANNED | tg={telegram_id} | license={license_key}")
        return {"ok": False, "error": "license_banned"}

    # ── Reuse an existing OPEN invoice (point 3: never pile up unpaid invoices).
    # Reuse regardless of the newly-requested amount so a user cannot spawn many
    # invoices by re-running /topup; the bot tells them the pending amount.
    try:
        now = datetime.now(timezone.utc)
        with db_session() as s:
            existing = s.execute(
                select(Payment)
                .where(
                    Payment.telegram_id == int(telegram_id),
                    Payment.credited.is_(False),
                    Payment.status == "waiting",
                    Payment.pay_url.isnot(None),
                )
                .order_by(Payment.created_at.desc())
                .limit(1)
            ).scalar_one_or_none()
            if existing is not None:
                not_expired = (existing.expires_at is None) or (
                    _aware(existing.expires_at) > now
                )
                if not_expired:
                    logger.info(
                        f"INVOICE_REUSED | order={existing.order_id} | tg={telegram_id} | "
                        f"amount={float(existing.amount):.2f}"
                    )
                    return {
                        "ok": True,
                        "reuse": True,
                        "order_id": existing.order_id,
                        "pay_url": existing.pay_url,
                        "amount": float(existing.amount),
                        "currency": existing.currency,
                    }
    except Exception as exc:
        logger.warning(f"begin_topup reuse-check failed tg={telegram_id}: {exc}")
        # Fall through to allocate a fresh order — never block a top-up on this.

    # ── Allocate a fresh order row BEFORE the provider call (crash-safe audit).
    order_id = uuid.uuid4().hex
    try:
        with db_session() as s:
            s.add(Payment(
                order_id=order_id,
                telegram_id=int(telegram_id),
                license_key=license_key,
                amount=amt,
                currency=Config.OXAPAY_CURRENCY,
                status="new",
            ))
    except Exception as exc:
        logger.error(f"begin_topup: pre-insert failed tg={telegram_id}: {exc}", exc_info=True)
        return {"ok": False, "error": "db_error"}

    # Admin heads-up on large attempts (debounced so it can't be used to spam).
    if amt >= Config.OXAPAY_LARGE_PAYMENT_USD:
        _admin_alert(
            "large_payment",
            "💸 <b>Large top-up attempt</b>\n\n"
            f"👤 User ID: <code>{int(telegram_id)}</code>\n"
            f"🔑 License: <code>{license_key}</code>\n"
            f"💵 Amount: <b>${amt:.2f}</b>\n"
            f"🧾 Order: <code>{order_id}</code>",
        )

    logger.info(
        f"INVOICE_ALLOCATED | order={order_id} | tg={telegram_id} | "
        f"license={license_key} | amount={amt:.2f}"
    )
    return {
        "ok": True,
        "reuse": False,
        "order_id": order_id,
        "amount": amt,
        "currency": Config.OXAPAY_CURRENCY,
    }


def record_topup(telegram_id: int, order_id: str, track_id: str, pay_url: str,
                 pay_address: str = "", expires_at=None) -> dict:
    """Persist the OxaPay provider details the bot obtained, flipping the order
    from 'new' to 'waiting'. Scoped to telegram_id so a caller can only mutate
    its own order. Idempotent-ish: re-recording an already-waiting order with the
    same track is harmless."""
    order_id = (order_id or "").strip()
    track_id = (track_id or "").strip()
    if not order_id or not track_id or not pay_url:
        return {"ok": False, "error": "missing_fields"}
    if not oxapay.is_valid_track_id(track_id):
        return {"ok": False, "error": "bad_track_id"}

    exp_dt = _epoch_to_dt(expires_at) or (
        datetime.now(timezone.utc) + timedelta(minutes=Config.OXAPAY_INVOICE_LIFETIME_MIN)
    )
    try:
        with db_session() as s:
            # Only the owner's NON-credited order may be (re)recorded; never
            # downgrade a credited/paid row.
            res = s.execute(
                update(Payment)
                .where(
                    Payment.order_id == order_id,
                    Payment.telegram_id == int(telegram_id),
                    Payment.credited.is_(False),
                    Payment.status.in_(["new", "waiting"]),
                )
                .values(
                    track_id=track_id,
                    pay_url=pay_url,
                    pay_address=(pay_address or None),
                    expires_at=exp_dt,
                    status="waiting",
                )
            )
            if res.rowcount == 0:
                return {"ok": False, "error": "not_recordable"}
    except Exception as exc:
        logger.error(f"record_topup failed order={order_id}: {exc}", exc_info=True)
        return {"ok": False, "error": "db_error"}

    logger.info(
        f"INVOICE_RECORDED | order={order_id} | track={track_id} | tg={telegram_id}"
    )
    return {"ok": True, "order_id": order_id, "track_id": track_id,
            "expires_at": exp_dt.isoformat()}


# ---------------------------------------------------------------------------
# Status (bot polling) — scoped to the requesting user (authorization)
# ---------------------------------------------------------------------------
def get_status(telegram_id: int, order_id: str = "", track_id: str = "") -> dict:
    order_id = (order_id or "").strip()
    track_id = (track_id or "").strip()
    if not order_id and not track_id:
        return {"ok": False, "error": "missing_ref"}
    try:
        with db_session() as s:
            q = select(Payment).where(Payment.telegram_id == int(telegram_id))
            if order_id:
                q = q.where(Payment.order_id == order_id)
            else:
                q = q.where(Payment.track_id == track_id)
            p = s.execute(q.order_by(Payment.created_at.desc()).limit(1)).scalar_one_or_none()
            if p is None:
                return {"ok": False, "error": "not_found"}

            # Lazy expiry for the UI ONLY — must NOT be persisted. If we wrote
            # "expired" to the DB here, a paid-but-not-yet-credited invoice (whose
            # local timer lapsed while a webhook/reconcile hiccup delayed the
            # credit) would drop out of reconciliation's `waiting` set and never
            # recover. Real expiry is decided solely by OxaPay via the credit
            # path; here we only DISPLAY "expired" without mutating the row.
            display_status = p.status
            if (p.status == "waiting" and not p.credited and p.expires_at
                    and p.expires_at < datetime.now(timezone.utc)):
                display_status = "expired"

            return {
                "ok": True,
                "status": display_status,
                "credited": bool(p.credited),
                "amount": float(p.amount),
                "currency": p.currency,
                "pay_url": p.pay_url,
                "order_id": p.order_id,
                "track_id": p.track_id,
                "expires_at": p.expires_at.isoformat() if p.expires_at else None,
            }
    except Exception as exc:
        logger.warning(f"get_status failed tg={telegram_id}: {exc}")
        return {"ok": False, "error": "db_error"}


# ---------------------------------------------------------------------------
# Verify & credit  (invoked by the bot once it has seen a confirmation, either
# via the OxaPay webhook it now hosts, or via its reconciliation sweep)
#
# This is the ONLY entry point that can move money, and it is the trust anchor:
# regardless of what the bot believes, MAIN independently re-verifies with the
# OxaPay inquiry API before crediting. It is fully idempotent and safe under
# retries / timeouts / concurrency (order_id identity + FOR UPDATE row lock +
# `credited` latch — see _credit_verified_payment).
#
# Response contract (so the bot retries correctly):
#   (200, ok:True,  result:credited|already_credited)   → TERMINAL (dequeue)
#   (200, ok:True,  result:not_paid_yet|expired|cancelled) → terminal-for-now
#   (200, ok:False, result:amount_mismatch|no_license)  → TERMINAL (admin flagged)
#   (404, ok:False) / (502, ok:False, verify_failed)    → TRANSIENT (bot retries)
# ---------------------------------------------------------------------------
def verify_and_credit(order_id: str, bot_verified: bool = False) -> tuple:
    order_id = (order_id or "").strip()
    if not order_id:
        return 400, {"ok": False, "error": "missing_order_id"}

    pay = _find_payment("", order_id)
    if pay is None:
        logger.warning(f"CREDIT_UNKNOWN_ORDER | order={order_id}")
        return 404, {"ok": False, "error": "unknown_order"}

    # Fast idempotent path — already credited (duplicate webhook + reconciliation
    # racing, or a retried call after a prior success). No lock needed to answer.
    if pay.credited:
        logger.info(f"CREDIT_DUPLICATE | order={order_id} (already credited)")
        return 200, {"ok": True, "result": "already_credited"}

    verify_track = (pay.track_id or "").strip()
    if not verify_track:
        # Never recorded a provider track id → nothing to verify against.
        return 200, {"ok": False, "result": "no_track"}

    # Re-verify against the authoritative OxaPay API. If the API is REACHABLE we
    # always trust its answer. If OUR call fails on a transport error
    # (network_error/timeout — e.g. the eventlet worker can't do the outbound
    # HTTPS), fall back to the bot's own verification: the bot runs sync workers
    # that reach OxaPay reliably and only sets bot_verified=True after confirming
    # the invoice is PAID via the same inquiry API. Crediting stays idempotent.
    logger.info(f"VERIFICATION_STARTED | order={order_id} | track={verify_track}")
    info = oxapay.get_payment(verify_track)
    if not info.get("ok"):
        err = str(info.get("error") or "")
        transport_failure = err.startswith("network_error") or err in ("timeout",)
        # Break-glass fallback (OFF by default): only when explicitly enabled,
        # only on a TRANSPORT failure of main's OWN verify (never on a
        # "not-paid" answer), and only when the bot asserts verified=PAID.
        if Config.TOPUP_TRUST_BOT_ON_VERIFY_FAIL and bot_verified and transport_failure:
            logger.warning(
                f"CREDIT_TRUST_BOT | order={order_id} | track={verify_track} | "
                f"main_verify={err} — crediting on bot-side verification (break-glass)"
            )
            result = _credit_verified_payment(order_id, {"status": "paid", "amount": None})
            if result in ("credited", "already_credited"):
                return 200, {"ok": True, "result": result}
            if result == "error":
                return 502, {"ok": False, "error": "credit_error"}
            return 200, {"ok": False, "result": result}

        logger.warning(
            f"VERIFICATION_FAILED | order={order_id} | track={verify_track} | "
            f"reason={err} | bot_verified={bot_verified}"
        )
        _admin_alert(
            "verify_unreachable",
            "⚠️ <b>OxaPay verification failed</b>\n\n"
            f"🧾 Order: <code>{order_id}</code>\n"
            f"🧾 track_id: <code>{verify_track}</code>\n"
            f"Reason: <code>{err}</code>\n"
            "(The bot will retry; crediting is idempotent.)",
        )
        # 502 → the bot treats it as transient and retries later.
        return 502, {"ok": False, "error": "verify_failed"}

    status = info.get("status") or ""
    if status in oxapay.PAID_STATUSES:
        _store_verified_payload(order_id, info)
        result = _credit_verified_payment(order_id, info)
        if result in ("credited", "already_credited"):
            return 200, {"ok": True, "result": result}
        if result == "error":
            return 502, {"ok": False, "error": "credit_error"}   # transient → retry
        # amount_mismatch / no_license → terminal, admin already alerted.
        return 200, {"ok": False, "result": result}

    if status in oxapay.EXPIRED_STATUSES:
        _mark_status(order_id, "expired")
        logger.info(f"INVOICE_EXPIRED | order={order_id} | track={verify_track}")
        return 200, {"ok": True, "result": "expired"}

    if status in oxapay.FAILED_STATUSES:
        _mark_status(order_id, "cancelled", error_reason=f"oxapay_status={status}")
        logger.info(f"INVOICE_CANCELLED | order={order_id} | status={status}")
        return 200, {"ok": True, "result": "cancelled"}

    # waiting / confirming → keep waiting, no credit.
    logger.info(f"CREDIT_PENDING | order={order_id} | status={status}")
    return 200, {"ok": True, "result": "not_paid_yet"}


# ---------------------------------------------------------------------------
# Reconciliation feed — the bot's periodic sweep asks for open invoices to
# re-check against OxaPay, so a payment whose webhook was missed (bot/main
# briefly offline) is still finalised.
# ---------------------------------------------------------------------------
def list_pending(limit: int = 200, lookback_hours: int = 72) -> dict:
    """Open (waiting, not-credited, verifiable) invoices, newest first, bounded.
    Older-than-lookback rows are excluded so the sweep cost stays constant even
    as the payments table grows."""
    try:
        limit = max(1, min(int(limit), 1000))
    except (TypeError, ValueError):
        limit = 200
    cutoff = datetime.now(timezone.utc) - timedelta(hours=max(1, int(lookback_hours)))
    out = []
    try:
        with db_session() as s:
            rows = s.execute(
                select(Payment.order_id, Payment.track_id, Payment.telegram_id, Payment.amount)
                .where(
                    Payment.credited.is_(False),
                    Payment.status == "waiting",
                    Payment.track_id.isnot(None),
                    Payment.created_at >= cutoff,
                )
                .order_by(Payment.created_at.desc())
                .limit(limit)
            ).all()
            for r in rows:
                out.append({
                    "order_id": r[0],
                    "track_id": r[1],
                    "telegram_id": int(r[2] or 0),
                    "amount": float(r[3] or 0),
                })
    except Exception as exc:
        logger.warning(f"list_pending failed: {exc}")
        return {"ok": False, "error": "db_error", "pending": []}
    return {"ok": True, "pending": out, "count": len(out)}


def _credit_verified_payment(order_id: str, info: dict) -> str:
    """
    Apply the credit + (re)activation in ONE locked transaction. Returns one of:
    'credited' | 'already_credited' | 'amount_mismatch' | 'no_license' | 'error'.

    Concurrency: the payment row is SELECT ... FOR UPDATE locked, so concurrent
    or duplicate webhook deliveries serialise here and the `credited` re-check
    inside the lock makes the credit run exactly once.
    """
    credited_license = None
    new_balance = None
    reactivated = False
    telegram_id = 0
    amt = 0.0

    session = SessionLocal()
    try:
        pay = session.execute(
            select(Payment).where(Payment.order_id == order_id).with_for_update()
        ).scalar_one_or_none()
        if pay is None:
            session.rollback()
            return "error"

        if pay.credited:
            session.rollback()
            logger.info(f"WEBHOOK_DUPLICATE | order={order_id} (re-check inside lock)")
            return "already_credited"

        telegram_id = int(pay.telegram_id or 0)
        amt = float(pay.amount)
        tx_hash = info.get("tx_hash")

        # Defence in depth: with under_paid_coverage=0 OxaPay only reports "paid"
        # on a full payment, but if the verified amount is clearly short, refuse
        # to credit and flag for manual review.
        oxa_amt = info.get("amount")
        if oxa_amt is not None:
            try:
                if float(oxa_amt) < amt - 0.01:
                    pay.status = "paid"
                    pay.error_reason = f"amount_mismatch reported={oxa_amt} expected={amt}"
                    pay.tx_hash = tx_hash
                    pay.confirmed_at = datetime.now(timezone.utc)
                    session.commit()
                    logger.warning(
                        f"AMOUNT_MISMATCH | order={order_id} | reported={oxa_amt} | expected={amt}"
                    )
                    _admin_alert(
                        "amount_mismatch",
                        "⚠️ <b>OxaPay amount mismatch</b>\n\n"
                        f"🧾 Order: <code>{order_id}</code>\n"
                        f"Expected: <b>${amt:.2f}</b>  Reported: <b>{oxa_amt}</b>\n"
                        "Not credited — please review.",
                        force=True,
                    )
                    return "amount_mismatch"
            except (TypeError, ValueError):
                pass

        # Atomic credit + reactivate of the user's CURRENT license (handles key
        # rotation). Banned licenses keep the balance but stay disabled.
        credit_sql = text(
            "WITH target AS ("
            "  SELECT license_key, active AS old_active FROM licenses"
            "  WHERE telegram_id = :tid"
            "  ORDER BY active DESC, created_at DESC LIMIT 1"
            "), upd AS ("
            "  UPDATE licenses l SET"
            "    available_balance = COALESCE(l.available_balance, 0) + :amt,"
            "    active = CASE WHEN COALESCE(l.available_balance,0) + :amt > 0 AND NOT l.banned"
            "                  THEN TRUE ELSE l.active END,"
            "    activated_at = CASE WHEN COALESCE(l.available_balance,0) + :amt > 0 AND NOT l.banned"
            "                        AND l.active = FALSE THEN now() ELSE l.activated_at END"
            "  FROM target WHERE l.license_key = target.license_key"
            "  RETURNING l.license_key, l.available_balance, l.active, l.banned, l.deduction_percentage"
            ") "
            "SELECT upd.license_key, upd.available_balance, upd.active, upd.banned, target.old_active,"
            "       upd.deduction_percentage"
            " FROM upd JOIN target ON upd.license_key = target.license_key"
        )
        row = session.execute(credit_sql, {"tid": telegram_id, "amt": amt}).first()

        if row is None:
            # The license vanished between create and pay. Money IS received, so
            # record it as paid + flag, never silently drop it.
            pay.status = "paid"
            pay.error_reason = "no_license_to_credit"
            pay.tx_hash = tx_hash
            pay.confirmed_at = datetime.now(timezone.utc)
            session.commit()
            logger.error(f"CREDIT_NO_LICENSE | order={order_id} | tg={telegram_id}")
            _admin_alert(
                "no_license_credit",
                "⚠️ <b>Top-up paid but no license to credit</b>\n\n"
                f"👤 User ID: <code>{telegram_id}</code>\n"
                f"🧾 Order: <code>{order_id}</code>\n"
                f"💵 Amount: <b>${amt:.2f}</b>",
                force=True,
            )
            return "no_license"

        credited_license = row[0]
        new_balance = float(row[1])
        new_active = bool(row[2])
        old_active = bool(row[4])
        ded_pct = float(row[5]) if row[5] is not None else None
        reactivated = (not old_active) and new_active

        # Flip the hard idempotency latch + record provider details, same tx.
        pay.status = "paid"
        pay.credited = True
        pay.tx_hash = tx_hash
        pay.license_key = credited_license
        pay.confirmed_at = datetime.now(timezone.utc)
        session.commit()
    except Exception as exc:
        session.rollback()
        logger.error(f"_credit_verified_payment failed order={order_id}: {exc}", exc_info=True)
        return "error"
    finally:
        session.close()

    # --- Post-commit side effects (best-effort; never affect the credit) ---
    logger.info(
        f"BALANCE_CREDITED | order={order_id} | tg={telegram_id} | license={credited_license} | "
        f"amount={amt:.2f} | balance={new_balance:.4f}"
    )
    # Make the license usable IMMEDIATELY (don't wait for the scanner cycle).
    # The scanner still owns the activation Telegram notice on the DB transition.
    try:
        _refresh_license_cache(credited_license)
    except Exception:
        pass
    if reactivated:
        logger.info(f"LICENSE_REACTIVATED | order={order_id} | license={credited_license}")

    # Optional "you can now claim ~$X more" line (display only; mirrors the
    # per-claim deduction). Skipped for After-Claims licenses (no percentage).
    claimable_line = ""
    if ded_pct and ded_pct > 0 and new_balance > 0:
        claimable = new_balance * 100.0 / ded_pct
        claimable_line = (
            f"🎯 You can now claim ~<b>${claimable:,.0f}</b> in bonus codes.\n"
        )

    _notify_user(
        telegram_id,
        "✅ <b>Recharge Successful</b>\n"
        "━━━━━━━━━━━━━━━\n"
        f"💵 Added  <b>${amt:.2f}</b>\n"
        f"💳 New balance  <b>${new_balance:,.2f}</b>\n"
        f"{claimable_line}\n"
        + ("🟢 Your license is active again — happy claiming! 🚀"
           if reactivated else "Happy claiming! 🚀"),
    )
    return "credited"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _find_payment(track_id: str, order_id: str) -> Optional[Payment]:
    try:
        with db_session() as s:
            p = None
            if track_id and oxapay.is_valid_track_id(track_id):
                p = s.execute(
                    select(Payment).where(Payment.track_id == track_id)
                ).scalar_one_or_none()
            if p is None and order_id:
                p = s.execute(
                    select(Payment).where(Payment.order_id == order_id)
                ).scalar_one_or_none()
            if p is not None:
                # Detach a lightweight copy of the fields we read later.
                s.expunge(p)
            return p
    except Exception as exc:
        logger.warning(f"_find_payment failed: {exc}")
        return None


def _store_verified_payload(order_id: str, info: dict) -> None:
    """Persist the authoritative OxaPay inquiry response (bounded) for audit."""
    try:
        import json
        payload = json.dumps(info.get("raw") or info, default=str)[:_MAX_WEBHOOK_PAYLOAD]
        with db_session() as s:
            s.execute(
                update(Payment).where(Payment.order_id == order_id)
                .values(webhook_payload=payload)
            )
    except Exception:
        pass


def _aware(dt) -> datetime:
    """Coerce a (possibly naive) datetime to an aware UTC datetime for safe
    comparison. DB columns are timezone-aware, but this guards mixed inputs."""
    if dt is None:
        return datetime.now(timezone.utc)
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def _mark_status(order_id: str, status: str, error_reason: str = None) -> None:
    try:
        with db_session() as s:
            vals = {"status": status}
            if error_reason:
                vals["error_reason"] = str(error_reason)[:200]
            # Never downgrade an already-credited row.
            s.execute(
                update(Payment)
                .where(Payment.order_id == order_id, Payment.credited.is_(False))
                .values(**vals)
            )
    except Exception:
        pass


def _refresh_license_cache(license_key: str) -> None:
    """Re-read one license row and upsert the in-process active-license cache so
    is_license_active() reflects a just-credited reactivation immediately."""
    if not license_key:
        return
    from app.models import License
    from app.license_manager import upsert_license_cache, remove_license_cache
    with db_session() as s:
        lic = s.execute(
            select(License).where(License.license_key == license_key)
        ).scalar_one_or_none()
        if not lic:
            return
        if lic.active and not lic.banned:
            upsert_license_cache(license_key, {
                "active": True,
                "telegram_id": int(lic.telegram_id),
                "maximum_usernames": int(lic.maximum_usernames or Config.MAX_CONNECTIONS_PER_LICENSE),
                "theclaimers_count": int(lic.theclaimers_count or 0),
                "banned": bool(lic.banned),
                "manager_id": (lic.manager_id or ""),
                "available_balance": float(lic.available_balance or 0),
                "deduction_percentage": (float(lic.deduction_percentage) if lic.deduction_percentage is not None else None),
            })
        else:
            remove_license_cache(license_key)


def _epoch_to_dt(value) -> Optional[datetime]:
    if value is None:
        return None
    try:
        return datetime.fromtimestamp(int(value), tz=timezone.utc)
    except (TypeError, ValueError, OverflowError, OSError):
        return None
