"""
Customer-facing slot-sales API for the Telegram bot + Mini App (blueprint at
/api/cust). The buyer is a TELEGRAM USER ID that OWNS slots (ApiSlot.slot_telegram_id);
slots live under operator "pool" accounts (ApiAccount.is_pool, ≤ max_slots each).

Trust model (operator security review):
  * Every route is gated by x-internal-token = INTERNAL_API_SECRET — only the bot
    calls it, never the browser. The buyer's telegram_id is DERIVED by the bot from
    the validated Mini App initData JWT and passed over this trusted channel; the
    backend treats it as the authenticated identity and never accepts an id the
    browser could assert directly.
  * Ownership is re-checked on every owned resource (slot_telegram_id == tid).
  * Expiry is a LIVE predicate (status='active' AND expires_at > now()) on every
    slot-touching op — the sweep is cleanup, not the authorization boundary.
  * The pending Stake token is only ever held encrypted in ApiOrder until payment;
    it is moved to the slot on allocate and never returned to the client.
"""
from __future__ import annotations

import hmac
import logging
import time
import uuid
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone

from flask import Blueprint, jsonify, request
from sqlalchemy import and_, func, or_, select
from sqlalchemy.exc import IntegrityError

from app.config import Config
from app.database import db_session
from app.models import ApiAccount, ApiClaim, ApiOrder, ApiSlot
from app.plans import all_plans, get_plan, is_purchasable
from app.token_crypto import decrypt_token, encrypt_token

logger = logging.getLogger(__name__)

api_customer_bp = Blueprint('api_customer', __name__, url_prefix='/api/cust')


# ---------------------------------------------------------------------------
# Auth / identity
# ---------------------------------------------------------------------------
def _require_internal() -> bool:
    secret = Config.INTERNAL_API_SECRET or Config.MASTER_ACCOUNT_KEY
    provided = (request.headers.get('x-internal-token', '') or '')
    return bool(secret) and hmac.compare_digest(str(secret), str(provided))


def _tid_from_request(data: dict):
    """The buyer's telegram_id, provided by the trusted bot (from the validated
    Mini App JWT). Only reachable behind the internal-token gate."""
    raw = (data or {}).get('telegram_id')
    if raw is None:
        raw = request.args.get('telegram_id') or request.headers.get('x-telegram-id')
    try:
        tid = int(raw)
        return tid if tid > 0 else None
    except (TypeError, ValueError):
        return None


def _now():
    return datetime.now(timezone.utc)


def _unauth():
    return jsonify({'ok': False, 'error': 'unauthorized', 'code': 'unauthorized'}), 401


def _bad(msg, code='bad_request', status=400):
    return jsonify({'ok': False, 'error': msg, 'code': code}), status


# ---------------------------------------------------------------------------
# Capacity helpers
# ---------------------------------------------------------------------------
def _pool_accounts(session):
    return session.execute(
        select(ApiAccount).where(
            ApiAccount.is_pool.is_(True),
            ApiAccount.active.is_(True),
            ApiAccount.banned.is_(False),
        ).order_by(ApiAccount.id)
    ).scalars().all()


def _active_slot(slot, now) -> bool:
    return (slot.status == 'active'
            and (slot.expires_at is None or slot.expires_at > now))


def _occupied_indexes(session, account_id, now):
    """slot_index values held by a currently-active (non-expired) slot."""
    rows = session.execute(
        select(ApiSlot.slot_index).where(
            ApiSlot.account_id == account_id,
            ApiSlot.status == 'active',
            or_(ApiSlot.expires_at.is_(None), ApiSlot.expires_at > now),
        )
    ).scalars().all()
    return set(int(i) for i in rows)


def _reserved_indexes(session, account_id, now, exclude_order_id=None):
    """slot_index values held by a valid (unexpired) pending reservation."""
    q = select(ApiOrder.reserved_slot_index).where(
        ApiOrder.status == 'pending',
        ApiOrder.reserved_pool_account_id == account_id,
        ApiOrder.reservation_expires_at.isnot(None),
        ApiOrder.reservation_expires_at > now,
        ApiOrder.reserved_slot_index.isnot(None),
    )
    if exclude_order_id:
        q = q.where(ApiOrder.order_id != exclude_order_id)
    rows = session.execute(q).scalars().all()
    return set(int(i) for i in rows)


def _capacity(session, now):
    accts = _pool_accounts(session)
    pool_ids = [a.id for a in accts]
    total = sum(int(a.max_slots or 0) for a in accts)
    if not pool_ids:
        return {'total': 0, 'occupied': 0, 'reserved': 0, 'available': 0}
    occupied = int(session.execute(
        select(func.count(ApiSlot.id)).where(
            ApiSlot.account_id.in_(pool_ids),
            ApiSlot.status == 'active',
            or_(ApiSlot.expires_at.is_(None), ApiSlot.expires_at > now),
        )
    ).scalar() or 0)
    reserved = int(session.execute(
        select(func.count(ApiOrder.id)).where(
            ApiOrder.status == 'pending',
            ApiOrder.reserved_pool_account_id.in_(pool_ids),
            ApiOrder.reservation_expires_at.isnot(None),
            ApiOrder.reservation_expires_at > now,
        )
    ).scalar() or 0)
    available = max(0, total - occupied - reserved)
    return {'total': total, 'occupied': occupied, 'reserved': reserved,
            'available': available}


def _pick_free(session, now, exclude_order_id=None, prefer=None):
    """Return (account, slot_index) for a free pool slot, or (None, None).
    `prefer` = (account_id, slot_index) tried first (the buyer's own reservation)."""
    accts = _pool_accounts(session)
    by_id = {a.id: a for a in accts}
    if prefer:
        pa_id, pidx = prefer
        a = by_id.get(pa_id)
        if a and 0 <= pidx < a.max_slots:
            used = _occupied_indexes(session, a.id, now)
            resd = _reserved_indexes(session, a.id, now, exclude_order_id)
            if pidx not in used and pidx not in resd:
                return a, pidx
    for a in accts:
        used = _occupied_indexes(session, a.id, now)
        resd = _reserved_indexes(session, a.id, now, exclude_order_id)
        for idx in range(int(a.max_slots or 0)):
            if idx not in used and idx not in resd:
                return a, idx
    return None, None


def _customer_slot_view(slot, account, online):
    """Customer-safe slot view — NO raw token, only a friendly worker label."""
    return {
        'slot_id': slot.id,
        'stake_username': slot.stake_username,
        'plan': slot.plan,
        'status': slot.status,
        'expires_at': slot.expires_at.isoformat() if slot.expires_at else None,
        'withdrawal_currency': slot.withdrawal_currency,
        'reload_currency': slot.reload_currency,
        'auto_vault': bool(slot.auto_vault),
        'auto_bonus': bool(slot.auto_bonus),
        'auto_reload': bool(slot.auto_reload),
        'value_filter': slot.value_filter,
        'worker_label': (account.worker_label if account else None) or 'Worker',
        'online': bool(online),
    }


def _account_online(license_key) -> bool:
    try:
        from app.license_manager import license_sids
        return bool(license_sids(license_key))
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Verify-token rate limit (per telegram_id, in-memory)
# ---------------------------------------------------------------------------
_verify_hits = defaultdict(deque)


def _verify_rate_ok(tid) -> bool:
    now = time.time()
    dq = _verify_hits[tid]
    while dq and dq[0] < now - 60:
        dq.popleft()
    if len(dq) >= Config.VERIFY_RATE_PER_MIN:
        return False
    dq.append(now)
    return True


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@api_customer_bp.route('/capacity', methods=['GET'])
def capacity():
    if not _require_internal():
        return _unauth()
    with db_session() as s:
        cap = _capacity(s, _now())
    return jsonify({'ok': True, **cap, 'plans': all_plans()}), 200


@api_customer_bp.route('/verify-token', methods=['POST'])
def verify_token():
    if not _require_internal():
        return _unauth()
    data = request.get_json(silent=True) or {}
    tid = _tid_from_request(data)
    if not tid:
        return _bad('telegram_id required')
    if not _verify_rate_ok(tid):
        return jsonify({'ok': False, 'valid': False, 'reason': 'rate_limited'}), 429
    token = (data.get('token') or '').strip()
    if not token:
        return jsonify({'ok': True, 'valid': False, 'reason': 'invalid'}), 200
    from app.routes.tmc_routes import verify_token_via_worker
    res = verify_token_via_worker(token)   # token never logged/persisted here
    return jsonify({'ok': True, **res}), 200


@api_customer_bp.route('/slots', methods=['GET'])
def list_slots():
    if not _require_internal():
        return _unauth()
    tid = _tid_from_request(None)
    if not tid:
        return _bad('telegram_id required')
    now = _now()
    with db_session() as s:
        rows = s.execute(
            select(ApiSlot, ApiAccount)
            .join(ApiAccount, ApiAccount.id == ApiSlot.account_id)
            .where(ApiSlot.slot_telegram_id == tid)
            .order_by(ApiSlot.expires_at.desc().nullslast())
        ).all()
        out = []
        for slot, account in rows:
            online = _account_online(account.license_key) if _active_slot(slot, now) else False
            v = _customer_slot_view(slot, account, online)
            v['expired'] = not _active_slot(slot, now)
            out.append(v)
    return jsonify({'ok': True, 'slots': out}), 200


@api_customer_bp.route('/slots/<int:slot_id>/config', methods=['POST'])
def slot_config(slot_id):
    if not _require_internal():
        return _unauth()
    data = request.get_json(silent=True) or {}
    tid = _tid_from_request(data)
    if not tid:
        return _bad('telegram_id required')
    now = _now()
    new_token = (data.get('stake_access_token') or '').strip() or None

    # A key change is verify-relayed BEFORE it can overwrite a working key.
    new_username = None
    if new_token:
        from app.routes.tmc_routes import verify_token_via_worker
        res = verify_token_via_worker(new_token)
        if not res.get('valid'):
            reason = res.get('reason', 'invalid')
            return jsonify({'ok': False, 'code': 'verify_' + reason,
                            'error': 'new API key could not be verified'}), 400
        new_username = res.get('username')

    with db_session() as s:
        slot = s.get(ApiSlot, slot_id)
        if not slot or slot.slot_telegram_id != tid:
            return jsonify({'ok': False, 'code': 'not_found', 'error': 'not found'}), 404
        if not _active_slot(slot, now):
            return jsonify({'ok': False, 'code': 'expired', 'error': 'slot expired'}), 403
        account = s.get(ApiAccount, slot.account_id)

        # Non-secret config (only fields provided).
        for f in ('withdrawal_currency', 'reload_currency', 'value_filter'):
            if f in data:
                setattr(slot, f, data[f])
        for f in ('auto_vault', 'auto_bonus', 'auto_reload'):
            if f in data:
                setattr(slot, f, bool(data[f]))
        # Verified key change → swap token + username atomically; else untouched.
        if new_token:
            from app.routes.api_slots import _token_fp
            slot.stake_access_token = new_token
            slot.token_fp = _token_fp(new_token)
            slot.stake_username = new_username
            slot.token_valid = True
        s.flush()
        account_key = account.license_key if account else None

    if account_key:
        try:
            from app.routes.tmc_routes import push_slots_to_account
            push_slots_to_account(account_key)
        except Exception:
            logger.exception('push after slot config failed (ignored)')
    return jsonify({'ok': True}), 200


@api_customer_bp.route('/stats', methods=['GET'])
def stats():
    if not _require_internal():
        return _unauth()
    tid = _tid_from_request(None)
    if not tid:
        return _bad('telegram_id required')
    window = (request.args.get('window') or '24h').lower()
    ctype = (request.args.get('type') or 'all').lower()
    now = _now()
    since = {'24h': now - timedelta(hours=24),
             '7d': now - timedelta(days=7),
             '30d': now - timedelta(days=30)}.get(window, now - timedelta(hours=24))

    with db_session() as s:
        slot_ids = s.execute(
            select(ApiSlot.id).where(ApiSlot.slot_telegram_id == tid)
        ).scalars().all()
        if not slot_ids:
            return jsonify({'ok': True, 'window': window, 'earned': {},
                            'successful_claims': 0, 'recent_codes': []}), 200

        # Type filter maps to the recorded currency semantics we have: reload vs
        # drop is carried on the claim via error_code/currency context; we filter
        # by couponType-equivalent when present, else include all.
        base = [ApiClaim.slot_id.in_(slot_ids), ApiClaim.created_at >= since]

        # Earnings grouped PER CURRENCY (never cross-summed).
        earned_rows = s.execute(
            select(ApiClaim.currency, func.coalesce(func.sum(ApiClaim.amount), 0.0),
                   func.count(ApiClaim.id))
            .where(and_(*base, ApiClaim.claimed.is_(True)))
            .group_by(ApiClaim.currency)
        ).all()
        earned = {}
        successful = 0
        for cur, amt, cnt in earned_rows:
            key = (cur or 'unknown').lower()
            earned[key] = round(float(amt or 0.0), 8)
            successful += int(cnt or 0)

        # Recent attempts (last 7 days regardless of window filter, capped).
        recent = s.execute(
            select(ApiClaim.code_norm, ApiClaim.claimed, ApiClaim.error_code,
                   ApiClaim.currency, ApiClaim.amount, ApiClaim.created_at)
            .where(ApiClaim.slot_id.in_(slot_ids),
                   ApiClaim.created_at >= now - timedelta(days=7))
            .order_by(ApiClaim.created_at.desc())
            .limit(100)
        ).all()
        recent_codes = [{
            'code': c, 'claimed': bool(cl),
            'result': ('claimed' if cl else (err or 'not claimed')),
            'currency': (cur or None), 'amount': (float(a) if a is not None else None),
            'ts': ts.isoformat() if ts else None,
        } for (c, cl, err, cur, a, ts) in recent]

    return jsonify({'ok': True, 'window': window, 'type': ctype,
                    'earned': earned, 'successful_claims': successful,
                    'recent_codes': recent_codes}), 200


@api_customer_bp.route('/drop', methods=['POST'])
def drop():
    if not _require_internal():
        return _unauth()
    data = request.get_json(silent=True) or {}
    tid = _tid_from_request(data)
    if not tid:
        return _bad('telegram_id required')
    code = (data.get('code') or '').strip()
    if not code:
        return _bad('code required')
    coupon_type = 'bonus' if str(data.get('couponType') or '').lower() == 'bonus' else 'drop'
    now = _now()

    # Backend resolves the buyer's OWN active, non-expired slots → group by pool
    # account → emit a slot-scoped drop. Client-supplied targets are ignored.
    with db_session() as s:
        rows = s.execute(
            select(ApiSlot, ApiAccount)
            .join(ApiAccount, ApiAccount.id == ApiSlot.account_id)
            .where(ApiSlot.slot_telegram_id == tid,
                   ApiSlot.status == 'active',
                   or_(ApiSlot.expires_at.is_(None), ApiSlot.expires_at > now))
        ).all()
        by_account = defaultdict(list)
        for slot, account in rows:
            by_account[account.license_key].append(slot.id)

    if not by_account:
        return jsonify({'ok': True, 'delivered': 0, 'slots': 0}), 200

    from app.routes.tmc_routes import emit_drop_to_slots
    delivered = 0
    total_slots = 0
    for lk, slot_ids in by_account.items():
        total_slots += len(slot_ids)
        try:
            delivered += int(emit_drop_to_slots(lk, code, slot_ids, coupon_type) or 0)
        except Exception:
            logger.exception('emit_drop_to_slots failed (ignored)')
    return jsonify({'ok': True, 'delivered': delivered, 'slots': total_slots}), 200


@api_customer_bp.route('/order/begin', methods=['POST'])
def order_begin():
    if not _require_internal():
        return _unauth()
    data = request.get_json(silent=True) or {}
    tid = _tid_from_request(data)
    if not tid:
        return _bad('telegram_id required')
    plan_code = (data.get('plan_code') or '').strip()
    plan = get_plan(plan_code)
    if not plan:
        return _bad('unknown plan', 'unknown_plan')
    if not is_purchasable(plan_code):
        return _bad('plan not available yet', 'plan_unavailable')
    token = (data.get('token') or '').strip()
    if not token:
        return _bad('API key required')

    # Re-verify the key (also snapshots the username) before creating the order.
    from app.routes.tmc_routes import verify_token_via_worker
    vres = verify_token_via_worker(token)
    if not vres.get('valid'):
        return _bad('API key could not be verified', 'verify_' + vres.get('reason', 'invalid'))
    username = vres.get('username')

    config = data.get('config') if isinstance(data.get('config'), dict) else {}
    import json as _json
    now = _now()
    with db_session() as s:
        cap = _capacity(s, now)
        if cap['available'] <= 0:
            return _bad('no slots available right now', 'no_capacity', 409)

        # One active reservation per buyer — supersede any prior pending order.
        prior = s.execute(
            select(ApiOrder).where(ApiOrder.telegram_id == tid,
                                   ApiOrder.status == 'pending')
        ).scalars().all()
        for p in prior:
            p.status = 'reservation_expired'
            p.enc_stake_token = None
            p.reserved_pool_account_id = None
            p.reserved_slot_index = None
            p.reservation_expires_at = None

        # Reservation gating: only buyers with a prior successful (allocated)
        # purchase hold a hard reservation; new users are re-checked at allocate.
        has_prior_payment = bool(s.execute(
            select(func.count(ApiOrder.id)).where(ApiOrder.telegram_id == tid,
                                                  ApiOrder.status == 'allocated')
        ).scalar() or 0)

        reserved_acct_id = None
        reserved_idx = None
        reservation_expires = None
        if has_prior_payment:
            acct, idx = _pick_free(s, now)
            if acct is not None:
                reserved_acct_id = acct.id
                reserved_idx = idx
                reservation_expires = now + timedelta(seconds=Config.RESERVATION_TTL_S)

        order_id = uuid.uuid4().hex
        order = ApiOrder(
            order_id=order_id, telegram_id=tid, plan_code=plan_code,
            price_usd=float(plan['price_usd']), duration_days=int(plan['duration_days']),
            stake_username=username, slot_config=_json.dumps(config),
            enc_stake_token=encrypt_token(token), status='pending',
            reserved_pool_account_id=reserved_acct_id, reserved_slot_index=reserved_idx,
            reservation_expires_at=reservation_expires,
        )
        s.add(order)
        s.flush()

    return jsonify({'ok': True, 'order_id': order_id,
                    'price_usd': float(plan['price_usd']),
                    'plan': {'code': plan_code, 'label': plan['label'],
                             'duration_days': plan['duration_days']},
                    'stake_username': username}), 200


@api_customer_bp.route('/order/allocate', methods=['POST'])
def order_allocate():
    """Called by the bot's OxaPay credit worker AFTER payment is verified.
    Idempotent + payment-integrity gated. Body:
      {order_id, paid_amount, paid_currency, track_id, status}
    """
    if not _require_internal():
        return _unauth()
    data = request.get_json(silent=True) or {}
    order_id = (data.get('order_id') or '').strip()
    if not order_id:
        return _bad('order_id required')
    paid_amount = data.get('paid_amount')
    paid_currency = (data.get('paid_currency') or Config.OXAPAY_CURRENCY or 'USD').upper()
    track_id = (data.get('track_id') or '').strip() or None
    pay_status = (data.get('status') or '').lower()
    now = _now()

    for attempt in range(4):
        try:
            with db_session() as s:
                order = s.execute(
                    select(ApiOrder).where(ApiOrder.order_id == order_id)
                    .with_for_update()
                ).scalar_one_or_none()
                if not order:
                    return jsonify({'ok': False, 'code': 'not_found',
                                    'error': 'order not found'}), 404

                # Idempotent: already allocated → return the same slot.
                if order.status == 'allocated':
                    return jsonify({'ok': True, 'already_allocated': True,
                                    'slot_id': order.slot_id}), 200
                if order.status not in ('pending', 'paid'):
                    return jsonify({'ok': False, 'code': 'bad_state',
                                    'error': f'order is {order.status}'}), 409

                # Payment-integrity gate — the browser can't have changed these.
                if pay_status and pay_status not in ('paid', 'confirmed', 'complete', 'completed'):
                    return jsonify({'ok': False, 'code': 'not_paid',
                                    'error': 'payment not confirmed'}), 402
                if paid_amount is not None:
                    try:
                        if float(paid_amount) + 1e-6 < float(order.price_usd):
                            return jsonify({'ok': False, 'code': 'amount_mismatch',
                                            'error': 'paid amount below price'}), 402
                    except (TypeError, ValueError):
                        return jsonify({'ok': False, 'code': 'amount_mismatch',
                                        'error': 'bad paid amount'}), 402
                order.status = 'paid'
                order.track_id = track_id or order.track_id

                token = decrypt_token(order.enc_stake_token)
                if not token:
                    order.status = 'failed'
                    return jsonify({'ok': False, 'code': 'token_lost',
                                    'error': 'pending token unavailable'}), 500

                acct, idx = _pick_free(
                    s, now, exclude_order_id=order.order_id,
                    prefer=((order.reserved_pool_account_id, order.reserved_slot_index)
                            if order.reserved_pool_account_id is not None
                            and order.reserved_slot_index is not None else None))
                if acct is None:
                    order.status = 'failed'
                    logger.error(f"allocate: NO capacity for paid order {order_id} — refund needed")
                    return jsonify({'ok': False, 'code': 'no_capacity',
                                    'error': 'no free slot — refund required'}), 409

                import json as _json
                try:
                    cfg = _json.loads(order.slot_config or '{}')
                except Exception:
                    cfg = {}

                # Reuse an existing (expired/revoked) row at this index, else create.
                slot = s.execute(
                    select(ApiSlot).where(ApiSlot.account_id == acct.id,
                                          ApiSlot.slot_index == idx)
                ).scalar_one_or_none()
                if slot is None:
                    slot = ApiSlot(account_id=acct.id, slot_index=idx)
                    s.add(slot)

                from app.routes.api_slots import _token_fp
                slot.slot_telegram_id = order.telegram_id
                slot.stake_access_token = token
                slot.token_fp = _token_fp(token)
                slot.stake_username = order.stake_username
                slot.token_valid = True
                slot.withdrawal_currency = cfg.get('withdrawal_currency') or 'usdt'
                slot.reload_currency = cfg.get('reload_currency') or 'usdt'
                slot.auto_vault = bool(cfg.get('auto_vault'))
                slot.auto_bonus = bool(cfg.get('auto_bonus'))
                slot.auto_reload = bool(cfg.get('auto_reload'))
                slot.value_filter = cfg.get('value_filter')
                slot.plan = order.plan_code
                slot.purchased_at = now
                slot.expires_at = now + timedelta(days=int(order.duration_days))
                slot.status = 'active'
                s.flush()   # assign slot.id (unique (account,index) guards races)

                order.slot_id = slot.id
                order.status = 'allocated'
                order.enc_stake_token = None                     # secure wipe
                order.reserved_pool_account_id = None
                order.reserved_slot_index = None
                order.reservation_expires_at = None
                account_key = acct.license_key
                slot_id = slot.id

            # Committed → push the new slot to the operator's script(s).
            try:
                from app.routes.tmc_routes import push_slots_to_account
                push_slots_to_account(account_key)
            except Exception:
                logger.exception('push after allocate failed (ignored)')
            return jsonify({'ok': True, 'slot_id': slot_id}), 200

        except IntegrityError:
            # Lost the (account,index) race to another order → retry a new pick.
            logger.warning(f"allocate: index race for order {order_id}, retry {attempt}")
            continue
    return jsonify({'ok': False, 'code': 'contention',
                    'error': 'could not allocate, retry'}), 503


@api_customer_bp.route('/order/<order_id>', methods=['GET'])
def order_status(order_id):
    if not _require_internal():
        return _unauth()
    # Optional ownership scope: when the bot passes the buyer's telegram_id, only
    # that buyer may read the order (prevents polling someone else's order_id).
    tid = _tid_from_request(None)
    with db_session() as s:
        order = s.execute(
            select(ApiOrder).where(ApiOrder.order_id == order_id)
        ).scalar_one_or_none()
        if not order or (tid is not None and order.telegram_id != tid):
            return jsonify({'ok': False, 'code': 'not_found'}), 404
        # Status ONLY — never the token or any secret.
        return jsonify({'ok': True, 'order_id': order.order_id,
                        'status': order.status, 'slot_id': order.slot_id,
                        'plan_code': order.plan_code,
                        'price_usd': order.price_usd,
                        'stake_username': order.stake_username}), 200
