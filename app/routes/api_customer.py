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
    """The sellable pool = accounts with a LIVE userscript connection (active,
    not banned). This is the ALLOCATION AUTHORITY — computed from the DB + live
    connection state, never from the display poll. Any connected userscript's
    account is eligible; no manual is_pool flag required."""
    from app.license_manager import connected_account_keys
    keys = connected_account_keys()
    if not keys:
        return []
    return session.execute(
        select(ApiAccount).where(
            ApiAccount.license_key.in_(keys),
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
    # Live reload status reported by the userscript (None = unknown/stale).
    rs = None
    try:
        from app.routes.tmc_routes import get_slot_reload_status
        rs = get_slot_reload_status(slot.id)
    except Exception:
        rs = None
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
        # Reload status for the Mini App (None when unknown).
        'reload_available': (bool(rs.get('available')) if rs else None),
        'reload_next_ms': (rs.get('next_claim_ms') if rs else None),
        'reload_unavailable': bool(rs is not None and not rs.get('available')),
    }


def _account_online(license_key) -> bool:
    try:
        from app.license_manager import license_sids
        return bool(license_sids(license_key))
    except Exception:
        return False


# Poll-backed DISPLAY capacity (cached). Never the allocation authority.
_cap_poll_cache = {'available': None, 'ts': 0.0}
_CAP_POLL_TTL = 45.0


def _get_polled_available() -> int:
    """Aggregate empty slots reported by connected userscripts (~5s poll), cached
    ~45s so only the first request after expiry pays the poll latency. Display-only."""
    global _cap_poll_cache
    now_t = time.time()
    if (_cap_poll_cache['available'] is not None
            and (now_t - _cap_poll_cache['ts']) < _CAP_POLL_TTL):
        return int(_cap_poll_cache['available'])
    polled = 0
    try:
        from app.routes.tmc_routes import poll_live_capacity
        polled = int(poll_live_capacity(timeout=5).get('available', 0))
    except Exception:
        logger.exception('capacity poll failed (ignored)')
    _cap_poll_cache = {'available': polled, 'ts': now_t}
    return polled


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
    now = _now()
    # DISPLAY number = live poll of connected userscripts (cached ~45s). This is
    # informational only; it never authorizes an allocation (order/begin +
    # order/allocate re-check the DB + live connections themselves).
    polled = _get_polled_available()          # no DB held during the ~5s poll
    with db_session() as s:
        reserved = int(s.execute(
            select(func.count(ApiOrder.id)).where(
                ApiOrder.status == 'pending',
                ApiOrder.reservation_expires_at.isnot(None),
                ApiOrder.reservation_expires_at > now,
            )
        ).scalar() or 0)
        dbcap = _capacity(s, now)             # DB-authoritative (reference)
    available = max(0, polled - reserved)
    return jsonify({'ok': True, 'available': available, 'reserved': reserved,
                    'total': dbcap['total'], 'occupied': dbcap['occupied'],
                    'plans': all_plans()}), 200


@api_customer_bp.route('/verify-token', methods=['POST'])
def verify_token():
    if not _require_internal():
        return _unauth()
    data = request.get_json(silent=True) or {}
    tid = _tid_from_request(data)
    if not tid:
        return _bad('telegram_id required')
    if not _verify_rate_ok(tid):
        # Opaque: never surface "rate_limited" — reuse the neutral 'unavailable'
        # reason (frontend shows a friendly "try again shortly"), status 200.
        return jsonify({'ok': True, 'valid': False, 'reason': 'unavailable'}), 200
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
        # Scope by the IMMUTABLE per-claim ownership snapshot (telegram_id), NOT by
        # currently-owned slot_ids. This is the privacy boundary AND the retention
        # guarantee: a buyer sees exactly THEIR OWN claims for the full window even
        # after their slot expired and its slot_id was reused by a new buyer (the
        # new buyer, in turn, only ever sees claims stamped with their own tid). A
        # reused slot can therefore never leak the previous owner's history.
        # Per-TYPE split for the Drops vs Reloads tabs. 'drop' includes bonus and
        # legacy NULL rows (they were code drops); NULL != 'reload' is UNKNOWN in
        # SQL, so include NULL explicitly. 'reload' is exact. 'all' → no type filter.
        type_conds = []
        if ctype == 'drop':
            type_conds = [or_(ApiClaim.claim_type != 'reload',
                              ApiClaim.claim_type.is_(None))]
        elif ctype == 'reload':
            type_conds = [ApiClaim.claim_type == 'reload']
        base = [ApiClaim.telegram_id == tid, ApiClaim.created_at >= since, *type_conds]

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

        # Per-USERNAME earnings over the SAME window, so the buyer sees which Stake
        # account claimed how much (works for 24h/7d/30d — windowed identically to
        # the overall total). Shape: {username: {currency: amount, ...}, ...}.
        by_user_rows = s.execute(
            select(ApiClaim.slot_username, ApiClaim.currency,
                   func.coalesce(func.sum(ApiClaim.amount), 0.0))
            .where(and_(*base, ApiClaim.claimed.is_(True)))
            .group_by(ApiClaim.slot_username, ApiClaim.currency)
        ).all()
        earned_by_user = {}
        for uname, cur, amt in by_user_rows:
            amt = round(float(amt or 0.0), 8)
            if amt <= 0:
                continue
            earned_by_user.setdefault(uname or '?', {})[(cur or 'unknown').lower()] = amt

        # Recent attempts (last 7 days), DETERMINISTICALLY ordered — the id DESC
        # secondary key means rows with an identical created_at never reorder
        # between requests. Fetch CAP+1 so we can truthfully report truncation
        # (exactly-CAP is NOT flagged; only a genuine CAP+1th row is).
        _CAP = 50
        recent = s.execute(
            select(ApiClaim.code_norm, ApiClaim.claimed, ApiClaim.error_code,
                   ApiClaim.currency, ApiClaim.amount, ApiClaim.created_at,
                   ApiClaim.claim_type, ApiClaim.slot_username)
            .where(ApiClaim.telegram_id == tid,
                   ApiClaim.created_at >= now - timedelta(days=7),
                   *type_conds)
            .order_by(ApiClaim.created_at.desc(), ApiClaim.id.desc())
            .limit(_CAP + 1)
        ).all()
        recent_truncated = len(recent) > _CAP
        recent = recent[:_CAP]
        recent_codes = [{
            # Reloads use a synthetic key internally — show a clean 'Reload' label.
            'code': ('Reload' if ct == 'reload' else c),
            'claimed': bool(cl),
            'result': ('claimed' if cl else (err or 'not claimed')),
            'currency': (cur or None), 'amount': (float(a) if a is not None else None),
            'ts': ts.isoformat() if ts else None,
            'type': (ct or 'drop'),
            'username': (uname or None),
        } for (c, cl, err, cur, a, ts, ct, uname) in recent]

    return jsonify({'ok': True, 'window': window, 'type': ctype,
                    'earned': earned, 'earned_by_user': earned_by_user,
                    'successful_claims': successful,
                    'recent_codes': recent_codes,
                    'recent_truncated': recent_truncated}), 200


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


def _allocate_order(order_id, track_id=None, pay_status=None,
                    paid_amount=None, paid_currency=None):
    """Core allocation — shared by POST /order/allocate and the reconcile sweep.
    Returns (payload_dict, http_status). Idempotent, payment-integrity gated, and
    transactional (FOR UPDATE + unique (account,index)). All OxaPay I/O happens
    OUTSIDE the row lock."""
    now = _now()
    if pay_status:
        pay_status = pay_status.lower()
    verified_by_backend = False

    # Reconcile path: no track_id passed → read the one stored at invoice time.
    if not track_id:
        with db_session() as s:
            row = s.execute(
                select(ApiOrder.track_id).where(ApiOrder.order_id == order_id)
            ).first()
            track_id = (row[0] if row else None)

    # DEFENSE-IN-DEPTH (matches the legacy backend): with our OWN OxaPay key we
    # INDEPENDENTLY re-verify the invoice (eventlet-safe curl get_payment) and use
    # THAT as authoritative — never trusting the bot-passed amount/status. No key
    # configured → fall back to the (internal-token-gated) bot-passed values.
    if Config.OXAPAY_MERCHANT_KEY and track_id:
        try:
            from app import oxapay as _oxa
            info = _oxa.get_payment(track_id)
        except Exception:
            info = {'ok': False}
        if not info.get('ok'):
            return {'ok': False, 'code': 'verify_unavailable',
                    'error': 'could not verify payment, retry'}, 503
        st = (info.get('status') or '').lower()
        if st not in _oxa.PAID_STATUSES:
            return {'ok': False, 'code': 'not_paid',
                    'error': f'payment status={st or "unknown"}'}, 402
        pay_status = st
        verified_by_backend = True
        if info.get('amount') is not None:
            paid_amount = info.get('amount')
        if info.get('currency'):
            paid_currency = str(info.get('currency')).upper()

    # POSITIVE-PROOF REQUIREMENT: never allocate without evidence of payment. If
    # the backend did NOT independently verify (no key / no track_id), the caller
    # (the internal-token-gated bot) MUST assert a paid status — otherwise refuse.
    # Closes a free-slot path when allocate is called with no payment info.
    if not verified_by_backend:
        if not pay_status or pay_status not in ('paid', 'confirmed', 'complete', 'completed'):
            return {'ok': False, 'code': 'not_paid',
                    'error': 'no payment proof (backend has no OxaPay key and no paid status supplied)'}, 402

    for attempt in range(4):
        try:
            account_key = None
            slot_id = None
            with db_session() as s:
                order = s.execute(
                    select(ApiOrder).where(ApiOrder.order_id == order_id)
                    .with_for_update()
                ).scalar_one_or_none()
                if not order:
                    return {'ok': False, 'code': 'not_found', 'error': 'order not found'}, 404
                if order.status == 'allocated':
                    return {'ok': True, 'already_allocated': True, 'slot_id': order.slot_id}, 200
                if order.status not in ('pending', 'paid'):
                    return {'ok': False, 'code': 'bad_state', 'error': f'order is {order.status}'}, 409

                # Payment-integrity gate.
                if pay_status and pay_status not in ('paid', 'confirmed', 'complete', 'completed'):
                    return {'ok': False, 'code': 'not_paid', 'error': 'payment not confirmed'}, 402
                if paid_amount is not None:
                    try:
                        if float(paid_amount) + 1e-6 < float(order.price_usd):
                            return {'ok': False, 'code': 'amount_mismatch',
                                    'error': 'paid amount below price'}, 402
                    except (TypeError, ValueError):
                        return {'ok': False, 'code': 'amount_mismatch', 'error': 'bad paid amount'}, 402
                order.status = 'paid'
                order.track_id = track_id or order.track_id

                token = decrypt_token(order.enc_stake_token)
                if not token:
                    order.status = 'failed'
                    return {'ok': False, 'code': 'token_lost', 'error': 'pending token unavailable'}, 500

                acct, idx = _pick_free(
                    s, now, exclude_order_id=order.order_id,
                    prefer=((order.reserved_pool_account_id, order.reserved_slot_index)
                            if order.reserved_pool_account_id is not None
                            and order.reserved_slot_index is not None else None))
                if acct is None:
                    order.status = 'failed'
                    logger.error(f"allocate: NO capacity for paid order {order_id} — refund needed")
                    return {'ok': False, 'code': 'no_capacity', 'error': 'no free slot — refund required'}, 409

                import json as _json
                try:
                    cfg = _json.loads(order.slot_config or '{}')
                except Exception:
                    cfg = {}

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
            return {'ok': True, 'slot_id': slot_id}, 200

        except IntegrityError:
            logger.warning(f"allocate: index race for order {order_id}, retry {attempt}")
            continue
    return {'ok': False, 'code': 'contention', 'error': 'could not allocate, retry'}, 503


@api_customer_bp.route('/order/track', methods=['POST'])
def order_track():
    """Persist the OxaPay track_id on a pending order at invoice-creation time so
    the reconcile sweep can recover a MISSED webhook (buyer paid, callback lost)."""
    if not _require_internal():
        return _unauth()
    data = request.get_json(silent=True) or {}
    order_id = (data.get('order_id') or '').strip()
    track_id = (data.get('track_id') or '').strip()
    if not order_id or not track_id:
        return _bad('order_id and track_id required')
    with db_session() as s:
        order = s.execute(
            select(ApiOrder).where(ApiOrder.order_id == order_id).with_for_update()
        ).scalar_one_or_none()
        if not order:
            return jsonify({'ok': False, 'code': 'not_found'}), 404
        if order.status == 'pending':
            order.track_id = track_id
    return jsonify({'ok': True}), 200


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
    payload, status = _allocate_order(
        order_id,
        track_id=(data.get('track_id') or '').strip() or None,
        pay_status=(data.get('status') or '').lower() or None,
        paid_amount=data.get('paid_amount'),
        paid_currency=(data.get('paid_currency') or None))
    return jsonify(payload), status


def reconcile_pending_orders(max_age_min=180):
    """Recover MISSED OxaPay webhooks: for each pending order that has a stored
    track_id (invoice was created) and is recent, re-verify with OxaPay and
    allocate if paid. Backend-side (it holds the OxaPay key) — mirrors the bot's
    legacy reconcile loop. Only runs when an OxaPay key is configured."""
    if not Config.OXAPAY_MERCHANT_KEY:
        return 0
    now = _now()
    cutoff = now - timedelta(minutes=max_age_min)
    with db_session() as s:
        rows = s.execute(
            select(ApiOrder.order_id).where(
                ApiOrder.status == 'pending',
                ApiOrder.track_id.isnot(None),
                ApiOrder.created_at >= cutoff)
            .limit(50)
        ).scalars().all()
    done = 0
    for oid in rows:
        try:
            payload, _ = _allocate_order(oid)   # verifies via stored track_id
            if payload.get('ok'):
                done += 1
        except Exception:
            logger.exception(f"reconcile: order {oid} failed (ignored)")
    return done


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
