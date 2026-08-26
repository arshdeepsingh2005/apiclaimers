"""
API-Claimer product — account + slot registry, broadcast, and claim recording.

Mounted at /api (blueprint `api_slots_bp`). All slot routes are authed by the
ACCOUNT JWT (the operator-entered "userscript value" = api_accounts.license_key,
exchanged for a short-lived JWT via POST /api/account/token). The account is the
identity; a slot's stable `slot_id` (backend-assigned) is the claim/dedup key.

Design notes:
  * The backend NEVER calls Stake to resolve a username (avoids the eventlet-SSL/
    curl path). The userscript resolves the username client-side (it already has
    _fetchUsernameWithToken) and reports it when saving a slot; we store it as
    mutable metadata under the fixed slot_id.
  * Raw Stake tokens are stored (operator revokes on leak); RLS + a restricted DB
    role are the DB-level controls (see the RLS migration).
  * Broadcast reuses the existing license-room fan-out keyed by the account's
    license_key (sessions are stored under it), so a customer broadcasts a code
    to ONLY their own connected slots.
"""
from __future__ import annotations

import hashlib
import hmac
import logging

from flask import Blueprint, jsonify, request
from sqlalchemy import select

from app.config import Config
from app.database import db_session
from app.models import ApiAccount, ApiSlot, ApiClaim

logger = logging.getLogger(__name__)

api_slots_bp = Blueprint('api_slots', __name__, url_prefix='/api')


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _token_fp(token: str) -> str:
    if not token:
        return ''
    return hashlib.sha256(token.encode('utf-8')).hexdigest()[:16]


def _bearer_token() -> str:
    h = request.headers.get('Authorization', '') or ''
    if h.lower().startswith('bearer '):
        return h[7:].strip()
    # fall back to an explicit header the userscript may send
    return (request.headers.get('x-account-token', '') or '').strip()


def _account_from_request(session):
    """Validate the account JWT and return the (active, non-banned) ApiAccount
    row bound to this session, or (None, error_response, status)."""
    from app.license_manager import validate_jwt, resolve_api_account
    payload = validate_jwt(_bearer_token())
    if not payload:
        return None, jsonify({'error': 'unauthorized', 'code': 'unauthorized'}), 401
    license_key = (payload.get('license_id') or '').strip()
    if not license_key:
        return None, jsonify({'error': 'unauthorized', 'code': 'unauthorized'}), 401
    acct = resolve_api_account(session, license_key)   # auto-provisions master key
    if acct is None or not acct.active or acct.banned:
        return None, jsonify({'error': 'account_inactive', 'code': 'account_inactive'}), 403
    return acct, None, None


def _slot_public(slot: ApiSlot) -> dict:
    """What the userscript needs to run a slot — includes the raw token (the
    backend is the source of truth; the script restores everything from here)."""
    return {
        'slot_id': slot.id,
        'slot_index': slot.slot_index,
        'slot_telegram_id': slot.slot_telegram_id,
        'stake_access_token': slot.stake_access_token,   # raw (source of truth)
        'stake_username': slot.stake_username,
        'token_valid': bool(slot.token_valid),
        'withdrawal_currency': slot.withdrawal_currency,
        'reload_currency': slot.reload_currency,
        'auto_vault': bool(slot.auto_vault),
        'auto_bonus': bool(slot.auto_bonus),
        'auto_reload': bool(slot.auto_reload),
        'value_filter': slot.value_filter,
        'status': slot.status,
        'expires_at': slot.expires_at.isoformat() if slot.expires_at else None,
    }


# ---------------------------------------------------------------------------
# Account token — exchange the account credential ("userscript value") for a JWT
# ---------------------------------------------------------------------------
def _require_admin() -> bool:
    """Admin gate for the license-management endpoints. Matches the
    x-admin-token header against INTERNAL_API_SECRET (preferred) or, if that's
    unset, the master key."""
    secret = Config.INTERNAL_API_SECRET or Config.MASTER_ACCOUNT_KEY
    provided = (request.headers.get('x-admin-token', '')
                or request.args.get('admin_token', '') or '')
    return bool(secret) and hmac.compare_digest(str(secret), str(provided))


@api_slots_bp.route('/admin/accounts', methods=['GET', 'POST'])
def admin_accounts():
    """List or create/activate API-Claimer licenses (accounts). This IS your
    'license table' management. Auth: header x-admin-token = INTERNAL_API_SECRET
    (or the master key if that's unset).

      POST body: { license_key, active?=true, max_slots?=7, max_connections?=2 }
      GET      : list all accounts (id, license_key, active, max_slots).
    """
    if not _require_admin():
        return jsonify({'error': 'unauthorized', 'code': 'unauthorized'}), 401
    with db_session() as s:
        if request.method == 'POST':
            data = request.get_json(silent=True) or {}
            key = (data.get('license_key') or '').strip()
            if not key:
                return jsonify({'error': 'license_key required'}), 400
            acct = s.execute(
                select(ApiAccount).where(ApiAccount.license_key == key)
            ).scalar_one_or_none()
            if acct is None:
                acct = ApiAccount(license_key=key)
                s.add(acct)
            acct.active = bool(data.get('active', True))
            acct.banned = bool(data.get('banned', False))
            acct.max_slots = int(data.get('max_slots', 7))
            acct.max_connections = int(data.get('max_connections', 2))
            # Operator sellable-capacity pool + customer-safe worker label.
            if 'is_pool' in data:
                acct.is_pool = bool(data.get('is_pool'))
            if 'worker_label' in data:
                acct.worker_label = (data.get('worker_label') or None)
            s.flush()
            return jsonify({'ok': True, 'id': acct.id, 'license_key': key,
                            'active': acct.active, 'max_slots': acct.max_slots,
                            'is_pool': bool(acct.is_pool),
                            'worker_label': acct.worker_label}), 200
        rows = s.execute(select(ApiAccount).order_by(ApiAccount.id)).scalars().all()
        return jsonify({'accounts': [
            {'id': a.id, 'license_key': a.license_key, 'active': a.active,
             'banned': a.banned, 'max_slots': a.max_slots,
             'is_pool': bool(a.is_pool), 'worker_label': a.worker_label} for a in rows]}), 200


@api_slots_bp.route('/account/token', methods=['POST'])
def account_token():
    data = request.get_json(silent=True) or {}
    license_key = (data.get('license_key') or data.get('account') or '').strip()
    if not license_key:
        return jsonify({'error': 'account credential required', 'code': 'bad_request'}), 400
    from app.license_manager import issue_jwt, resolve_api_account
    with db_session() as session:
        acct = resolve_api_account(session, license_key)   # auto-provisions master key
        if acct is None or not acct.active or acct.banned:
            return jsonify({'error': 'account_inactive', 'code': 'account_inactive'}), 403
        tid = int(acct.owner_telegram_id or 0)
    try:
        token, jti, exp = issue_jwt(license_key, tid)
    except RuntimeError:
        return jsonify({'error': 'server_misconfigured', 'code': 'server_error'}), 500
    return jsonify({'token': token, 'jti': jti, 'expires_at': exp,
                    'account': license_key}), 200


# ---------------------------------------------------------------------------
# Slot registry
# ---------------------------------------------------------------------------
@api_slots_bp.route('/slots', methods=['GET'])
def list_slots():
    with db_session() as session:
        acct, err, status = _account_from_request(session)
        if err is not None:
            return err, status
        rows = session.execute(
            select(ApiSlot).where(ApiSlot.account_id == acct.id)
            .order_by(ApiSlot.slot_index)
        ).scalars().all()
        return jsonify({
            'account': acct.license_key,
            'max_slots': acct.max_slots,
            'max_connections': acct.max_connections,
            'slots': [_slot_public(s) for s in rows],
        }), 200


@api_slots_bp.route('/slots', methods=['POST'])
def upsert_slot():
    """Create or update the slot at `slot_index`. The token + client-resolved
    username are mutable under a fixed slot_id. Enforces max_slots on create."""
    data = request.get_json(silent=True) or {}
    try:
        slot_index = int(data.get('slot_index'))
    except (TypeError, ValueError):
        return jsonify({'error': 'slot_index required', 'code': 'bad_request'}), 400
    if slot_index < 0:
        return jsonify({'error': 'bad slot_index', 'code': 'bad_request'}), 400

    with db_session() as session:
        acct, err, status = _account_from_request(session)
        if err is not None:
            return err, status
        if slot_index >= acct.max_slots:
            return jsonify({'error': 'slot_index over max_slots',
                            'code': 'max_slots', 'max_slots': acct.max_slots}), 403

        slot = session.execute(
            select(ApiSlot).where(ApiSlot.account_id == acct.id,
                                  ApiSlot.slot_index == slot_index)
        ).scalar_one_or_none()

        token = data.get('stake_access_token')
        if slot is None:
            # Create — but only if under max_slots total (defence in depth).
            count = session.execute(
                select(ApiSlot).where(ApiSlot.account_id == acct.id)
            ).scalars().all()
            if len(count) >= acct.max_slots:
                return jsonify({'error': 'max_slots reached',
                                'code': 'max_slots', 'max_slots': acct.max_slots}), 403
            slot = ApiSlot(account_id=acct.id, slot_index=slot_index)
            session.add(slot)

        # Apply mutable fields (only those provided).
        if token is not None:
            slot.stake_access_token = token or None
            slot.token_fp = _token_fp(token) if token else None
        if 'stake_username' in data:
            slot.stake_username = (data.get('stake_username') or None)
        if 'token_valid' in data:
            slot.token_valid = bool(data.get('token_valid'))
        for f in ('slot_telegram_id',):
            if f in data:
                try:
                    setattr(slot, f, int(data[f]) if data[f] is not None else None)
                except (TypeError, ValueError):
                    pass
        for f in ('withdrawal_currency', 'reload_currency', 'value_filter',
                  'plan', 'status'):
            if f in data:
                setattr(slot, f, data[f])
        for f in ('auto_vault', 'auto_bonus', 'auto_reload'):
            if f in data:
                setattr(slot, f, bool(data[f]))

        session.flush()   # assign slot.id
        result = _slot_public(slot)
        account_key = acct.license_key
    # Transaction committed → re-push the fresh slot list to every connected
    # script for this account so a RUNNING userscript hydrates the new/edited
    # slot and grows its Turnstile pool live (no reconnect needed).
    try:
        from app.routes.tmc_routes import push_slots_to_account
        push_slots_to_account(account_key)
    except Exception:
        logger.exception("slot push after upsert failed (ignored)")
    return jsonify({'ok': True, 'slot': result}), 200


@api_slots_bp.route('/slots/<int:slot_id>', methods=['DELETE'])
def delete_slot(slot_id: int):
    with db_session() as session:
        acct, err, status = _account_from_request(session)
        if err is not None:
            return err, status
        slot = session.execute(
            select(ApiSlot).where(ApiSlot.id == slot_id,
                                  ApiSlot.account_id == acct.id)
        ).scalar_one_or_none()
        if slot is None:
            return jsonify({'error': 'not_found', 'code': 'not_found'}), 404
        session.delete(slot)
        account_key = acct.license_key
    # Re-push the remaining slots so running scripts drop the deleted slot and
    # shrink their Turnstile pool target accordingly (no reconnect needed).
    try:
        from app.routes.tmc_routes import push_slots_to_account
        push_slots_to_account(account_key)
    except Exception:
        logger.exception("slot push after delete failed (ignored)")
    return jsonify({'ok': True}), 200


# ---------------------------------------------------------------------------
# Broadcast — the account holder drops a code to their OWN connected slots.
# Reuses the license-room fan-out keyed by the account's license_key.
# ---------------------------------------------------------------------------
@api_slots_bp.route('/broadcast', methods=['POST'])
def broadcast():
    data = request.get_json(silent=True) or {}
    code = (data.get('code') or '').strip()
    if not code:
        return jsonify({'error': 'code required', 'code': 'bad_request'}), 400
    coupon_type = 'bonus' if str(data.get('couponType') or '').strip().lower() == 'bonus' else 'drop'
    with db_session() as session:
        acct, err, status = _account_from_request(session)
        if err is not None:
            return err, status
        account_key = acct.license_key
    try:
        from app.routes.tmc_routes import emit_drop_to_license
        delivered = emit_drop_to_license(account_key, code, coupon_type)
    except Exception as exc:
        logger.warning(f"api broadcast emit failed: {exc}")
        delivered = 0
    return jsonify({'ok': True, 'delivered': int(delivered)}), 200


# ---------------------------------------------------------------------------
# Claim recording — CLAIMED-WINS upsert on (account_id, slot_id, code_norm).
# Called from the userClaim handler. A later claimed=true (RDP2) upgrades an
# earlier already_claimed (RDP1); a claimed row is never downgraded; dupes no-op.
# ---------------------------------------------------------------------------
def record_api_claim(account_id: int, slot_id: int, code_norm: str, *,
                     claimed: bool, error_code: str = None, currency: str = None,
                     amount=None, slot_username: str = None,
                     telegram_id: int = None, claim_type: str = None) -> None:
    if not account_id or not slot_id or not code_norm:
        return
    from sqlalchemy.dialects.postgresql import insert as pg_insert
    try:
        with db_session() as session:
            # Resolve the OWNER authoritatively from the slot row (never trust the
            # userscript payload). This becomes the immutable ownership snapshot on
            # the claim, so customer stats can be scoped to the buyer who actually
            # owned the slot at claim time — even after the slot_id is later reused.
            owner_tid = telegram_id
            if not owner_tid:
                owner_tid = session.execute(
                    select(ApiSlot.slot_telegram_id).where(ApiSlot.id == slot_id)
                ).scalar_one_or_none()
            stmt = pg_insert(ApiClaim.__table__).values(
                account_id=account_id, slot_id=slot_id, code_norm=code_norm,
                telegram_id=owner_tid, claim_type=(claim_type or 'drop'),
                claimed=bool(claimed), error_code=error_code, currency=currency,
                amount=amount, slot_username=slot_username,
            )
            # Upgrade to claimed only (never downgrade); refresh metadata on upgrade.
            # telegram_id is DELIBERATELY absent from set_ — the ownership snapshot
            # is immutable once written (one-time codes never collide across owners).
            stmt = stmt.on_conflict_do_update(
                index_elements=['account_id', 'slot_id', 'code_norm'],
                set_={
                    'claimed': True,
                    'error_code': None,
                    'currency': stmt.excluded.currency,
                    'amount': stmt.excluded.amount,
                    'slot_username': stmt.excluded.slot_username,
                },
                where=(ApiClaim.__table__.c.claimed.is_(False))
                & (stmt.excluded.claimed.is_(True)),
            )
            session.execute(stmt)
    except Exception:
        logger.exception("record_api_claim failed (ignored)")
