"""
Internal API — health + license lifecycle for the Telegram bot service.

All /api/xr9k/* routes require the x-internal-token header validated with
hmac.compare_digest against Config.INTERNAL_API_SECRET.
"""
import hmac
import logging
import time
import uuid
from datetime import datetime, timezone

from flask import Blueprint, abort, jsonify, request
from sqlalchemy import select, update

from app.config import Config

logger = logging.getLogger(__name__)

internal_bp = Blueprint('internal', __name__, url_prefix='/internal')


@internal_bp.route('/health')
def internal_health():
    """Internal health check endpoint for UptimeRobot monitoring."""
    return jsonify({
        'status': 'healthy',
        'service': 'code-server',
        'internal': True,
    }), 200


# ---------------------------------------------------------------------------
# Auth helper — bot ↔ backend shared secret
# ---------------------------------------------------------------------------

def _require_internal_token():
    expected = Config.INTERNAL_API_SECRET or ''
    provided = request.headers.get('x-internal-token', '') or ''
    if not expected or not hmac.compare_digest(expected, provided):
        abort(401)


# ---------------------------------------------------------------------------
# /api/xr9k/lic/* — license lifecycle
# Mounted at the app level (see app/__init__.py register_blueprint).
# ---------------------------------------------------------------------------

xr9k_bp = Blueprint('xr9k', __name__, url_prefix='/api/xr9k')


def _now_utc():
    return datetime.now(timezone.utc)


def _serialize_license(lic) -> dict:
    from app.license_manager import get_unique_username_count
    try:
        active_now = get_unique_username_count(lic.license_key)
    except Exception:
        active_now = 0
    return {
        'license_key': lic.license_key,
        'telegram_id': int(lic.telegram_id),
        'active': bool(lic.active),
        # Cumulative `theclaimers_count` column is retained for backward-compat
        # but is no longer updated. `active_now` is the live unique-username count.
        'theclaimers_count': int(lic.theclaimers_count or 0),
        'active_now': int(active_now),
        'maximum_usernames': int(lic.maximum_usernames or Config.MAX_CONNECTIONS_PER_LICENSE),
        'banned': bool(lic.banned),
        # Prepaid-balance billing. available_balance is the live USD balance;
        # deduction_percentage is the per-claim fee rate (NULL => the license is
        # an "After Claims Payment" license, surfaced as such by the bot).
        'available_balance': (float(lic.available_balance) if getattr(lic, 'available_balance', None) is not None else 0.0),
        'deduction_percentage': (float(lic.deduction_percentage) if getattr(lic, 'deduction_percentage', None) is not None else None),
        # Preferred bot UI language (ISO 639-1) or None => auto-detect.
        'language': getattr(lic, 'language', None),
        'created_at': lic.created_at.isoformat() if lic.created_at else None,
        'activated_at': lic.activated_at.isoformat() if lic.activated_at else None,
        'deactivated_at': lic.deactivated_at.isoformat() if lic.deactivated_at else None,
    }


@xr9k_bp.route('/lic/info', methods=['GET'])
def lic_info():
    _require_internal_token()
    try:
        telegram_id = int(request.args.get('telegram_id') or '0')
    except ValueError:
        return jsonify({'error': 'bad_telegram_id'}), 400
    if not telegram_id:
        return jsonify({'error': 'telegram_id required'}), 400

    from app.database import db_session
    from app.models import License
    with db_session() as session:
        # Active row preferred; fall back to most recent if no active row
        lic = session.execute(
            select(License)
            .where(License.telegram_id == telegram_id, License.active.is_(True))
            .limit(1)
        ).scalar_one_or_none()
        if not lic:
            lic = session.execute(
                select(License)
                .where(License.telegram_id == telegram_id)
                .order_by(License.created_at.desc())
                .limit(1)
            ).scalar_one_or_none()
        if not lic:
            return jsonify({'error': 'not_found'}), 404
        return jsonify(_serialize_license(lic)), 200


@xr9k_bp.route('/lic/reg', methods=['POST'])
def lic_register():
    """Idempotent registration. Returns existing license if telegram_id already has one."""
    _require_internal_token()
    data = request.get_json(silent=True) or {}
    try:
        telegram_id = int(data.get('telegram_id') or 0)
    except (TypeError, ValueError):
        return jsonify({'error': 'bad_telegram_id'}), 400
    if not telegram_id:
        return jsonify({'error': 'telegram_id required'}), 400

    proposed_key = (data.get('license_key') or '').strip()
    if not proposed_key:
        proposed_key = f"THECLAIMERS-{uuid.uuid4()}"
    elif not proposed_key.startswith('THECLAIMERS-'):
        return jsonify({'error': 'bad_license_key'}), 400

    from app.database import db_session
    from app.models import License
    with db_session() as session:
        # Existing active license for this telegram_id?
        existing = session.execute(
            select(License)
            .where(License.telegram_id == telegram_id, License.active.is_(True))
            .limit(1)
        ).scalar_one_or_none()
        if existing:
            return jsonify(_serialize_license(existing)), 200

        # Existing inactive — also return it (don't double-register on /start)
        existing = session.execute(
            select(License)
            .where(License.telegram_id == telegram_id)
            .order_by(License.created_at.desc())
            .limit(1)
        ).scalar_one_or_none()
        if existing:
            return jsonify(_serialize_license(existing)), 200

        new = License(
            license_key=proposed_key,
            telegram_id=telegram_id,
            active=False,
            theclaimers_count=0,
            # New licenses start capped at DEFAULT_MAX_USERNAMES (5); the admin
            # raises it manually. (Rotation preserves the existing cap.)
            maximum_usernames=Config.DEFAULT_MAX_USERNAMES,
            banned=False,
        )
        session.add(new)
        session.flush()
        return jsonify(_serialize_license(new)), 201


@xr9k_bp.route('/lic/set-lang', methods=['POST'])
def lic_set_lang():
    """Set a user's preferred bot language on ALL of their license rows.

    Language is a per-USER preference but stored per-license-row. `lic/info`
    returns the active row (else the most-recent), and a telegram_id can own
    several rows, so we update them ALL — whichever row a read returns then
    carries the same value. Idempotent; last write wins. An empty/None language
    clears the override (back to Telegram auto-detect).
    """
    _require_internal_token()
    data = request.get_json(silent=True) or {}
    try:
        telegram_id = int(data.get('telegram_id') or 0)
    except (TypeError, ValueError):
        return jsonify({'error': 'bad_telegram_id'}), 400
    if not telegram_id:
        return jsonify({'error': 'telegram_id required'}), 400

    raw = data.get('language')
    if raw is None or (isinstance(raw, str) and not raw.strip()):
        lang = None  # clear => auto-detect
    else:
        lang = str(raw).strip().lower()
        if not (lang.isalpha() and 2 <= len(lang) <= 8):
            return jsonify({'error': 'bad_language'}), 400

    from app.database import db_session
    from app.models import License
    with db_session() as session:
        result = session.execute(
            update(License)
            .where(License.telegram_id == telegram_id)
            .values(language=lang)
        )
        updated = int(result.rowcount or 0)
    return jsonify({
        'ok': True, 'telegram_id': telegram_id, 'language': lang, 'updated': updated,
    }), 200


@xr9k_bp.route('/lic/on', methods=['POST'])
def lic_activate():
    _require_internal_token()
    data = request.get_json(silent=True) or {}
    license_key = (data.get('license_key') or '').strip()
    if not license_key:
        return jsonify({'error': 'license_key required'}), 400

    from app.database import db_session
    from app.models import License
    from app.license_manager import upsert_license_cache, redact_key
    from app.utils.telegram import notify_bot_service, push_license_sync

    with db_session() as session:
        lic = session.execute(
            select(License).where(License.license_key == license_key)
        ).scalar_one_or_none()
        if not lic:
            return jsonify({'error': 'not_found'}), 404
        if lic.banned:
            return jsonify({'error': 'banned'}), 403
        if not lic.active:
            lic.active = True
            lic.activated_at = _now_utc()
        telegram_id = int(lic.telegram_id)
        max_usernames = int(lic.maximum_usernames or Config.MAX_CONNECTIONS_PER_LICENSE)
        count = int(lic.theclaimers_count or 0)
        manager_id = (lic.manager_id or '')

    upsert_license_cache(license_key, {
        'active': True,
        'telegram_id': telegram_id,
        'maximum_usernames': max_usernames,
        'theclaimers_count': count,
        'banned': False,
        'manager_id': manager_id,
    })

    push_license_sync(license_key, telegram_id, True, count, max_usernames)
    notify_bot_service(
        telegram_id,
        "🟢 <b>License Activated</b>\n"
        "━━━━━━━━━━━━━━━\n"
        f"🔑 <code>{redact_key(license_key)}</code>\n\n"
        "You're all set! Use /drop to broadcast codes, /connected to see your "
        "claimers, and /count to track results.\n\nWelcome aboard! 🚀"
    )

    return jsonify({'ok': True, 'license_key': license_key, 'active': True}), 200


@xr9k_bp.route('/lic/off', methods=['POST'])
def lic_deactivate():
    _require_internal_token()
    data = request.get_json(silent=True) or {}
    license_key = (data.get('license_key') or '').strip()
    if not license_key:
        return jsonify({'error': 'license_key required'}), 400

    from app.database import db_session
    from app.models import License
    from app.license_manager import remove_license_cache, revoke_license_sessions, redact_key
    from app.utils.telegram import notify_bot_service, push_license_sync

    with db_session() as session:
        lic = session.execute(
            select(License).where(License.license_key == license_key)
        ).scalar_one_or_none()
        if not lic:
            return jsonify({'error': 'not_found'}), 404
        lic.active = False
        lic.deactivated_at = _now_utc()
        telegram_id = int(lic.telegram_id)

    remove_license_cache(license_key)
    # Revoke session JTIs (S-02) and disconnect /_tmc clients in that room
    try:
        from app.routes import tmc_routes
        tmc_routes.disconnect_license_room(license_key)
    except Exception:
        revoke_license_sessions(license_key)

    push_license_sync(license_key, telegram_id, False)
    notify_bot_service(
        telegram_id,
        "🔴 <b>License Deactivated</b>\n"
        "━━━━━━━━━━━━━━━\n"
        f"🔑 <code>{redact_key(license_key)}</code>\n\n"
        "Your license has been switched off. Tap 🛟 Support (@adityaofficial96) "
        "if you think this is a mistake."
    )
    return jsonify({'ok': True, 'license_key': license_key, 'active': False}), 200


@xr9k_bp.route('/lic/drop', methods=['POST'])
def lic_drop():
    _require_internal_token()
    data = request.get_json(silent=True) or {}
    license_key = (data.get('license_key') or '').strip()
    code = (data.get('code') or '').strip()
    if not license_key or not code:
        return jsonify({'error': 'license_key and code required'}), 400

    from app.license_manager import is_license_active
    if not is_license_active(license_key):
        return jsonify({'ok': False, 'error': 'license_not_active'}), 404

    try:
        from app.routes import tmc_routes
        # F-report: open the response-report window BEFORE the fan-out so a fast
        # client's userClaim (folded in a separate greenlet mid-fanout) is not
        # lost. No-op unless an admin is configured. Isolated in its own
        # try/except so a report-hook failure can NEVER suppress the broadcast.
        try:
            tmc_routes._schedule_or_extend(code)
        except Exception:
            logger.exception("F-report schedule failed (ignored)")
        connected_clients = tmc_routes.emit_drop_to_license(license_key, code)
    except Exception as exc:
        logger.warning(f"lic_drop emit failed: {exc}")
        connected_clients = 0

    return jsonify({'ok': True, 'connected_clients': int(connected_clients)}), 200


@xr9k_bp.route('/lic/rl', methods=['POST'])
def lic_reload():
    _require_internal_token()
    data = request.get_json(silent=True) or {}
    license_key = (data.get('license_key') or '').strip()
    if not license_key:
        return jsonify({'error': 'license_key required'}), 400

    from app.license_manager import is_license_active
    if not is_license_active(license_key):
        return jsonify({'results': []}), 200

    try:
        from app.routes import tmc_routes
        results = tmc_routes.collect_reload_responses(license_key, wait_seconds=5.0)
    except Exception as exc:
        logger.warning(f"lic_reload failed: {exc}")
        results = []
    return jsonify({'results': results}), 200


@xr9k_bp.route('/lic/browsers', methods=['GET'])
def lic_browsers():
    _require_internal_token()
    license_key = (request.args.get('license_key') or '').strip()
    if not license_key:
        return jsonify({'error': 'license_key required'}), 400

    from app.license_manager import is_license_active
    if not is_license_active(license_key):
        return jsonify({'browsers': 0, 'accounts': []}), 200

    try:
        from app.routes import tmc_routes
        agg = tmc_routes.collect_send_browsers(license_key, wait_seconds=5.0)
    except Exception as exc:
        logger.warning(f"lic_browsers failed: {exc}")
        agg = {'browsers': 0, 'accounts': []}
    return jsonify(agg), 200


@xr9k_bp.route('/lic/list', methods=['GET'])
def lic_list():
    """Return ALL licenses (bot uses this to bootstrap its cache)."""
    _require_internal_token()
    from app.database import db_session
    from app.models import License
    with db_session() as session:
        rows = session.execute(select(License)).scalars().all()
        return jsonify({'licenses': [_serialize_license(l) for l in rows]}), 200


# ---------------------------------------------------------------------------
# Admin remote claimer management (the /api menu). All routes are internal-token
# gated AND scoped by the `telegram_id` the bot passes (the bot enforces the
# real _is_admin check). Reads come from the in-memory cache (no DB query). The
# raw API token is NEVER returned — only has_api + validity are exposed.
# ---------------------------------------------------------------------------
def _serialize_claimer(e: dict) -> dict:
    return {
        'claimer_id': e.get('claimer_id'),
        'claimer_name': e.get('claimer_name'),
        'stake_username': e.get('stake_username'),
        'online': bool(e.get('online')),
        'config_state': e.get('config_state') or 'synced',
        'has_api': bool(e.get('desired_token')) or bool(e.get('observed_api_fp')),
        'api_managed': bool(e.get('desired_token')),
        'api_valid': bool(e.get('observed_api_valid')),
        'currency': (e.get('desired_currency') or e.get('observed_currency')),
        'filters': (e.get('desired_filters') if e.get('desired_filters') is not None
                    else e.get('observed_filters')) or {},
        'version': e.get('version'),
        'last_seen': e.get('last_seen'),
        'last_push': e.get('last_push'),
        'last_api_validation': e.get('last_api_validation'),
    }


def _push_and_result(tid: int, cid: str, task: str, payload: dict) -> dict:
    """Set-then-push: emit the task, wait (bounded) for the claimer's ack, and
    return a bot-friendly result. Offline → applied False (will sync on reconnect)."""
    from app.routes import tmc_routes
    acks = tmc_routes.collect_claimer_result(cid, tid, task, payload, wait_seconds=6.0)
    if not acks:
        return {'ok': True, 'online': False, 'applied': False}
    ack = acks[-1]
    return {
        'ok': ack.get('ok', True) is not False,
        'online': True,
        'applied': (ack.get('ok', True) is not False) and (ack.get('valid', True) is not False),
        'valid': ack.get('valid'),
        'currency': ack.get('currency'),
        'filters': ack.get('filters'),
        'username': ack.get('username'),
    }


@xr9k_bp.route('/admin/claimers', methods=['GET'])
def admin_claimers():
    _require_internal_token()
    tid = int(request.args.get('telegram_id') or 0)
    if not tid:
        return jsonify({'error': 'telegram_id required'}), 400
    from app import claimer_manager
    return jsonify({'claimers': [_serialize_claimer(e) for e in claimer_manager.list_claimers(tid)]}), 200


@xr9k_bp.route('/admin/claimer/detail', methods=['GET'])
def admin_claimer_detail():
    _require_internal_token()
    tid = int(request.args.get('telegram_id') or 0)
    cid = (request.args.get('claimer_id') or '').strip()
    if not tid or not cid:
        return jsonify({'error': 'telegram_id and claimer_id required'}), 400
    from app import claimer_manager
    e = claimer_manager.get_claimer(tid, cid)
    if not e:
        return jsonify({'ok': False, 'error': 'not_found'}), 404
    e['claimer_id'] = cid
    return jsonify({'ok': True, 'claimer': _serialize_claimer(e)}), 200


@xr9k_bp.route('/admin/claimer/set_api', methods=['POST'])
def admin_set_api():
    _require_internal_token()
    data = request.get_json(silent=True) or {}
    tid = int(data.get('telegram_id') or 0)
    cid = (data.get('claimer_id') or '').strip()
    token = (data.get('token') or '').strip()
    if not tid or not cid or not token:
        return jsonify({'error': 'telegram_id, claimer_id, token required'}), 400
    from app import claimer_manager
    if claimer_manager.set_desired(tid, cid, token=token) is None:
        return jsonify({'ok': False, 'error': 'not_found'}), 404
    return jsonify(_push_and_result(tid, cid, 'setApi', {'token': token})), 200


@xr9k_bp.route('/admin/claimer/remove_api', methods=['POST'])
def admin_remove_api():
    _require_internal_token()
    data = request.get_json(silent=True) or {}
    tid = int(data.get('telegram_id') or 0)
    cid = (data.get('claimer_id') or '').strip()
    if not tid or not cid:
        return jsonify({'error': 'telegram_id, claimer_id required'}), 400
    from app import claimer_manager
    if claimer_manager.set_desired(tid, cid, token=None) is None:
        return jsonify({'ok': False, 'error': 'not_found'}), 404
    return jsonify(_push_and_result(tid, cid, 'removeApi', {})), 200


@xr9k_bp.route('/admin/claimer/set_currency', methods=['POST'])
def admin_set_currency():
    _require_internal_token()
    data = request.get_json(silent=True) or {}
    tid = int(data.get('telegram_id') or 0)
    cid = (data.get('claimer_id') or '').strip()
    currency = (data.get('currency') or '').strip().lower()
    if not tid or not cid or not currency:
        return jsonify({'error': 'telegram_id, claimer_id, currency required'}), 400
    from app import claimer_manager
    if claimer_manager.set_desired(tid, cid, currency=currency) is None:
        return jsonify({'ok': False, 'error': 'not_found'}), 404
    return jsonify(_push_and_result(tid, cid, 'setCurrency', {'currency': currency})), 200


@xr9k_bp.route('/admin/claimer/set_filters', methods=['POST'])
def admin_set_filters():
    _require_internal_token()
    data = request.get_json(silent=True) or {}
    tid = int(data.get('telegram_id') or 0)
    cid = (data.get('claimer_id') or '').strip()
    filters = data.get('filters')   # dict (true-only) or list of keys
    if not tid or not cid:
        return jsonify({'error': 'telegram_id, claimer_id required'}), 400
    from app import claimer_manager
    snap = claimer_manager.set_desired(tid, cid, filters=filters)
    if snap is None:
        return jsonify({'ok': False, 'error': 'not_found'}), 404
    return jsonify(_push_and_result(tid, cid, 'setFilters', {'filters': snap.get('desired_filters') or {}})), 200


@xr9k_bp.route('/admin/next_value', methods=['POST'])
def admin_next_value():
    """Set/clear the persistent 'value for next code' override. Global (not
    per-claimer); admin-gated by the bot, internal-token-gated here. Validation
    is authoritative here — never trust the caller."""
    _require_internal_token()
    data = request.get_json(silent=True) or {}
    from app import value_override
    if data.get('reset'):
        value_override.clear_override()
        return jsonify({'ok': True, 'override': None}), 200
    raw = data.get('value')
    if isinstance(raw, bool):
        return jsonify({'ok': False, 'error': 'invalid_value'}), 400
    try:
        num = float(raw)
    except (TypeError, ValueError):
        return jsonify({'ok': False, 'error': 'invalid_value'}), 400
    if not value_override.is_valid_override(num):
        return jsonify({'ok': False, 'error': 'invalid_value'}), 400
    stored = value_override.set_override(num)
    return jsonify({'ok': True, 'override': stored}), 200


# ---------------------------------------------------------------------------
# Admin-only live diagnostics (consumed by the bot's /licenselivecount
# and /claimcount commands). Both endpoints are read-only and do NOT mutate
# any state. The bot enforces the actual admin check via ADMIN_USER_ID; this
# layer only enforces the standard x-internal-token shared secret.
# ---------------------------------------------------------------------------

@xr9k_bp.route('/lic/livecount', methods=['GET'])
def lic_livecount():
    """
    Per-license live connection snapshot for the admin /licenselivecount
    command. Returns BOTH:
      • unique_usernames  — distinct stake usernames currently in /_tmc
        for this license (matches can_admit / max_usernames semantics)
      • total_sessions    — raw socket count (multiple tabs of the same
        username each contribute, so this can exceed unique_usernames)
      • usernames[]       — breakdown of each username → tab count

    Aggregate `totals` at the end gives the system-wide picture, computed
    inside the same lock-acquire so the per-license rows and the totals
    can never disagree.

    Output shape:
    {
      "licenses": [
        {
          "license_key": "THECLAIMERS-...",
          "telegram_id": 12345,
          "unique_usernames": 3,
          "total_sessions": 5,
          "max_usernames": 100,
          "usernames": [
            {"username": "alice",   "sessions": 2},
            {"username": "bob",     "sessions": 2},
            {"username": "charlie", "sessions": 1}
          ]
        }, ...
      ],
      "totals": {
        "licenses_with_active_users": 5,
        "total_unique_usernames":    12,
        "total_sessions":            18
      }
    }
    """
    _require_internal_token()

    from app.license_manager import active_sessions, _sessions_lock, get_license_cache_entry

    # Snapshot under a single lock acquisition. We deep-copy minimal fields
    # only (username from each session) so we release the lock fast and
    # don't hold it through the JSON serialisation.
    snapshot: list = []
    with _sessions_lock:
        for license_key, bucket in active_sessions.items():
            # Per-username session count for this license
            counts: dict = {}
            ips_by_user: dict = {}
            vers_by_user: dict = {}
            for sess in bucket.values():
                u = sess.get('username')
                if not u:
                    continue
                counts[u] = counts.get(u, 0) + 1
                _ip = sess.get('ip')
                if _ip:
                    ips_by_user.setdefault(u, set()).add(_ip)
                _ver = sess.get('version')
                if _ver:
                    vers_by_user.setdefault(u, set()).add(_ver)
            if not counts:
                # No usernames at all (anonymous sessions, very rare) —
                # skip this license entirely; it doesn't contribute to totals
                continue
            # telegram_id is the same for every session in a license; grab
            # any one. Fall back to None if absent.
            tid = None
            for sess in bucket.values():
                tid = sess.get('telegram_id')
                if tid:
                    break
            snapshot.append({
                'license_key': license_key,
                'telegram_id': int(tid) if tid else 0,
                'counts': counts,                  # username → tab count
                'ips_by_user': ips_by_user,        # username → set of IPs
                'vers_by_user': vers_by_user,      # username → set of versions
                'total_sessions_raw': len(bucket), # includes anonymous
            })

    # Enrich with license metadata (max_usernames) OUTSIDE the lock — the
    # license cache has its own lock, holding both at once would invite
    # lock-order bugs.
    licenses_out: list = []
    for row in snapshot:
        cache_entry = get_license_cache_entry(row['license_key']) or {}
        max_users = int(
            cache_entry.get('maximum_usernames')
            or Config.MAX_CONNECTIONS_PER_LICENSE
        )
        # Sort usernames by tab count desc, then alphabetically, for
        # consistent rendering. Cap at 50 to bound Telegram message size.
        sorted_users = sorted(
            row['counts'].items(),
            key=lambda kv: (-kv[1], kv[0]),
        )[:50]
        licenses_out.append({
            'license_key':      row['license_key'],
            'telegram_id':      row['telegram_id'],
            'manager_id':       (cache_entry.get('manager_id') or ''),
            'unique_usernames': len(row['counts']),
            'total_sessions':   sum(row['counts'].values()),
            'max_usernames':    max_users,
            'usernames': [
                {'username': u, 'sessions': c,
                 'ips': sorted(row.get('ips_by_user', {}).get(u, [])),
                 'versions': sorted(row.get('vers_by_user', {}).get(u, []))}
                for u, c in sorted_users
            ],
        })

    # Sort licenses by activity (most sessions first) for admin readability.
    licenses_out.sort(key=lambda l: (-l['total_sessions'], l['license_key']))

    totals = {
        'licenses_with_active_users': len(licenses_out),
        'total_unique_usernames':     sum(l['unique_usernames'] for l in licenses_out),
        'total_sessions':             sum(l['total_sessions']   for l in licenses_out),
    }

    return jsonify({'licenses': licenses_out, 'totals': totals}), 200


@xr9k_bp.route('/code/claimcount', methods=['GET'])
def code_claimcount():
    """
    Look up `code_claims.total_claims_count` for a single code, consumed
    by the admin /claimcount command. Codes are stored lowercase in
    `code_claims` (the conversion worker normalises before INSERT), so we
    lowercase here too. Empty/missing code → 400; unseen code → 0 (not 404)
    so the bot can render a clean "0 claims yet" line.

    Output shape:
    {
      "code":         "ABC123",   # echoed back in original case
      "code_normalised": "abc123",
      "total_claims_count": 42
    }
    """
    _require_internal_token()
    code_raw = (request.args.get('code') or '').strip()
    if not code_raw:
        return jsonify({'error': 'code required'}), 400
    if len(code_raw) > 64:
        return jsonify({'error': 'code too long'}), 400

    code_lower = code_raw.lower()

    from app.database import db_session
    from app.models import CodeClaim
    try:
        with db_session() as session:
            row = session.execute(
                select(CodeClaim).where(CodeClaim.code == code_lower)
            ).scalar_one_or_none()
            total = int(row.total_claims_count) if row else 0
    except Exception as exc:
        logger.warning(f"code_claimcount DB error code={code_lower}: {exc}")
        return jsonify({'error': 'db_error'}), 500

    return jsonify({
        'code':              code_raw,
        'code_normalised':   code_lower,
        'total_claims_count': total,
    }), 200


@xr9k_bp.route('/lic/rotate', methods=['POST'])
def lic_rotate():
    """
    Admin-initiated key rotation (v3.1 §A). Issues a new key for the same
    telegram_id, disconnects old room, syncs bot cache for both keys.
    """
    _require_internal_token()
    data = request.get_json(silent=True) or {}
    try:
        telegram_id = int(data.get('telegram_id') or 0)
    except (TypeError, ValueError):
        return jsonify({'error': 'bad_telegram_id'}), 400
    if not telegram_id:
        return jsonify({'error': 'telegram_id required'}), 400

    new_key = (data.get('new_key') or '').strip()
    if new_key and not new_key.startswith('THECLAIMERS-'):
        return jsonify({'error': 'bad_license_key'}), 400
    if not new_key:
        new_key = f"THECLAIMERS-{uuid.uuid4()}"

    from app.database import db_session
    from app.models import License
    from app.license_manager import remove_license_cache, upsert_license_cache, redact_key
    from app.utils.telegram import notify_bot_service, push_license_sync

    with db_session() as session:
        old = session.execute(
            select(License)
            .where(License.telegram_id == telegram_id, License.active.is_(True))
            .limit(1)
        ).scalar_one_or_none()
        if not old:
            return jsonify({'error': 'no_active_license_for_telegram_id'}), 404

        old_key = old.license_key
        max_usernames = int(old.maximum_usernames or Config.MAX_CONNECTIONS_PER_LICENSE)
        count = int(old.theclaimers_count or 0)
        manager_id = (old.manager_id or '')
        # Carry the prepaid balance + deduction rate to the new key — rotation is
        # the SAME user/billing, so their balance must not be lost or reset.
        carry_balance = float(getattr(old, 'available_balance', 0) or 0)
        carry_pct = getattr(old, 'deduction_percentage', None)

        # Insert new active row; the partial unique index allows this only
        # because we'll deactivate the old row in the same transaction.
        old.active = False
        old.deactivated_at = _now_utc()
        session.flush()

        new_row = License(
            license_key=new_key,
            telegram_id=telegram_id,
            active=True,
            activated_at=_now_utc(),
            theclaimers_count=count,
            maximum_usernames=max_usernames,
            banned=False,
            manager_id=manager_id,
            available_balance=carry_balance,
            deduction_percentage=carry_pct,
        )
        session.add(new_row)
        session.flush()

    # Emit key_changed to old room (clients use it to pre-fill popup with new
    # key) then close the room. Sessions JTIs are revoked.
    try:
        from app.routes import tmc_routes
        tmc_routes.emit_license_key_changed(old_key, new_key)
        tmc_routes.disconnect_license_room(old_key)
    except Exception as exc:
        logger.warning(f"rotate: emit_license_key_changed failed: {exc}")

    remove_license_cache(old_key)
    upsert_license_cache(new_key, {
        'active': True,
        'telegram_id': telegram_id,
        'maximum_usernames': max_usernames,
        'theclaimers_count': count,
        'banned': False,
        'manager_id': manager_id,
    })

    # Sync bot cache (deletion of old + upsert of new)
    push_license_sync(old_key, telegram_id, None)
    push_license_sync(new_key, telegram_id, True, count, max_usernames)

    # Notify user
    notify_bot_service(
        telegram_id,
        "🔑 <b>LICENSE KEY CHANGED</b>\n\n"
        "Your license key has been updated by the admin.\n\n"
        f"OLD KEY: <code>{redact_key(old_key)}</code>\n"
        f"NEW KEY: <code>{redact_key(new_key)}</code>\n\n"
        "Please update your key in the Tampermonkey popup.\n"
        "Contact @adityaofficial96 if you need help."
    )

    return jsonify({'ok': True, 'old_key': old_key, 'new_key': new_key}), 200


# ---------------------------------------------------------------------------
# /api/xr9k/topup/* — OxaPay balance top-up (bot → backend)
#
# The bot owns the Telegram UX; this is where the invoice is actually created
# and persisted (Service 1 owns the DB + the OxaPay secret). Amounts are
# validated AGAIN here so the bot's client-side check can never be bypassed.
# ---------------------------------------------------------------------------

def _topup_telegram_id(data):
    """Parse + validate telegram_id from a request body. Returns int or None."""
    try:
        tid = int(data.get('telegram_id') or 0)
    except (TypeError, ValueError):
        return None
    return tid if tid > 0 else None


@xr9k_bp.route('/topup/begin', methods=['POST'])
def topup_begin():
    """Validate + reuse-or-allocate an order. The bot turns a fresh order into an
    OxaPay invoice itself (keeping provider I/O off this backend)."""
    _require_internal_token()
    data = request.get_json(silent=True) or {}
    telegram_id = _topup_telegram_id(data)
    if telegram_id is None:
        return jsonify({'ok': False, 'error': 'missing_telegram_id'}), 400

    from app.services import payment_service
    result = payment_service.begin_topup(telegram_id, data.get('amount'))
    return jsonify(result), 200


@xr9k_bp.route('/topup/record', methods=['POST'])
def topup_record():
    """Persist the OxaPay track_id / pay_url the bot obtained for a fresh order."""
    _require_internal_token()
    data = request.get_json(silent=True) or {}
    telegram_id = _topup_telegram_id(data)
    if telegram_id is None:
        return jsonify({'ok': False, 'error': 'missing_telegram_id'}), 400

    from app.services import payment_service
    result = payment_service.record_topup(
        telegram_id,
        order_id=(data.get('order_id') or ''),
        track_id=(data.get('track_id') or ''),
        pay_url=(data.get('pay_url') or ''),
        pay_address=(data.get('pay_address') or ''),
        expires_at=data.get('expires_at'),
    )
    return jsonify(result), 200


@xr9k_bp.route('/topup/credit', methods=['POST'])
def topup_credit():
    """Re-verify against OxaPay and credit, idempotently. This is the trust
    anchor: main verifies independently of whatever the bot believes. Safe under
    retries / timeouts / concurrent calls. The HTTP status drives the bot's
    retry decision (2xx = handled-or-terminal; 5xx = transient, retry later)."""
    _require_internal_token()
    data = request.get_json(silent=True) or {}
    order_id = (data.get('order_id') or '').strip()
    if not order_id:
        return jsonify({'ok': False, 'error': 'missing_order_id'}), 400

    # `verified`: the bot confirmed PAID via its own OxaPay inquiry before
    # forwarding. Used ONLY as a fallback when main's own OxaPay call fails on a
    # transport error (see verify_and_credit). Still idempotent + token-gated.
    bot_verified = bool(data.get('verified'))
    from app.services import payment_service
    status_code, result = payment_service.verify_and_credit(order_id, bot_verified=bot_verified)
    return jsonify(result), status_code


@xr9k_bp.route('/topup/pending', methods=['GET', 'POST'])
def topup_pending():
    """Open invoices for the bot's reconciliation sweep (missed-webhook recovery)."""
    _require_internal_token()
    data = request.get_json(silent=True) or {}
    try:
        limit = int(data.get('limit') or request.args.get('limit') or 200)
    except (TypeError, ValueError):
        limit = 200
    try:
        lookback = int(data.get('lookback_hours') or request.args.get('lookback_hours') or 72)
    except (TypeError, ValueError):
        lookback = 72
    from app.services import payment_service
    return jsonify(payment_service.list_pending(limit=limit, lookback_hours=lookback)), 200


@xr9k_bp.route('/topup/status', methods=['POST'])
def topup_status():
    _require_internal_token()
    data = request.get_json(silent=True) or {}
    telegram_id = _topup_telegram_id(data)
    if telegram_id is None:
        return jsonify({'ok': False, 'error': 'missing_telegram_id'}), 400

    from app.services import payment_service
    result = payment_service.get_status(
        telegram_id,
        order_id=(data.get('order_id') or ''),
        track_id=(data.get('track_id') or ''),
    )
    return jsonify(result), 200


@xr9k_bp.route('/settings', methods=['POST'])
def runtime_settings_update():
    """Admin runtime settings (in-memory), set by the bot's /maskcode,
    /claimdelay & /everycodesame commands. Applies whichever keys are present,
    returns the full current state. Never touches money or claims. The
    every_code_same key affects ONLY the broadcast DEDUP key
    (websocket_manager.is_code_duplicate) — no other broadcast behavior, and the
    code is still delivered with its original casing."""
    _require_internal_token()
    data = request.get_json(silent=True) or {}
    from app.utils import runtime_settings

    if 'maskcode' in data:
        try:
            runtime_settings.set_mask_code(bool(data.get('maskcode')))
        except Exception:
            return jsonify({'ok': False, 'error': 'bad_maskcode'}), 400
    if 'first_claim_delay' in data:
        try:
            runtime_settings.set_first_claim_delay(data.get('first_claim_delay'))
        except (TypeError, ValueError):
            return jsonify({'ok': False, 'error': 'bad_first_claim_delay'}), 400
    if 'every_code_same' in data:
        try:
            runtime_settings.set_every_code_same(bool(data.get('every_code_same')))
        except Exception:
            return jsonify({'ok': False, 'error': 'bad_every_code_same'}), 400

    return jsonify({'ok': True, 'settings': runtime_settings.snapshot()}), 200


# ---------------------------------------------------------------------------
# /api/xr9k/claims/* — 24-hour rolling claim history queries
#
# Three read-only endpoints feeding the bot's /count command:
#   GET /api/xr9k/claims/user?telegram_id=N&hours=H     (user-self)
#   GET /api/xr9k/claims/license?key=K&hours=H          (admin)
#   GET /api/xr9k/claims/username?name=U&hours=H        (admin)
#
# All gated by _require_internal_token() (bot ↔ backend shared secret).
# The admin-vs-user distinction lives in the BOT — these endpoints just
# answer "given this filter, what's in the window".
#
# hours: int 1..24 (default 24). Values outside the range are clamped.
# Returns: { records: [...], total_records: N, total_usd: float, hours: H }
# ---------------------------------------------------------------------------

def _parse_hours_param() -> float:
    """Parse and clamp the ?hours= query parameter to [1, 24]."""
    raw = request.args.get('hours', '24')
    try:
        h = float(raw)
    except (TypeError, ValueError):
        h = 24.0
    # Clamp to the supported window (matches the bot-side validation).
    if h < 1:
        h = 1.0
    if h > 24:
        h = 24.0
    return h


def _parse_window_param():
    """
    Resolve the query time window as (start_utc, end_utc) datetimes.

    Preferred (new) params — explicit epoch-millisecond bounds the bot computes
    from the IST window choice (Stream Special / 1d / 7d / Custom):
        ?start_ms=<int>&end_ms=<int>
    Falls back to the legacy ?hours= (clamped 1-24h) when start/end absent, so
    older callers keep working. Returns (start_utc, end_utc) or None on bad
    input (caller then 400s).
    """
    from datetime import datetime, timezone, timedelta
    start_ms = request.args.get('start_ms')
    end_ms = request.args.get('end_ms')
    if start_ms is not None and end_ms is not None:
        try:
            s = datetime.fromtimestamp(int(start_ms) / 1000.0, tz=timezone.utc)
            e = datetime.fromtimestamp(int(end_ms) / 1000.0, tz=timezone.utc)
        except (TypeError, ValueError, OverflowError, OSError):
            return None
        if e < s:
            return None
        # Hard safety cap: never allow a window wider than retention + 1 day,
        # regardless of what the caller asks (defence in depth vs. huge scans).
        try:
            from app.claim_history import CLAIM_RETENTION_DAYS
            max_span = timedelta(days=CLAIM_RETENTION_DAYS + 1)
        except Exception:
            max_span = timedelta(days=31)
        if (e - s) > max_span:
            s = e - max_span
        return s, e
    # Legacy hours fallback
    hours = _parse_hours_param()
    from app.claim_history import rolling_window_utc
    return rolling_window_utc(hours / 24.0)


def _serialize_records(records: list) -> dict:
    """
    Common JSON shape for all three endpoints. Records are returned
    sorted newest-first. Each record has a stable schema regardless
    of which query produced it.

    Also includes a per-username rollup (`by_username`) — usernames and the
    TOTAL amount each one claimed in the window, with NO codes. This is what
    the /count report renders: who claimed how much, not which codes.
    """
    # newest first
    sorted_records = sorted(records, key=lambda r: r['ts'], reverse=True)
    total_usd = sum(float(r.get('amount_usd') or 0) for r in records)

    # Per-username rollup: sum amounts, count claims. Codes are dropped.
    by_user: dict = {}
    for r in records:
        uname = (r.get('username') or '?')
        row = by_user.get(uname)
        if row is None:
            row = {'username': uname, 'total_usd': 0.0, 'count': 0}
            by_user[uname] = row
        row['total_usd'] += float(r.get('amount_usd') or 0)
        row['count'] += 1
    # Highest earner first; round each total to a sane precision.
    by_username = sorted(
        ({'username': v['username'],
          'total_usd': round(v['total_usd'], 4),
          'count': v['count']} for v in by_user.values()),
        key=lambda x: x['total_usd'],
        reverse=True,
    )

    return {
        'records': sorted_records,
        'total_records': len(records),
        'total_usd': round(total_usd, 4),
        'by_username': by_username,
        'unique_users': len(by_username),
    }


@xr9k_bp.route('/claims/user', methods=['GET'])
def claims_by_user():
    """Records for a specific Telegram user (themselves) in the last H hours."""
    _require_internal_token()
    try:
        telegram_id = int(request.args.get('telegram_id') or 0)
    except (TypeError, ValueError):
        return jsonify({'ok': False, 'error': 'bad_telegram_id'}), 400
    if telegram_id <= 0:
        return jsonify({'ok': False, 'error': 'missing_telegram_id'}), 400

    window = _parse_window_param()
    if window is None:
        return jsonify({'ok': False, 'error': 'bad_window'}), 400
    start_utc, end_utc = window
    try:
        from app.claim_history import query_by_telegram_window
        records = query_by_telegram_window(telegram_id, start_utc, end_utc)
    except Exception as exc:
        logger.warning(f"claims_by_user error tg_id={telegram_id}: {exc}", exc_info=True)
        return jsonify({'ok': False, 'error': 'internal_error'}), 500

    payload = _serialize_records(records)
    payload['ok'] = True
    payload['start_ms'] = int(start_utc.timestamp() * 1000)
    payload['end_ms'] = int(end_utc.timestamp() * 1000)
    payload['telegram_id'] = telegram_id
    return jsonify(payload), 200


@xr9k_bp.route('/claims/license', methods=['GET'])
def claims_by_license():
    """Records for a specific license_key in the last H hours (admin)."""
    _require_internal_token()
    license_key = (request.args.get('key') or '').strip()
    if not license_key:
        return jsonify({'ok': False, 'error': 'missing_key'}), 400

    window = _parse_window_param()
    if window is None:
        return jsonify({'ok': False, 'error': 'bad_window'}), 400
    start_utc, end_utc = window
    try:
        from app.claim_history import query_by_license_window
        records = query_by_license_window(license_key, start_utc, end_utc)
    except Exception as exc:
        logger.warning(
            f"claims_by_license error key={license_key[:12]}...: {exc}",
            exc_info=True,
        )
        return jsonify({'ok': False, 'error': 'internal_error'}), 500

    payload = _serialize_records(records)
    payload['ok'] = True
    payload['start_ms'] = int(start_utc.timestamp() * 1000)
    payload['end_ms'] = int(end_utc.timestamp() * 1000)
    payload['license_key'] = license_key
    return jsonify(payload), 200


@xr9k_bp.route('/claims/username', methods=['GET'])
def claims_by_username_route():
    """Records for a specific Stake username in the last H hours (admin)."""
    _require_internal_token()
    username = (request.args.get('name') or '').strip()
    if not username:
        return jsonify({'ok': False, 'error': 'missing_name'}), 400
    if len(username) > 64:
        return jsonify({'ok': False, 'error': 'name_too_long'}), 400

    window = _parse_window_param()
    if window is None:
        return jsonify({'ok': False, 'error': 'bad_window'}), 400
    start_utc, end_utc = window
    try:
        from app.claim_history import query_by_username_window
        records = query_by_username_window(username, start_utc, end_utc)
    except Exception as exc:
        logger.warning(
            f"claims_by_username error name={username[:32]}: {exc}",
            exc_info=True,
        )
        return jsonify({'ok': False, 'error': 'internal_error'}), 500

    payload = _serialize_records(records)
    payload['ok'] = True
    payload['start_ms'] = int(start_utc.timestamp() * 1000)
    payload['end_ms'] = int(end_utc.timestamp() * 1000)
    payload['username'] = username
    return jsonify(payload), 200
