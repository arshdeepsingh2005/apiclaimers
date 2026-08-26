"""
Fire-and-forget Telegram notifier via detached curl subprocess.

Why a detached child process, not a greenlet or thread:
  - Greenlet (eventlet.spawn_n + requests.post): exceptions go to stderr, not
    the logger; under heavy SSE hub load the greenlet can be starved; and
    requests+urllib3+eventlet has edge cases on SSL handshake that silently
    hang.
  - OS thread (eventlet.patcher.original): that path was what broke before —
    patcher.original() returns a module whose _thread.start_new_thread is
    still green, so the "real thread" was actually a starved greenlet.
  - subprocess.Popen with start_new_session=True forks a real OS process that
    is fully detached from the eventlet hub. curl does the HTTPS send on its
    own. The parent greenlet returns in ~1–5 ms (the cost of fork+exec). No
    shared state, no hub dependency, no SSL compatibility surface.
"""
import html as _html
import json
import logging
import os
import re
import subprocess
from urllib.parse import quote

logger = logging.getLogger(__name__)


def safe_html(value) -> str:
    """HTML-escape user-controlled values before insertion into parse_mode='HTML' messages."""
    if value is None:
        return ""
    return _html.escape(str(value), quote=False)


def _mask_username(username: str) -> str:
    if not username:
        return "***"
    if len(username) == 1:
        return "*"
    if len(username) == 2:
        return f"{username[0]}*{username[1]}"
    return f"{username[0]}{'*' * (len(username) - 2)}{username[-1]}"

def _mask_code(code: str) -> str:         
  if not code:
    return "***"
  if len(code) <= 2:
    return "*" * len(code)
  return f"{code[0]}{'*' * (len(code) - 2)}{code[-1]}"

def _send_telegram(payload: dict) -> None:
    """Fire curl in a detached child process. Returns immediately."""
    token = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
    chat_id = os.environ.get("TELEGRAM_CHAT_ID", "").strip()
    if not token or not chat_id:
        logger.warning("Telegram: credentials not set — message dropped")
        return

    body = dict(payload)
    body["chat_id"] = chat_id
    url = f"https://api.telegram.org/bot{token}/sendMessage"

    try:
        subprocess.Popen(
            [
                "curl", "--silent", "--show-error",
                "--max-time", "15", "--connect-timeout", "10",
                "-X", "POST",
                "-H", "Content-Type: application/json",
                "-d", json.dumps(body),
                "-o", "/dev/null",
                url,
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL,
            start_new_session=True,
            close_fds=True,
        )
        logger.info("Telegram: dispatched via detached curl")
    except FileNotFoundError:
        logger.error("Telegram: curl not found on the system PATH")
    except Exception as e:
        logger.error(f"Telegram: failed to spawn curl — {e}")


def _queue_message(text: str, parse_mode: str = "HTML", reply_markup: dict = None) -> None:
    payload = {"text": text, "parse_mode": parse_mode}
    if reply_markup:
        payload["reply_markup"] = reply_markup
    _send_telegram(payload)


def _send_admin(payload: dict) -> bool:
    """Detached-curl send to the OPERATOR's admin bot (ADMIN_BOT_TOKEN) →
    ADMIN_TELEGRAM_ID. Same fork+exec discipline as `_send_telegram`: returns in
    ~1–5 ms, never waits on the network, never holds a lock. Returns True if a
    send was dispatched, False if creds are missing or the spawn failed."""
    token = os.environ.get("ADMIN_BOT_TOKEN", "").strip()
    chat_id = os.environ.get("ADMIN_TELEGRAM_ID", "").strip()
    if not token or not chat_id:
        return False
    body = dict(payload)
    body["chat_id"] = chat_id
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    try:
        subprocess.Popen(
            [
                "curl", "--silent", "--show-error",
                "--max-time", "15", "--connect-timeout", "10",
                "-X", "POST",
                "-H", "Content-Type: application/json",
                "-d", json.dumps(body),
                "-o", "/dev/null",
                url,
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL,
            start_new_session=True,
            close_fds=True,
        )
        return True
    except Exception as e:
        logger.error(f"notify_admin_direct: curl spawn failed — {e}")
        return False


def notify_admin_direct(message_html: str) -> bool:
    """DM the admin directly via ADMIN_BOT_TOKEN → ADMIN_TELEGRAM_ID (detached
    curl; non-blocking, best-effort, never raises). No-op (False) if either env
    var is unset."""
    if not message_html:
        return False
    if len(message_html) > 4096:
        message_html = message_html[:4090] + "\n…"
    return _send_admin({"text": message_html, "parse_mode": "HTML"})


def notify_startup() -> None:
    _queue_message("Restarted....")


def notify_first_claim(
    username: str,
    code: str,
    amount: float,
    currency: str,
    first_claimed_at: str,
) -> None:
    """
    Dispatch the FIRST-CLAIMED Telegram alert.

    Called exclusively by the conversion worker after the atomic upsert
    on `code_claims` returned `inserted=True` — so invocation is the
    dedup guarantee. No in-process deque is needed and no second fire
    can happen for the same lowercased code.

    `first_claimed_at` is the worker's UTC wall-clock string at the
    moment of the first DB insert.
    """
    logger.info(
        f"Telegram: notify_first_claim | user={username} | "
        f"code={code[:8]}... | amount={amount}"
    )

    if amount <= 0:
        logger.warning(f"Telegram: skipping — amount={amount} <= 0")
        return

    # Masking is an admin runtime toggle (/maskcode); the stake-code exemption
    # is case-insensitive since `code` is now the EXACT (original-case) code.
    from app.utils import runtime_settings
    display_code = (
        _mask_code(code)
        if runtime_settings.get_mask_code() and not code.lower().startswith('stake')
        else code
    )
    # Claim Now must carry the REAL exact code (URL-encoded), never the masked one.
    claim_url = f"https://playstake.club/drop?code={quote(str(code), safe='')}"

    _queue_message(
        f"⚡ <b>FIRST CLAIMED</b> ⚡\n\n"
        f"🎟️ Code: <code>{safe_html(display_code)}</code>\n"
        f"👤 User: <code>{_mask_username(username)}</code>\n"
        f"💵 Amount: <b>{amount} {currency}</b>\n"
        f"🕒 First claimed: <b>{first_claimed_at}</b>\n\n"
        f"🔥 Grab it before it's gone!",
        reply_markup={"inline_keyboard": [
            [{"text": "⚡ Claim Now", "url": claim_url}],
            [
                {"text": "💎 Get Claimer", "url": "https://t.me/Adityadropsbot"},
                {"text": "🆘 Support", "url": "https://t.me/adityaofficial96"},
            ],
        ]}
    )


# ---------------------------------------------------------------------------
# Bot service (Service 2) — per-license push and license cache sync.
# Both calls require Config.INTERNAL_API_SECRET and BOT_SERVICE_URL.
# Returns False silently if either is unset or the call fails: notifications
# are best-effort; the websocket session must continue regardless.
# ---------------------------------------------------------------------------

def _bot_service_call(path: str, body: dict, timeout: float = 5.0) -> bool:
    from app.config import Config
    if not Config.BOT_SERVICE_URL or not Config.INTERNAL_API_SECRET:
        return False
    url = f"{Config.BOT_SERVICE_URL.rstrip('/')}{path}"
    try:
        # Use detached curl for the same reasons _send_telegram does — keeps
        # the eventlet hub clean and never blocks the worker on bot latency.
        subprocess.Popen(
            [
                "curl", "--silent", "--show-error",
                "--max-time", str(int(timeout)),
                "--connect-timeout", "5",
                "-X", "POST",
                "-H", "Content-Type: application/json",
                "-H", f"x-internal-token: {Config.INTERNAL_API_SECRET}",
                "-d", json.dumps(body),
                "-o", "/dev/null",
                url,
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL,
            start_new_session=True,
            close_fds=True,
        )
        return True
    except Exception as exc:
        logger.warning(f"bot_service_call {path}: {exc}")
        return False


def notify_bot_service(telegram_id: int, message_html: str) -> bool:
    """Push a Telegram message to a specific user via the bot service."""
    if not telegram_id or not message_html:
        return False
    if len(message_html) > 4096:
        message_html = message_html[:4090] + "\n…"
    return _bot_service_call(
        "/nx/v3/push",
        {"telegram_id": int(telegram_id), "message": message_html},
    )


_UNSET = object()


def push_license_sync(
    license_key: str,
    telegram_id: int,
    active,  # None => deleted, False => deactivated, True => active/upserted
    theclaimers_count: int = 0,
    maximum_usernames: int = 100,
    available_balance=_UNSET,
    deduction_percentage=_UNSET,
) -> bool:
    """Update the bot's license cache. `active=None` signals deletion.

    available_balance / deduction_percentage use an _UNSET sentinel so callers
    that don't have a balance to report (lic on/off/rotate) OMIT the keys, and
    the bot preserves whatever it already cached. deduction_percentage=None is a
    MEANINGFUL value ("After Claims Payment"), distinct from _UNSET, and is sent
    as JSON null when explicitly provided.
    """
    if not license_key:
        return False
    body = {
        "license_key": license_key,
        "telegram_id": int(telegram_id or 0),
        "active": active,
        "theclaimers_count": int(theclaimers_count or 0),
        "maximum_usernames": int(maximum_usernames or 0),
    }
    if available_balance is not _UNSET:
        body["available_balance"] = (
            float(available_balance) if available_balance is not None else None
        )
    if deduction_percentage is not _UNSET:
        body["deduction_percentage"] = (
            float(deduction_percentage) if deduction_percentage is not None else None
        )
    return _bot_service_call("/nx/v3/lic-sync", body)


def notify_broadcast(code: str, broadcast_epoch: float = None, source: str = None,
                     coupon_type: str = None, value=None) -> None:
    """Admin alert: a code was broadcast to ALL users.

    Includes the exact broadcast instant in IST (Asia/Kolkata, UTC+5:30) with
    millisecond precision, the ingest `source` (e.g. 'textarea-monitor') for
    provenance, and — when present — the broadcast `value` (exactly as delivered
    to clients, including any /valuefornextcode injection). Sent ONLY to the
    admin via the bot service (notify_bot_service -> /nx/v3/push) — a direct DM,
    never the group. Requires the ADMIN_TELEGRAM_ID env var. Best-effort: any
    failure is swallowed.
    """
    try:
        from datetime import datetime, timezone, timedelta
        _ist = timezone(timedelta(hours=5, minutes=30))
        if broadcast_epoch is not None:
            dt = datetime.fromtimestamp(broadcast_epoch, _ist)
        else:
            dt = datetime.now(_ist)
        stamp = dt.strftime("%Y-%m-%d %H:%M:%S.") + f"{dt.microsecond // 1000:03d}"
        src_line    = f"📍 Source: <b>{safe_html(source)}</b>\n" if source else ""
        coupon_line = f"🎁 Type: <b>{'Bonus' if coupon_type == 'bonus' else 'Drop'}</b>\n" if coupon_type else ""
        value_line  = (f"💰 Value: <b>{safe_html(str(value))}</b>\n"
                       if value is not None and value != "" else "")
        message = (
            "📡 <b>CODE BROADCAST</b>\n\n"
            f"🎟️ Code: <code>{safe_html(code)}</code>\n"
            f"{value_line}"
            f"{coupon_line}"
            f"{src_line}"
            f"🕒 Broadcast at: <b>{stamp} IST</b>"
        )
        admin_id = os.environ.get("ADMIN_TELEGRAM_ID", "").strip()
        if not admin_id:
            logger.warning("notify_broadcast: ADMIN_TELEGRAM_ID not set; admin alert skipped")
            return
        # Prefer the operator's OWN bot (ADMIN_BOT_TOKEN, direct DM) when set;
        # otherwise fall back to the bot-service push. Exactly one delivery.
        if not notify_admin_direct(message):
            notify_bot_service(int(admin_id), message)
    except Exception as e:
        logger.warning(f"notify_broadcast: {e}")
