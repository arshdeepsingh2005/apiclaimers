"""
OxaPay v1 Merchant API client (balance top-up).

Auth model (v1): the Merchant API Key is sent in the `merchant_api_key` request
header. Base URL, paths, key, timeouts and invoice options all come from
Config (env) — nothing about the provider is hardcoded here.

Three responsibilities, and ONLY these — no DB, no balance logic:
  * create_invoice()  — POST {base}{invoice_path}
  * get_payment()     — GET  {base}{inquiry_path}/{track_id}   (source of truth)
  * verify_hmac()     — HMAC-SHA512(raw_body, merchant_key) == header  (anti-forgery)

Network safety: this runs inside Service 1, where eventlet.monkey_patch() has
patched sockets, so `requests` yields to the hub and never blocks the worker.
Every call has a hard timeout. Responses are parsed DEFENSIVELY (the v1 success
body wraps the result in `data`, but we tolerate flat bodies and alternate key
spellings) so a minor provider-shape change degrades to a clean error instead
of a crash.
"""
from __future__ import annotations

import hashlib
import hmac
import logging
import re
from typing import Optional

import requests

from app.config import Config

logger = logging.getLogger(__name__)

# OxaPay track ids are short numeric/alphanumeric tokens. We hard-validate any
# value before it is interpolated into the inquiry URL path — defence in depth
# against path traversal / SSRF even though it only ever comes from our own DB
# or an HMAC-verified webhook.
_TRACK_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


# ---------------------------------------------------------------------------
# Payment-path diagnostics (Phase 2 — INSTRUMENTATION ONLY, no behavior change).
#
# The reconciliation/verify hang was traced to get_payment(): the backend logs
# went silent right after VERIFICATION_STARTED with NO "curl timeout"/"curl rc"
# line — which points at the greenlet blocking INSIDE tpool.execute() waiting for
# a free native thread (tpool.execute has NO acquisition ceiling). WHY the pool
# exhausts is NOT yet proven, so this records — without altering timing or
# concurrency — exactly which resource drains:
#   * tpool_wait : seconds BEFORE the curl subprocess actually started
#                  (= time to acquire a tpool native thread). Large ⇒ tpool
#                  saturation (the leading hypothesis).
#   * curl       : seconds the curl subprocess itself ran.
#   * inflight   : concurrent get_payment calls sitting in tpool right now.
#   * threads/open_fds/zombies : process resource counts, to catch a leak.
# A 60s heartbeat logs the resource counts even while a call is stuck (the
# per-call line can't fire mid-hang), so the drain is visible in real time.
# Everything here is read-only and logs no secrets. Disable with OXAPAY_DIAG=0.
# ---------------------------------------------------------------------------
import os as _os
import threading as _threading
import time as _time

_DIAG_ON = _os.environ.get("OXAPAY_DIAG", "1") != "0"
_inflight = 0
_inflight_lock = _threading.Lock()      # tiny counter lock; couples with nothing else
_diag_started = False
_diag_start_lock = _threading.Lock()

# Admin alerting (via the bot relay → Bot 2 automatically). Debounced so a
# sustained stall sends ONE message per cooldown, never a flood.
_ALERT_COOLDOWN = float(_os.environ.get("OXAPAY_DIAG_ALERT_COOLDOWN", "900"))  # 15 min
_SATURATION_HEARTBEATS = int(_os.environ.get("OXAPAY_DIAG_SAT_MINUTES", "2"))  # sustained minutes
_last_alert_ts = 0.0
_alert_ts_lock = _threading.Lock()


def _admin_ids() -> list:
    out = []
    for p in (_os.environ.get("ADMIN_TELEGRAM_ID") or "").replace(",", " ").split():
        try:
            out.append(int(p))
        except (TypeError, ValueError):
            pass
    return out


def _alert_admin(text: str) -> None:
    """Debounced admin alert. Sends via notify_bot_service, which the bot routes
    to Bot 2's token for admin ids (token_for) — so this reaches the admin bot
    automatically. notify_bot_service is a detached curl → non-blocking; never
    raises. One alert per _ALERT_COOLDOWN regardless of how long the stall lasts."""
    if not _DIAG_ON:
        return
    ids = _admin_ids()
    if not ids:
        return
    global _last_alert_ts
    now = _time.monotonic()
    with _alert_ts_lock:
        if now - _last_alert_ts < _ALERT_COOLDOWN:
            return
        _last_alert_ts = now
    try:
        from app.utils.telegram import notify_bot_service
        for tid in ids:
            try:
                notify_bot_service(tid, text)
            except Exception:
                pass
    except Exception:
        pass


def _proc_fds() -> int:
    try:
        return len(_os.listdir(f"/proc/{_os.getpid()}/fd"))
    except Exception:
        return -1


def _zombie_children() -> int:
    """Count OUR zombie (unreaped) child processes — read-only, never reaps."""
    pid = _os.getpid()
    want = str(pid).encode()
    try:
        n = 0
        for d in _os.listdir("/proc"):
            if not d.isdigit():
                continue
            try:
                with open(f"/proc/{d}/stat", "rb") as f:
                    parts = f.read().split()
                # /proc/<pid>/stat: [0]=pid (comm) [2]=state [3]=ppid
                if len(parts) > 3 and parts[3] == want and parts[2] == b"Z":
                    n += 1
            except Exception:
                continue
        return n
    except Exception:
        return -1


def _tpool_size() -> int:
    try:
        return int(_os.environ.get("EVENTLET_THREADPOOL_SIZE", "20"))
    except Exception:
        return 20


def _diag_log(track_id: str, t0: float, t: dict, outcome: str, rc=None) -> None:
    """One structured line per get_payment call, separating tpool-wait from curl."""
    if not _DIAG_ON:
        return
    try:
        now = _time.monotonic()
        rs, re_ = t.get("run_start"), t.get("run_end")
        tpool_wait = (rs - t0) if rs else (now - t0)     # time acquiring a native thread
        curl = (re_ - rs) if (rs and re_) else -1.0      # time in the curl subprocess
        total = now - t0
        with _inflight_lock:
            inflight = _inflight
        line = ("OXAPAY_DIAG call | track=%s outcome=%s tpool_wait=%.3f curl=%.3f "
                "total=%.3f rc=%s inflight=%d threads=%d open_fds=%d")
        args = (track_id, outcome, tpool_wait, curl, total, rc, inflight,
                _threading.active_count(), _proc_fds())
        # WARN when the smoking-gun signals appear (thread-acquire stall / very slow).
        if tpool_wait > 1.0 or total > 5.0:
            logger.warning(line, *args)
            # A call that COMPLETED but had to wait a long time for a tpool thread
            # is direct proof of saturation — alert (debounced) via Bot 2.
            if tpool_wait > 5.0:
                _alert_admin(
                    "⚠️ <b>OxaPay verify stalled</b>\n\n"
                    f"track <code>{track_id}</code> waited <b>{tpool_wait:.1f}s</b> for a "
                    f"tpool thread (inflight={inflight}).\n"
                    "Reconciliation retries; restart the backend if it persists."
                )
        else:
            logger.info(line, *args)
    except Exception:
        pass


def _diag_heartbeat() -> None:
    # One-time environment snapshot: whether os is monkey-patched decides if the
    # subprocess timeout can even fire inside a tpool NATIVE thread.
    try:
        import eventlet.patcher as _ep
        logger.info(
            "OXAPAY_DIAG env | os_patched=%s socket_patched=%s thread_patched=%s tpool_size=%d",
            _ep.is_monkey_patched("os"), _ep.is_monkey_patched("socket"),
            _ep.is_monkey_patched("thread"), _tpool_size(),
        )
    except Exception:
        pass
    last = None
    sat_count = 0
    tpsize = _tpool_size()
    while True:
        _time.sleep(60)
        try:
            with _inflight_lock:
                inflight = _inflight
            threads, fds, zomb = _threading.active_count(), _proc_fds(), _zombie_children()
            snap = (threads, fds, zomb, inflight)
            if snap != last:
                logger.info(
                    "OXAPAY_DIAG heartbeat | threads=%d open_fds=%d zombies=%d inflight=%d tpool_size=%d",
                    threads, fds, zomb, inflight, tpsize,
                )
                last = snap
            # Saturation = (near) all tpool threads occupied by in-flight verifies.
            # Sustained for _SATURATION_HEARTBEATS minutes == the reconciliation
            # hang in progress → alert the admin (debounced) via Bot 2.
            if inflight >= max(1, tpsize - 1):
                sat_count += 1
            else:
                sat_count = 0
            if sat_count >= _SATURATION_HEARTBEATS:
                _alert_admin(
                    "⚠️ <b>OxaPay verification stalling</b>\n\n"
                    f"tpool saturated: <b>inflight={inflight}/{tpsize}</b> for "
                    f"~{sat_count} min.\n"
                    f"threads={threads} · open_fds={fds} · zombies={zomb}\n\n"
                    "Payments are <b>not</b> lost — reconciliation retries and crediting "
                    "is idempotent. If it persists, restart the backend. "
                    "Diagnostics: search logs for <code>OXAPAY_DIAG</code>."
                )
                sat_count = 0   # cooldown governs any repeat
        except Exception:
            pass


def _diag_start() -> None:
    """Idempotently start the 60s resource heartbeat (one daemon thread)."""
    global _diag_started
    if not _DIAG_ON:
        return
    with _diag_start_lock:
        if _diag_started:
            return
        _diag_started = True
    try:
        _threading.Thread(target=_diag_heartbeat, daemon=True, name="oxapay-diag").start()
    except Exception:
        pass


def is_valid_track_id(track_id) -> bool:
    return bool(track_id) and bool(_TRACK_ID_RE.match(str(track_id)))


def _headers() -> dict:
    return {
        "merchant_api_key": Config.OXAPAY_MERCHANT_KEY,
        "Content-Type": "application/json",
        "Accept": "application/json",
    }


def is_configured() -> bool:
    """True only if the minimum config to create invoices is present."""
    return bool(
        Config.OXAPAY_MERCHANT_KEY
        and Config.OXAPAY_API_BASE
        and Config.OXAPAY_CALLBACK_URL
    )


def _unwrap(body: dict) -> dict:
    """v1 wraps the payload in `data`; tolerate a flat body too."""
    if isinstance(body, dict) and isinstance(body.get("data"), dict):
        return body["data"]
    return body if isinstance(body, dict) else {}


def create_invoice(amount: float, order_id: str, description: str = "") -> dict:
    """
    Create a payment invoice.

    Returns a normalised dict:
      {ok: True, track_id, pay_url, pay_address, expired_at(epoch|None), raw}
      {ok: False, error}
    Never raises.
    """
    if not is_configured():
        return {"ok": False, "error": "oxapay_not_configured"}

    url = f"{Config.OXAPAY_API_BASE}{Config.OXAPAY_INVOICE_PATH}"
    payload = {
        "amount": float(amount),
        "currency": Config.OXAPAY_CURRENCY,
        "lifetime": int(Config.OXAPAY_INVOICE_LIFETIME_MIN),
        "fee_paid_by_payer": int(Config.OXAPAY_FEE_PAID_BY_PAYER),
        "under_paid_coverage": float(Config.OXAPAY_UNDERPAID_COVERAGE),
        "callback_url": Config.OXAPAY_CALLBACK_URL,
        "order_id": order_id,
        "description": description or "Balance top-up",
    }
    if Config.OXAPAY_RETURN_URL:
        payload["return_url"] = Config.OXAPAY_RETURN_URL

    try:
        resp = requests.post(
            url, json=payload, headers=_headers(),
            timeout=Config.OXAPAY_HTTP_TIMEOUT,
        )
    except requests.exceptions.Timeout:
        logger.error(f"OxaPay create_invoice timeout order_id={order_id}")
        return {"ok": False, "error": "timeout"}
    except Exception as exc:
        logger.error(f"OxaPay create_invoice network error order_id={order_id}: {exc}")
        return {"ok": False, "error": "network_error"}

    try:
        body = resp.json()
    except Exception:
        logger.error(f"OxaPay create_invoice bad JSON status={resp.status_code} order_id={order_id}")
        return {"ok": False, "error": f"bad_response_{resp.status_code}"}

    if resp.status_code not in (200, 201):
        # v1 error bodies look like {"error": {"message": ...}} or {"message": ...}
        err = ""
        if isinstance(body, dict):
            err = (
                (body.get("error") or {}).get("message")
                if isinstance(body.get("error"), dict)
                else body.get("message")
            ) or ""
        logger.error(
            f"OxaPay create_invoice HTTP {resp.status_code} order_id={order_id}: {str(err)[:200]}"
        )
        return {"ok": False, "error": f"http_{resp.status_code}"}

    data = _unwrap(body)
    track_id = data.get("track_id") or data.get("trackId")
    pay_url = data.get("payment_url") or data.get("payLink") or data.get("pay_url")
    if not track_id or not pay_url:
        logger.error(f"OxaPay create_invoice missing track_id/pay_url order_id={order_id}: {str(body)[:200]}")
        return {"ok": False, "error": "incomplete_response"}

    return {
        "ok": True,
        "track_id": str(track_id),
        "pay_url": str(pay_url),
        "pay_address": data.get("address") or data.get("pay_address"),
        "expired_at": data.get("expired_at") or data.get("expiredAt"),
        "raw": data,
    }


def get_payment(track_id: str) -> dict:
    """
    Fetch the authoritative payment state from OxaPay (the only source we trust
    before crediting). Returns:
      {ok: True, status(lowercased), amount, currency, tx_hash, address, raw}
      {ok: False, error}
    Never raises.
    """
    if not Config.OXAPAY_MERCHANT_KEY or not Config.OXAPAY_API_BASE:
        return {"ok": False, "error": "oxapay_not_configured"}
    if not is_valid_track_id(track_id):
        return {"ok": False, "error": "bad_track_id"}

    url = f"{Config.OXAPAY_API_BASE}{Config.OXAPAY_INQUIRY_PATH}/{track_id}"

    # ── Why curl instead of requests here ────────────────────────────────────
    # This runs inside the main backend under `eventlet 0.33.3`, whose SSL
    # monkey-patch is BROKEN on Python 3.11: every stdlib SSLContext attribute
    # setter (`options`, `minimum_version`, …) recurses infinitely
    # (RecursionError), so requests/urllib3 CANNOT complete an outbound HTTPS
    # handshake here. curl performs TLS in its OWN process, fully unaffected by
    # eventlet — the same reason app/utils/telegram.py shells out to curl.
    #   • Run it OFF the eventlet hub via tpool (native thread) so the blocking
    #     subprocess wait never freezes the worker / broadcasts.
    #   • Pass the merchant key via --config on STDIN, never on argv, so it
    #     cannot leak into the process list.
    import json as _json
    import subprocess
    timeout = int(Config.OXAPAY_HTTP_TIMEOUT)
    cfg = (
        f'header = "merchant_api_key: {Config.OXAPAY_MERCHANT_KEY}"\n'
        'header = "Accept: application/json"\n'
    )
    cmd = ["curl", "-sS", "--max-time", str(timeout),
           "--connect-timeout", "10", "--config", "-", url]

    # --- Phase-2 diagnostics: measure tpool-acquire vs curl separately. The
    # _t dict is filled by _run when the curl ACTUALLY starts/ends (inside the
    # native thread), so (run_start - t0) isolates time spent waiting for a free
    # tpool thread. No behavior change: same subprocess/timeout/returns below.
    _diag_start()
    _t: dict = {"run_start": None, "run_end": None}

    def _run():
        _t["run_start"] = _time.monotonic()
        try:
            return subprocess.run(cmd, input=cfg.encode("utf-8"),
                                  capture_output=True, timeout=timeout + 5)
        finally:
            _t["run_end"] = _time.monotonic()

    global _inflight
    with _inflight_lock:
        _inflight += 1
    _t0 = _time.monotonic()
    try:
        try:
            try:
                from eventlet import tpool
                proc = tpool.execute(_run)      # off the hub — never blocks the worker
            except ImportError:
                proc = _run()                   # dev / no eventlet
        except subprocess.TimeoutExpired:
            _diag_log(track_id, _t0, _t, "curl_subprocess_timeout")
            logger.error(f"OxaPay get_payment timeout track_id={track_id} url={url}")
            return {"ok": False, "error": "timeout"}
        except FileNotFoundError:
            _diag_log(track_id, _t0, _t, "curl_missing")
            logger.error("OxaPay get_payment: curl not found on PATH")
            return {"ok": False, "error": "network_error:curl_missing"}
        except Exception as exc:
            etype = type(exc).__name__
            _diag_log(track_id, _t0, _t, f"exception:{etype}")
            logger.error(
                f"OxaPay get_payment curl-run FAILED track_id={track_id} url={url} "
                f"{etype}: {exc}", exc_info=True
            )
            return {"ok": False, "error": f"network_error:{etype}"}
    finally:
        with _inflight_lock:
            _inflight -= 1

    _diag_log(track_id, _t0, _t, "ok", rc=getattr(proc, "returncode", None))

    if proc.returncode != 0:
        err = (proc.stderr or b"").decode("utf-8", "replace")[:200].strip()
        logger.error(
            f"OxaPay get_payment curl rc={proc.returncode} track_id={track_id} "
            f"url={url} stderr={err!r}"
        )
        # rc 28 = timeout; treat as a transport failure the caller can retry.
        return {"ok": False, "error": f"network_error:curl_rc_{proc.returncode}"}

    try:
        body = _json.loads((proc.stdout or b"").decode("utf-8", "replace"))
    except Exception:
        logger.error(f"OxaPay get_payment bad JSON track_id={track_id}")
        return {"ok": False, "error": "bad_response"}

    data = _unwrap(body)
    status = str(data.get("status") or "").strip().lower()

    # tx hash can live in a `txs` list (v1) or a flat field.
    tx_hash = data.get("tx_hash") or data.get("txID") or data.get("txid")
    if not tx_hash:
        txs = data.get("txs") or data.get("transactions")
        if isinstance(txs, list) and txs:
            first = txs[0]
            if isinstance(first, dict):
                tx_hash = first.get("tx_hash") or first.get("hash") or first.get("txID")

    return {
        "ok": True,
        "status": status,
        "amount": data.get("amount"),
        "currency": data.get("currency"),
        "tx_hash": tx_hash,
        "address": data.get("address"),
        "raw": data,
    }


def verify_hmac(raw_body: bytes, signature: Optional[str]) -> bool:
    """
    Verify the webhook signature: HMAC-SHA512 of the EXACT raw request body,
    keyed by the Merchant API Key, compared (constant-time) to the `HMAC`
    header OxaPay sends. Without the merchant key a forged body cannot produce
    a valid signature.
    """
    if not Config.OXAPAY_MERCHANT_KEY or not signature or not raw_body:
        return False
    try:
        expected = hmac.new(
            Config.OXAPAY_MERCHANT_KEY.encode("utf-8"),
            raw_body,
            hashlib.sha512,
        ).hexdigest()
        return hmac.compare_digest(expected, str(signature).strip())
    except Exception:
        return False


# Terminal/positive statuses as reported by OxaPay v1 (lowercased).
PAID_STATUSES = frozenset({"paid", "confirmed", "complete", "completed"})
EXPIRED_STATUSES = frozenset({"expired"})
FAILED_STATUSES = frozenset({"failed", "cancelled", "canceled"})
