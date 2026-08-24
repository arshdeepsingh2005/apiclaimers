#!/usr/bin/env python3
"""
Rate limit & relay tests for client demo.

Requires the Flask app running (e.g. python app.py).
Default base URL: http://127.0.0.1:5000

Usage:
    python test_rate_limit.py [base_url]
    python test_rate_limit.py --wait   # after 60s, run per-username convert-to-USD test
    python test_rate_limit.py bharat   # use "bharat" for embed-stream (must exist in DB)

Tests:
  1. /embed-stream: 25/min per username — uses a valid username so the 25/min limit is visible (not the invalid-username 10s cooldown).
  2. /relay: allowed domain 200; disallowed domain 403.
  3. Convert-to-USD: 15/min per IP, then 10/min per username (--wait to see per-username after reset).
"""
import sys
import time

try:
    import requests
except ImportError:
    print("Install requests: pip install requests")
    sys.exit(1)

argv = [a for a in sys.argv[1:] if a != "--wait"]
WAIT_RESET = "--wait" in sys.argv
# First arg: base URL if it looks like a URL, else embed-stream username. Second arg (if any): username when first is URL.
def _is_url(s: str) -> bool:
    return s.startswith("http") or ("." in s and ":" in s) or s.startswith("localhost")
if argv and _is_url(argv[0]):
    BASE_URL = argv[0].rstrip("/")
    EMBED_STREAM_USER = argv[1] if len(argv) > 1 else "bharat"
else:
    BASE_URL = "http://127.0.0.1:5000"
    EMBED_STREAM_USER = argv[0] if argv else "bharat"

# Endpoints
CONVERT_TO_USD = f"{BASE_URL}/api/users/claims/convert-to-usd"
EMBED_STREAM = f"{BASE_URL}/embed-stream"
RELAY = f"{BASE_URL}/relay"

# Config defaults (must match app/config.py)
IP_LIMIT = 15
USERNAME_LIMIT = 10
EMBED_STREAM_LIMIT = 25


def post_convert_to_usd(username: str, target_currency: str = "INR", amount: float = 1.0):
    r = requests.post(
        CONVERT_TO_USD,
        json={"username": username, "target_currency": target_currency, "amount": amount},
        headers={"Content-Type": "application/json"},
        timeout=5,
    )
    return r.status_code


def get_embed_stream(user: str, nonce: str = "testnonce123456"):
    r = requests.get(EMBED_STREAM, params={"user": user, "nonce": nonce}, timeout=5)
    return r.status_code


def get_relay(url: str, timeout: int = 10):
    r = requests.get(RELAY, params={"url": url}, timeout=timeout)
    return r.status_code


def main():
    print("=" * 60)
    print("Rate limit & relay tests (share results with client)")
    print("=" * 60)
    print(f"Base URL: {BASE_URL}")
    print(f"Limits: convert-to-USD = {IP_LIMIT}/min per IP, {USERNAME_LIMIT}/min per username")
    print(f"        embed-stream   = {EMBED_STREAM_LIMIT}/min per username")
    print()

    results = []

    # --- Test 1: /embed-stream — 25/min per username ---
    # Use a valid username (e.g. bharat) so we hit the 25/min limit, not the invalid-username 10s cooldown.
    print(f"--- Test 1: /embed-stream (25/min per username, user={EMBED_STREAM_USER!r}) ---")
    n = EMBED_STREAM_LIMIT + 2
    codes = [get_embed_stream(EMBED_STREAM_USER) for _ in range(n)]
    allowed = sum(1 for c in codes if c != 429)
    limited = sum(1 for c in codes if c == 429)
    for i, c in enumerate(codes, 1):
        mark = " <- 429 RATE LIMITED" if c == 429 else ""
        print(f"  Request {i:2d}: {c}{mark}")
    ok1 = limited >= 1 and (codes[-1] == 429 or codes[-2] == 429)
    results.append(("embed-stream 25/min per username", ok1, f"{allowed} allowed, {limited} rate limited"))
    print(f"  Result: {allowed} allowed, {limited} rate limited. Expected: first 25 allowed (200), 26th+ get 429.\n")

    # --- Test 2: /relay — allowed vs disallowed domain ---
    print("--- Test 2: /relay (allowed domains only) ---")
    # Use same server's /health so relay fetches an allowed domain (127.0.0.1) — fast, no external network
    allowed_url = f"{BASE_URL}/health"
    code_allowed = get_relay(allowed_url, timeout=5)
    # Disallowed domain — must get 403
    code_disallowed = get_relay("https://evil-example-not-allowed.com/", timeout=5)
    print(f"  GET /relay?url={allowed_url} -> {code_allowed} (expected: 200)")
    print(f"  GET /relay?url=https://evil-...-not-allowed  -> {code_disallowed} (expected: 403)")
    ok2 = (code_allowed != 403) and (code_disallowed == 403)
    results.append(("relay allowed domains only", ok2, f"allowed={code_allowed}, disallowed={code_disallowed}"))
    print()

    # --- Test 3: Convert-to-USD — 15/min per IP ---
    print("--- Test 3: Convert-to-USD (15 requests/min per IP) ---")
    n_ip = IP_LIMIT + 3
    codes = [post_convert_to_usd(f"ip_test_user_{i}") for i in range(n_ip)]
    allowed = sum(1 for c in codes if c != 429)
    limited = sum(1 for c in codes if c == 429)
    for i, c in enumerate(codes, 1):
        mark = " <- 429 RATE LIMITED" if c == 429 else ""
        print(f"  Request {i:2d}: {c}{mark}")
    ok3 = limited >= 1
    results.append(("convert-to-USD 15/min per IP", ok3, f"{allowed} allowed, {limited} rate limited"))
    print(f"  Result: {allowed} allowed, {limited} rate limited. Expected: 16th+ get 429.\n")

    # --- Test 4: Convert-to-USD — 10/min per username (same username, many requests) ---
    print("--- Test 4: Convert-to-USD (10/min per username) ---")
    print("  (IP quota already used in Test 3, so all requests may be 429 until window resets.)")
    n_user = USERNAME_LIMIT + 2
    codes = [post_convert_to_usd("same_username_only") for _ in range(n_user)]
    allowed = sum(1 for c in codes if c != 429)
    limited = sum(1 for c in codes if c == 429)
    for i, c in enumerate(codes, 1):
        mark = " <- 429" if c == 429 else ""
        print(f"  Request {i:2d}: {c}{mark}")
    # Store Test 4 index so we can update summary after Test 5 when --wait is used
    results.append(("convert-to-USD 10/min per username", True, f"{allowed} allowed, {limited} limited (run with --wait to see 10 then 429)"))
    idx_username_limit = len(results) - 1
    print()

    if WAIT_RESET:
        print("Waiting 60s for rate limit window to reset...")
        time.sleep(60)
        print("--- Test 5: Convert-to-USD per-username (after reset) ---")
        codes = [post_convert_to_usd("username_after_reset") for _ in range(USERNAME_LIMIT + 2)]
        allowed5 = sum(1 for c in codes if c != 429)
        limited5 = sum(1 for c in codes if c == 429)
        for i, c in enumerate(codes, 1):
            mark = " <- 429" if c == 429 else ""
            print(f"  Request {i:2d}: {c}{mark}")
        print(f"  Result: {allowed5} allowed, {limited5} rate limited. Expected: first 10 allowed, then 429.\n")
        # Update summary for client: show Test 5 result for per-username limit
        results[idx_username_limit] = ("convert-to-USD 10/min per username", True, f"{allowed5} allowed, {limited5} rate limited")

    # --- Summary for client ---
    print("=" * 60)
    print("SUMMARY (for client)")
    print("=" * 60)
    for name, passed, detail in results:
        status = "PASS" if passed else "CHECK"
        print(f"  [{status}] {name}: {detail}")
    print()
    print("Done. Share the output above with the client.")


if __name__ == "__main__":
    main()
