"""
Application configuration.
"""
import os
from dotenv import load_dotenv

load_dotenv()


class Config:
    """Base configuration."""
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key-change-in-production'
    DEBUG = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
    
    # WebSocket configuration
    # Auto-detected in app/__init__.py - 'threading' for dev, 'eventlet' for production
    SOCKETIO_ASYNC_MODE = os.environ.get('SOCKETIO_ASYNC_MODE', 'threading')  # Default to threading for local dev
    SOCKETIO_CORS_ALLOWED_ORIGINS = '*'
    
    # Code ingestion settings
    MAX_CODE_LENGTH = 1000
    CODE_QUEUE_SIZE = 1000
    MAX_CONTENT_LENGTH = 1 * 1024 * 1024  # 1MB max request body
    INGEST_SHARED_TOKEN = os.environ.get('INGEST_SHARED_TOKEN')
    AUTH_DISABLED = os.environ.get('AUTH_DISABLED', '').lower() == 'true'
    
    ENABLE_RSA_AUTH = os.environ.get('ENABLE_RSA_AUTH', 'false').lower() == 'true'
    MASK_CODE = os.environ.get('MASK_CODE', '').lower()   # ← ADD THIS LINE
    # Default delay (seconds) before the group FIRST-CLAIMED notification fires.
    # 0 = instant. Admin can change it at runtime via the bot's /claimdelay
    # command (in-memory; resets to this env default on restart).
    FIRST_CLAIM_DELAY_SEC = float(os.environ.get('FIRST_CLAIM_DELAY_SEC', '0'))
    # SSE configuration
    WS_SECRET = os.environ.get('WS_SECRET') or os.environ.get('SECRET_KEY') or 'dev-ws-secret-change-in-production'
    NONCE_SECRET = os.environ.get('NONCE_SECRET', '')

    # rollback flags: gate broadcast transports; default keeps SSE on, /_v off
    SSE_BROADCAST_ENABLED = os.environ.get('SSE_BROADCAST_ENABLED', 'true').lower() != 'false'
    V_BROADCAST_ENABLED = os.environ.get('V_BROADCAST_ENABLED', 'false').lower() == 'true'

    # API-Claimer product mode. When true (set in the API-Claimer backend's
    # Render env), the copied main-product background workers that query
    # main-product tables/services are NOT started — they would error/log-spam
    # against the new API-Claimer database and re-introduce the OxaPay tpool
    # hang. Disabled by this flag: license-balance scanner, username/balance
    # cache sweep, SSE cleanup, OxaPay conversion worker, claim_history pruner.
    # The session reaper (active_disconnect_loop) stays — it's in-memory only.
    # This IS the API-Claimer backend folder, so default the mode ON (env can
    # still override to 'false' if ever needed).
    API_CLAIMER_MODE = os.environ.get('API_CLAIMER_MODE', 'true').lower() == 'true'

    # Shared master account key. When set, ANY userscript that enters this exact
    # value connects to ONE shared api_account (auto-provisioned on first use —
    # no manual DB insert needed). All such scripts share that account's slots.
    # Defaults to 'cutie' so it works out of the box; override via env for a
    # stronger key. NOTE: anyone with this key can connect — use a long random
    # value in production.
    MASTER_ACCOUNT_KEY = (os.environ.get('MASTER_ACCOUNT_KEY', 'cutie') or '').strip()

    # License/Telegram system (Service 1 ↔ Service 2)
    # Falls back to SECRET_KEY so account-token issuance works out of the box
    # (override with a dedicated random value in production).
    LICENSE_JWT_SECRET = os.environ.get('LICENSE_JWT_SECRET', '') or SECRET_KEY
    INTERNAL_API_SECRET = os.environ.get('INTERNAL_API_SECRET', '')
    BOT_SERVICE_URL = os.environ.get('BOT_SERVICE_URL', '').rstrip('/')
    LICENSE_SCAN_INTERVAL = int(os.environ.get('LICENSE_SCAN_INTERVAL', '10'))
    LICENSE_TOKEN_EXPIRY_SECONDS = int(os.environ.get('LICENSE_TOKEN_EXPIRY_SECONDS', '7200'))
    MAX_CONNECTIONS_PER_LICENSE = int(os.environ.get('MAX_CONNECTIONS_PER_LICENSE', '100'))

    # Default per-claim deduction rate (%) applied to every NEW license unless
    # explicitly overridden. NULL/After-Claims is the legacy behaviour for
    # pre-existing rows; new rows default to this percentage + zero balance.
    DEFAULT_DEDUCTION_PERCENTAGE = float(os.environ.get('DEFAULT_DEDUCTION_PERCENTAGE', '4'))

    # Day-of-week rate schedule for DEFAULT-plan licenses ONLY (i.e. those whose
    # deduction_percentage == DEFAULT_DEDUCTION_PERCENTAGE). On Saturdays they are
    # charged the (lower) Saturday rate; every other day they pay the weekday
    # default. A license with a *custom* deduction_percentage (any value other
    # than the default) is charged that exact value EVERY day — the schedule does
    # not touch it. NULL deduction_percentage = After-Claims (no deduction).
    # The day is computed in IST (Asia/Kolkata) everywhere — see app.utils.ist.
    DEDUCTION_RATE_WEEKDAY = float(os.environ.get('DEDUCTION_RATE_WEEKDAY', os.environ.get('DEFAULT_DEDUCTION_PERCENTAGE', '4')))
    DEDUCTION_RATE_SATURDAY = float(os.environ.get('DEDUCTION_RATE_SATURDAY', '3.5'))

    # New licenses start with this unique-username cap (raised manually by admin).
    DEFAULT_MAX_USERNAMES = int(os.environ.get('DEFAULT_MAX_USERNAMES', '5'))

    # Per-license "balance changed" notifications are coalesced: after a burst of
    # successful claims goes quiet for this many seconds, ONE summary is sent.
    BALANCE_NOTIFY_DEBOUNCE_SEC = float(os.environ.get('BALANCE_NOTIFY_DEBOUNCE_SEC', '3'))

    # ── OxaPay balance top-up (v1 Merchant API) ───────────────────────────────
    # Everything is env-driven; nothing about the payment provider is hardcoded.
    # Auth is the Merchant API Key sent in the `merchant_api_key` header (v1).
    OXAPAY_MERCHANT_KEY = os.environ.get('OXAPAY_MERCHANT_KEY', '')
    OXAPAY_API_BASE = os.environ.get('OXAPAY_API_BASE', 'https://api.oxapay.com/v1').rstrip('/')
    # Relative paths under the base, overridable in case the account/API differs.
    OXAPAY_INVOICE_PATH = os.environ.get('OXAPAY_INVOICE_PATH', '/payment/invoice')
    # Inquiry is GET {base}{OXAPAY_INQUIRY_PATH}/{track_id}
    OXAPAY_INQUIRY_PATH = os.environ.get('OXAPAY_INQUIRY_PATH', '/payment')
    # Public callback URL OxaPay POSTs the webhook to. MUST be set for top-up to
    # work; points at this service's /pay/oxapay/webhook route.
    OXAPAY_CALLBACK_URL = os.environ.get('OXAPAY_CALLBACK_URL', '')
    # Where the payer's browser returns after paying (optional, cosmetic).
    OXAPAY_RETURN_URL = os.environ.get('OXAPAY_RETURN_URL', '')
    OXAPAY_CURRENCY = os.environ.get('OXAPAY_CURRENCY', 'USD')
    # Invoice lifetime in minutes (v1 accepts 15..2880). Expired invoices never credit.
    OXAPAY_INVOICE_LIFETIME_MIN = int(os.environ.get('OXAPAY_INVOICE_LIFETIME_MIN', '30'))
    # 0 = fee paid by merchant, 1 = fee paid by payer.
    OXAPAY_FEE_PAID_BY_PAYER = int(os.environ.get('OXAPAY_FEE_PAID_BY_PAYER', '1'))
    # Underpayment tolerance (%). 0 => only an exact/over payment is marked paid.
    OXAPAY_UNDERPAID_COVERAGE = float(os.environ.get('OXAPAY_UNDERPAID_COVERAGE', '0'))
    OXAPAY_HTTP_TIMEOUT = int(os.environ.get('OXAPAY_HTTP_TIMEOUT', '20'))
    # Break-glass ONLY. When False (default), main ALWAYS re-verifies with OxaPay
    # itself before crediting — the secure design. When True, if main's OWN
    # OxaPay call fails on a transport error, main will credit on the bot's
    # verified=True assertion (the bot confirmed PAID via its own inquiry).
    # Leave False; the greendns fix restores main's independent verification.
    TOPUP_TRUST_BOT_ON_VERIFY_FAIL = os.environ.get('TOPUP_TRUST_BOT_ON_VERIFY_FAIL', 'false').lower() == 'true'

    # Top-up amount bounds (USD). Enforced on BOTH the bot and the backend.
    TOPUP_MIN_USD = float(os.environ.get('TOPUP_MIN_USD', '1'))
    TOPUP_MAX_USD = float(os.environ.get('TOPUP_MAX_USD', '100'))
    # Admin gets alerted for attempts at/above this amount (defaults to the cap).
    OXAPAY_LARGE_PAYMENT_USD = float(os.environ.get('OXAPAY_LARGE_PAYMENT_USD', os.environ.get('TOPUP_MAX_USD', '100')))
    
    # Allowed origins for CORS and embed-stream
    ALLOWED_ORIGINS = [
        "https://kciade.online",
        "https://www.kciade.online",
        "https://stake.com",
        "https://stake.ac",
        "https://stake.games",
        "https://stake.bet",
        "https://stake.pet",
        "https://stake.mba",
        "https://stake.jp",
        "https://stake.bz",
        "https://stake.ceo",
        "https://stake.krd",
        "https://staketr.com",
        "https://stake1001.com",
        "https://stake1002.com",
        "https://stake1003.com",
        "https://stake1017.com",
        "https://stake1021.com",
        "https://stake1022.com",
        "https://stake1039.com",
        "https://stake.us",
        "https://stake.br",
        "https://stake1020.com",
        "https://stake1034.com",
        "https://stake1035.com",
        "https://stake1036.com",
        "https://stake1037.com",
        "https://stake1038.com",
        "https://stake1043.com",
        "https://stake1048.com",
        "https://stake1052.com",
        "https://stake1057.com",
        "https://stake1061.com",
        "https://stake1066.com",
        "https://stake1067.com",
        "https://stake1068.com",
        "https://stake1069.com",
        "https://stake1070.com",
        "https://stake1071.com",
        "https://stake1072.com",
        "https://stake1073.com",
        "https://stake1074.com",
        "https://stake1075.com",
        "https://stake1076.com",
        "https://stake1077.com",
        "https://stake1078.com",
        "https://stake1079.com",
        "https://stake1080.com",
        "https://stake1081.com",
        "https://stake1082.com",
        "https://stake1083.com",
        "https://stake1084.com",
        "https://stake1085.com",
        "https://stake1086.com",
        "https://stake1087.com",
        "https://stake1088.com",
        "https://stake1089.com",
        "https://stake1090.com",
        "https://stake1091.com",
        "https://stake1092.com",
        "https://stake1093.com",
        "https://stake1094.com",
        "https://stake1095.com",
        "https://stake3000.com",
        "https://stake3001.com",
        "https://stake3002.com",
        "https://stake3003.com",
        "https://stake3004.com",
        "https://stake3005.com",
        "https://stake3006.com",
        "https://stake3007.com",
        "https://stake3008.com",
        "https://stake3009.com",
        "https://stake3010.com",
        "https://stake3011.com",
        "https://stake3012.com",
        "https://stake3013.com",
        "https://stake3014.com",
        "https://stake3015.com",
        "https://stake3016.com",
        "https://stake3017.com",
        "https://stake3018.com",
        "https://stake3019.com",
        "https://stake3020.com",
        "https://stake3026.com",
        "https://stake3027.com",
        "https://stake3028.com",
        "https://stake3029.com",
        "https://stake3030.com",
        "https://stake3031.com",
        "https://stake3033.com",
        "https://stake3035.com",
        "https://stake3039.com",
        "https://stake3040.com",
        "https://stake3041.com",
        "https://stake3043.com",
        "https://stake3045.com",
        "https://stake3046.com",
        "https://stake3047.com",
        "https://stake3048.com",
        "https://stake3050.com",
        "https://stake3051.com",
        "https://stake3053.com",
        "https://stake3056.com",
        "https://stake3058.com",
        "https://stake3061.com",
        "https://stake3062.com",
        "https://stake3064.com",
        "https://stake3065.com",
        "https://stake3067.com",
        "https://stake3069.com",
        "https://stake3070.com",
        "https://stake3071.com",
        "https://stake3072.com",
        "https://stake3074.com",
        "https://stake3075.com",
        "https://stake3077.com",
        "https://stake3079.com",
        "https://stake3082.com",
        "https://stake3083.com",
        "https://stake3087.com",
        "https://stake3088.com",
        "https://stake3090.com",
        "https://stake3091.com",
        "https://stake3092.com",
        "https://stake3094.com",
        "https://stake3097.com",
        "https://stake3098.com",
        "https://stake3099.com",
        "https://stake3199.com",
        "https://stakeru8.com",
        "https://stakeru9.com",
        "https://stkmirror.com",
        "https://put-1.onrender.com",
        "https://tanishq-rl44.onrender.com"
    ]
    
    # Add Render host if available
    RENDER_HOST = os.environ.get('RENDER_EXTERNAL_URL', '')
    if RENDER_HOST:
        ALLOWED_ORIGINS.append(RENDER_HOST)
    
    # Add Cloudflare domain if available (for custom domains behind Cloudflare)
    CLOUDFLARE_DOMAIN = os.environ.get('CLOUDFLARE_DOMAIN', '')
    if CLOUDFLARE_DOMAIN:
        # Add both http and https versions
        if not CLOUDFLARE_DOMAIN.startswith('http'):
            ALLOWED_ORIGINS.extend([
                f"https://{CLOUDFLARE_DOMAIN}",
                f"http://{CLOUDFLARE_DOMAIN}",
                f"https://www.{CLOUDFLARE_DOMAIN}",
                f"http://www.{CLOUDFLARE_DOMAIN}"
            ])
        else:
            ALLOWED_ORIGINS.append(CLOUDFLARE_DOMAIN)
    
    # Development/localhost support - always allow localhost for testing
    import os
    if os.environ.get('FLASK_ENV') == 'development' or os.environ.get('FLASK_DEBUG', '').lower() == 'true':
        ALLOWED_ORIGINS.extend([
            "http://localhost:3000",
            "http://localhost:5000",
            "http://127.0.0.1:5000",
            "http://127.0.0.1:3000"
        ])
    
    # Pinned users - always kept in cache for fast WebSocket connections
    PINNED_USERS = ["bharat", "marc_henry"]
    NONCE_SECRET = os.environ.get('NONCE_SECRET', '')


    # Rate limiting (Flask-Limiter) — applied on username-bearing API endpoints
    # Per IP: max requests per minute (effectively max usernames one IP can send in 1 min)
    RATELIMIT_IP_USERNAME_PER_MINUTE = int(os.environ.get('RATELIMIT_IP_USERNAME_PER_MINUTE', '15'))
    # Per username: max requests per minute for the same username (convert-to-usd API)
    RATELIMIT_PER_USERNAME_PER_MINUTE = int(os.environ.get('RATELIMIT_PER_USERNAME_PER_MINUTE', '10'))
    # Per username on /embed-stream: max requests per minute per user param
    RATELIMIT_EMBED_STREAM_PER_USERNAME_PER_MINUTE = int(
        os.environ.get('RATELIMIT_EMBED_STREAM_PER_USERNAME_PER_MINUTE', '25')
    )
    # Rate limit storage: set RATELIMIT_STORAGE_URI for production (e.g. redis://...) when using multiple workers
    RATELIMIT_STORAGE_URI = os.environ.get('RATELIMIT_STORAGE_URI', '')

    # Domains the /relay endpoint is allowed to fetch (hostnames only, no scheme)
    RELAY_ALLOWED_DOMAINS = [
        'kciade.online',
        'www.kciade.online',
        'stake.com',
        'stake.ac',
        'stake.games',
        'stake.bet',
        'stake.pet',
        'stake.mba',
        'stake.jp',
        'stake.bz',
        'stake.ceo',
        'stake.krd',
        'staketr.com',
        'stake1001.com',
        'stake1002.com',
        'stake1003.com',
        'stake1017.com',
        'stake1021.com',
        'stake1022.com',
        'stake1039.com',
        'stake.us',
        'stake.br',
        'code-uksx.onrender.com',
        'https://put-1.onrender.com',
        'https://tanishq-rl44.onrender.com',
    ]
    # Allow adding relay domains via env (comma-separated)
    _relay_extra = os.environ.get('RELAY_ALLOWED_DOMAINS', '')
    if _relay_extra:
        RELAY_ALLOWED_DOMAINS.extend(d.strip().lower() for d in _relay_extra.split(',') if d.strip())

    # ── Attack-surface reduction (security hardening) ─────────────────────────
    # /relay is an unauthenticated allowlisted-fetch proxy that the current
    # license-only userscript never calls. Keep it OFF in production; flip on
    # only if a legitimate flow needs it.
    RELAY_ENABLED = os.environ.get('RELAY_ENABLED', 'false').lower() == 'true'
    # Legacy/iframe HTTP endpoints (/api/handshake, /api/codes, /api/server-time,
    # /api/users/claims/convert-to-usd, SSE /embed-stream, /events) are unused by
    # the license-only userscript. Left ENABLED by default so any old userscript
    # still in the wild keeps working; set to false to shrink the surface once
    # you've confirmed no legacy clients remain.
    LEGACY_ENDPOINTS_ENABLED = os.environ.get('LEGACY_ENDPOINTS_ENABLED', 'true').lower() == 'true'
