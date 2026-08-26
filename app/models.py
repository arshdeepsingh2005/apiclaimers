"""
Database models aligned with the legacy FastAPI service.
"""
from sqlalchemy import (
    BigInteger,
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.sql import func

from app.database import Base


class User(Base):
    """
    Minimal user representation sourced from public.app_users.
    """

    __tablename__ = "app_users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(64), unique=True, nullable=False, index=True)
    usd_claim_amount = Column(Float, nullable=False, default=0.0)


class ExchangeRate(Base):
    """
    Stores exchange rates relative to USD.
    Example: 1 USD = rate * target_currency
    """

    __tablename__ = "exchange_rates"

    id = Column(Integer, primary_key=True, index=True)
    target_currency = Column(String(10), nullable=False, index=True)  # ISO code like INR, EUR
    rate_from_usd = Column(Float, nullable=False)


class CodeClaim(Base):
    """
    Aggregate claim counter for each unique code (stored lowercase).

    Written only from the conversion worker via a single atomic
    INSERT ... ON CONFLICT (code) DO UPDATE statement, so no row-level
    locking or read-then-write race window exists.

    No timestamps by design — the "first claim" signal comes from the
    RETURNING (xmax = 0) AS inserted expression inside the upsert, not
    from a created_at column.
    """

    __tablename__ = "code_claims"

    code = Column(String(64), primary_key=True)  # stored lowercase
    total_claims_count = Column(Integer, nullable=False, default=1)


class License(Base):
    """
    Per-Telegram-user license issued via the bot. license_key is the PK.

    During admin rotation, an old row may coexist with a new row briefly;
    only the active one is unique per telegram_id — enforced by the
    partial unique index uq_licenses_tid_active.
    """

    __tablename__ = "licenses"

    license_key = Column(String(60), primary_key=True)
    telegram_id = Column(BigInteger, nullable=False, index=True)
    active = Column(Boolean, nullable=False, default=False)
    theclaimers_count = Column(Integer, nullable=False, default=0)
    usd_claim_amount = Column(Float, nullable=False, default=0.0)
    maximum_usernames = Column(Integer, nullable=False, default=100)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    activated_at = Column(DateTime(timezone=True), nullable=True)
    deactivated_at = Column(DateTime(timezone=True), nullable=True)
    banned = Column(Boolean, nullable=False, default=False)
    ban_reason = Column(Text, nullable=True)
    manager_id = Column(String(64), nullable=True)
    # Prepaid balance in USD. Topped up MANUALLY by the admin for now. Each
    # successful claim on a *percentage* license deducts deduction_percentage%
    # of the claimed USD from this balance. Allowed to go negative — the
    # license-scanner auto-disables the license the moment it drops below 0.
    available_balance = Column(Float, nullable=False, default=0.0)
    # Per-claim deduction rate in percent (e.g. 4 => 4%). NEW licenses default to
    # 4 (the prepaid model). NULL is the legacy "After Claims Payment" mode kept
    # for pre-existing rows: no balance deduction, no balance UI, no auto-disable.
    # The default is applied at the ORM layer here AND as a DB column DEFAULT
    # (see app.database.ensure_license_columns) so EVERY creation path gets it.
    deduction_percentage = Column(Float, nullable=True, default=4.0)
    # Preferred UI language for the bot's messages (ISO 639-1, e.g. 'en','ja').
    # NULL => auto-detect from the Telegram client's language_code. A per-USER
    # preference stored on EVERY license row for the telegram_id (the bot's
    # set-lang updates them all), so whichever row lic/info returns carries it.
    # Also added as a DB column via app.database.ensure_license_columns.
    language = Column(String(8), nullable=True)

    __table_args__ = (
        # partial unique index — only ONE active license per telegram_id,
        # allowing rotation INSERT-then-DELETE within a single transaction
        Index(
            'uq_licenses_tid_active',
            'telegram_id',
            unique=True,
            postgresql_where=Column('active'),
        ),
    )


# LicenseClaimLog removed — per-claim audit storage replaced by stdout
# CLAIM / CLAIM_COUNT log lines. Migration: DROP TABLE license_claim_log;


class Payment(Base):
    """
    OxaPay balance top-up invoice + its lifecycle (audit-grade).

    One row per invoice. `order_id` is OUR merchant invoice id (a uuid we mint
    BEFORE calling OxaPay, so a row always exists even if the provider call or
    the process dies mid-flight). `track_id` is OxaPay's invoice id, filled in
    after creation.

    Idempotency / anti-double-credit is enforced by THREE independent guards:
      1. UNIQUE(order_id) and UNIQUE(track_id) — a provider invoice maps to at
         most one row, so duplicate webhooks can't fan out into duplicate rows.
      2. `credited` boolean — the hard "balance already applied" latch, flipped
         inside the same locked transaction that applies the credit.
      3. SELECT ... FOR UPDATE on this row in the webhook path serialises
         concurrent/duplicate callbacks so the credit runs exactly once.

    Money is NEVER credited from webhook data alone — the webhook is only a
    trigger; the real status is re-fetched from the OxaPay API first.
    """

    __tablename__ = "payments"

    id = Column(Integer, primary_key=True, index=True)
    # Our merchant invoice id (uuid4 hex). Created before the provider call.
    order_id = Column(String(64), unique=True, nullable=False, index=True)
    # OxaPay invoice id. Nullable until the create call returns; unique after.
    track_id = Column(String(64), unique=True, nullable=True, index=True)
    telegram_id = Column(BigInteger, nullable=False, index=True)
    # License at creation time (audit). The credit resolves the user's CURRENT
    # license by telegram_id so key rotation between create and pay is handled.
    license_key = Column(String(60), nullable=True, index=True)
    amount = Column(Float, nullable=False)              # USD requested
    currency = Column(String(10), nullable=False, default="USD")
    pay_url = Column(Text, nullable=True)
    pay_address = Column(Text, nullable=True)
    tx_hash = Column(Text, nullable=True)
    # new → waiting → paid | expired | failed | cancelled
    status = Column(String(20), nullable=False, default="new", index=True)
    # Hard idempotency latch: True once the balance credit has been applied.
    credited = Column(Boolean, nullable=False, default=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )
    confirmed_at = Column(DateTime(timezone=True), nullable=True)
    expires_at = Column(DateTime(timezone=True), nullable=True)
    # Last raw webhook body (audit / forensics). Bounded before storage.
    webhook_payload = Column(Text, nullable=True)
    error_reason = Column(Text, nullable=True)


class ClaimerApi(Base):
    """
    Admin-managed remote configuration for one claimer (userscript instance).

    Identity is the client-generated, GM-persisted `claimer_id` (UUID) scoped
    per `telegram_id`; `claimer_name` is a human display label. There is a hard
    separation, enforced structurally, between:

      * DESIRED config (`desired_*`) — the authoritative intent, written ONLY by
        admin actions (Set API / Currency / Filters). Reconciliation pushes this
        to the live claimer.
      * OBSERVED state (`observed_*`, `stake_username`, `version`) — what the
        claimer last reported. Written ONLY by the client `claimerStatus` path,
        used for display + diffing, and NEVER allowed to overwrite `desired_*`.

    This is the durable backing store; the runtime source of truth is the
    in-memory `_claimer_cache` (mirrors `active_license_cache`). Observed/meta
    updates are batched to this table every 30-60s by a background flush worker;
    desired-config changes are write-through (persisted immediately).

    The API token is stored via `_enc_token`/`_dec_token` (pass-through in Phase 1,
    swappable for encryption in Phase 2) and is NEVER logged or returned to the
    bot/admin — only its fingerprint (`desired_token_fp`) is compared.
    """

    __tablename__ = "claimer_apis"

    id = Column(Integer, primary_key=True, index=True)
    telegram_id = Column(BigInteger, nullable=False, index=True)
    claimer_id = Column(String(64), nullable=False)     # client UUID (GM-persisted)
    claimer_name = Column(String(64), nullable=True)    # display label

    # ── DESIRED (authoritative; admin writes only) ──────────────────────────
    desired_token = Column(Text, nullable=True)         # opaque, via _enc/_dec
    desired_token_fp = Column(String(64), nullable=True)  # sha256(token) short
    desired_currency = Column(String(10), nullable=True)
    desired_filters = Column(Text, nullable=True)       # JSON, true-only blocked

    # ── OBSERVED (informational; client writes only) ────────────────────────
    observed_api_fp = Column(String(64), nullable=True)
    observed_api_valid = Column(Boolean, nullable=False, default=False)
    observed_currency = Column(String(10), nullable=True)
    observed_filters = Column(Text, nullable=True)      # JSON, true-only blocked
    stake_username = Column(String(64), nullable=True)
    version = Column(String(32), nullable=True)

    # ── META ────────────────────────────────────────────────────────────────
    online = Column(Boolean, nullable=False, default=False)
    # synced | needs_sync | push_failed
    config_state = Column(String(20), nullable=False, default="synced")
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    last_seen = Column(DateTime(timezone=True), nullable=True)
    last_api_validation = Column(DateTime(timezone=True), nullable=True)
    last_push = Column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        # One row per (telegram_id, claimer_id).
        Index('uq_claimer_apis_tid_cid', 'telegram_id', 'claimer_id', unique=True),
    )



# ===========================================================================
# API-Claimer product (multi-API / slot model). Isolated new tables — the
# legacy tables above are inherited from the copied backend and mostly unused
# here. See the plan: an ACCOUNT owns up to N SLOTS; a SLOT has a stable
# backend-assigned slot_id (identity), a MUTABLE Stake token + resolved
# username (metadata), and per-slot config. Claims are deduped by
# (account_id, slot_id, code_norm) with a claimed-wins upsert.
# ===========================================================================

class ApiAccount(Base):
    """
    A purchasable API-Claimer account (the operator-entered 'userscript value'
    authenticates as this account). Manually activated by the admin for now;
    the bot purchase flow wires in later. Multiple concurrent connections
    (RDPs) per account are allowed, capped by max_connections.
    """

    __tablename__ = "api_accounts"

    id = Column(Integer, primary_key=True, index=True)
    # The account credential the script enters (its identity value). Unique.
    license_key = Column(String(80), unique=True, nullable=False, index=True)
    owner_telegram_id = Column(BigInteger, nullable=True, index=True)
    active = Column(Boolean, nullable=False, default=False)     # manual activation
    banned = Column(Boolean, nullable=False, default=False)
    ban_reason = Column(Text, nullable=True)
    # Purchased slot cap (how many api_slots this account may register).
    max_slots = Column(Integer, nullable=False, default=7)
    # RDP/connection cap (e.g. 2 for premium redundancy).
    max_connections = Column(Integer, nullable=False, default=2)
    # Operator sellable-capacity pool: when True this account's free slot_indexes
    # are sold to buyers by the Telegram bot (Σ max_slots of pool accounts = total
    # capacity). worker_label is the CUSTOMER-SAFE display name (e.g. "Worker 3")
    # shown in the Mini App — never an RDP name / IP / region.
    is_pool = Column(Boolean, nullable=False, default=False, index=True)
    worker_label = Column(String(40), nullable=True)
    plan = Column(String(40), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    activated_at = Column(DateTime(timezone=True), nullable=True)
    expires_at = Column(DateTime(timezone=True), nullable=True)


class ApiSlot(Base):
    """
    One API slot = one Stake claiming identity within an account.

    `id` (slot_id) is the STABLE internal identity — backend-assigned, pushed
    to every RDP, and the dedup key. The Stake token + resolved username are
    MUTABLE under a fixed slot_id (the user can swap the API key; we re-resolve
    the username or mark it invalid). `slot_index` is the 0-based position
    within the account (unique per account) for the 7-slot UI.

    `stake_access_token` is stored opaque via the service-layer _enc/_dec hook
    (same pattern as ClaimerApi.desired_token). Raw-token storage is an
    accepted risk (operator revokes on leak) and the tables use RLS.
    """

    __tablename__ = "api_slots"

    id = Column(Integer, primary_key=True, index=True)          # slot_id (stable identity)
    account_id = Column(Integer, ForeignKey("api_accounts.id", ondelete="CASCADE"),
                        nullable=False, index=True)
    slot_index = Column(Integer, nullable=False)                # 0..max_slots-1 within account
    slot_telegram_id = Column(BigInteger, nullable=True)

    # ── Stake credentials (MUTABLE under a fixed slot_id) ────────────────────
    stake_access_token = Column(Text, nullable=True)            # opaque, via _enc/_dec
    token_fp = Column(String(64), nullable=True)                # sha256(token) short
    stake_username = Column(String(64), nullable=True)          # metadata only — re-resolved on key change
    token_valid = Column(Boolean, nullable=False, default=False)

    # ── Per-slot config (editable in Settings / Telegram app later) ──────────
    withdrawal_currency = Column(String(10), nullable=True)
    reload_currency = Column(String(10), nullable=True)
    auto_vault = Column(Boolean, nullable=False, default=False)
    auto_bonus = Column(Boolean, nullable=False, default=False)
    auto_reload = Column(Boolean, nullable=False, default=False)
    value_filter = Column(Text, nullable=True)                  # JSON/opaque filter config

    # ── Plan / lifecycle (per-slot sale) ─────────────────────────────────────
    plan = Column(String(40), nullable=True)
    purchased_at = Column(DateTime(timezone=True), nullable=True)
    expires_at = Column(DateTime(timezone=True), nullable=True)
    status = Column(String(20), nullable=False, default="active")  # active|expired|revoked

    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    __table_args__ = (
        # One slot per (account, slot_index) — the 7-slot grid position.
        UniqueConstraint('account_id', 'slot_index', name='uq_api_slots_acct_idx'),
    )


class ApiClaim(Base):
    """
    Per-(account, slot, code) claim ledger with CLAIMED-WINS dedup.

    The unique (account_id, slot_id, code_norm) key makes a claim recorded
    exactly once across 2 RDPs. Recording uses:
        INSERT ... ON CONFLICT (account_id, slot_id, code_norm)
        DO UPDATE SET claimed=true, ...
        WHERE api_claims.claimed=false AND EXCLUDED.claimed=true
    so a later claimed=true (RDP2) UPGRADES an earlier already_claimed (RDP1);
    a claimed row is never downgraded; pure duplicates no-op. Identity is the
    stable slot_id, never the (mutable) username — username is a snapshot.
    """

    __tablename__ = "api_claims"

    id = Column(Integer, primary_key=True, index=True)
    account_id = Column(Integer, ForeignKey("api_accounts.id", ondelete="CASCADE"),
                        nullable=False, index=True)
    slot_id = Column(Integer, ForeignKey("api_slots.id", ondelete="CASCADE"),
                     nullable=False, index=True)
    # IMMUTABLE ownership snapshot: the Telegram ID that OWNED this slot at the
    # moment of the claim. Unlike ApiSlot.slot_telegram_id (which is REASSIGNED
    # when an expired slot's row is reused by a new buyer), this is written once
    # and never changed — so a buyer's history stays bound to THEM even after the
    # physical slot_id is handed to someone else. Customer-facing stats are scoped
    # by this column (never by the reusable slot_id), which is what prevents a new
    # buyer of a reused slot from seeing the previous owner's claims. Nullable only
    # for pre-migration rows (which then belong to nobody and are shown to nobody).
    telegram_id = Column(BigInteger, nullable=True, index=True)
    # Claim KIND — 'drop' | 'bonus' | 'reload'. Lets the Stats dashboard show the
    # Drops tab (codes) separately from the Reloads tab. Immutable snapshot (never
    # in the on-conflict SET). Legacy rows are NULL and are treated as drops.
    claim_type = Column(String(10), nullable=True, index=True)
    code_norm = Column(String(64), nullable=False)
    claimed = Column(Boolean, nullable=False, default=False)
    error_code = Column(String(40), nullable=True)
    currency = Column(String(10), nullable=True)
    amount = Column(Float, nullable=True)
    slot_username = Column(String(64), nullable=True)           # snapshot at claim time
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    __table_args__ = (
        UniqueConstraint('account_id', 'slot_id', 'code_norm', name='uq_api_claims_acct_slot_code'),
    )


class ApiOrder(Base):
    """
    A slot PURCHASE order (Telegram bot self-serve flow).

    Lifecycle (state machine — transitions enforced in app/routes/api_customer.py
    under a row lock, never re-entering a terminal state):

        pending ──pay──> paid ──allocate──> allocated   (terminal)
        pending ──────────────────────────> failed | reservation_expired
        paid ─────────────────────────────> refunded

    `allocated` is terminal: `allocate` is idempotent (SELECT ... FOR UPDATE +
    the unique `slot_id` once set), so two concurrent allocate calls yield
    EXACTLY ONE ApiSlot / capacity decrement / userscript push; the loser returns
    the already-assigned slot_id.

    SECURITY — the pending Stake token is held ONLY as an encrypted, short-lived
    secret in `enc_stake_token` (Fernet/AES-GCM keyed by Config.TOKEN_ENC_KEY). It
    is written at order/begin, decrypted ONCE inside allocate to move it onto the
    ApiSlot, then WIPED (set NULL). It is never logged, never returned to the Mini
    App, never included in GET /order/<id> or any error object, and is
    secure-deleted whenever the order goes failed/refunded/reservation_expired.
    price_usd / plan_code / duration_days live ONLY here (server-side) so the
    browser cannot mutate them after invoice creation.

    Reservation: a buyer with a prior successful payment may hold a
    (reserved_pool_account_id, reserved_slot_index) with a SHORT self-expiring
    `reservation_expires_at`. Capacity counts a reservation only while it is
    unexpired, so an abandoned checkout frees the slot at read time (the sweep
    then deletes the row + wipes the token). At most one active reservation per
    telegram_id.
    """

    __tablename__ = "api_orders"

    id = Column(Integer, primary_key=True, index=True)
    order_id = Column(String(64), unique=True, nullable=False, index=True)   # uuid
    telegram_id = Column(BigInteger, nullable=False, index=True)             # owner (server-derived)
    plan_code = Column(String(40), nullable=False)
    price_usd = Column(Float, nullable=False)
    duration_days = Column(Integer, nullable=False)
    stake_username = Column(String(64), nullable=True)                       # verified snapshot
    slot_config = Column(Text, nullable=True)                                # JSON, NON-SECRET only

    # Encrypted pending token — NULL once moved to the slot or securely deleted.
    enc_stake_token = Column(Text, nullable=True)

    status = Column(String(24), nullable=False, default="pending", index=True)
    slot_id = Column(Integer, ForeignKey("api_slots.id", ondelete="SET NULL"), nullable=True)

    # Capacity reservation (unpaid hold; self-expiring).
    reserved_pool_account_id = Column(Integer, ForeignKey("api_accounts.id", ondelete="SET NULL"),
                                      nullable=True)
    reserved_slot_index = Column(Integer, nullable=True)
    reservation_expires_at = Column(DateTime(timezone=True), nullable=True, index=True)

    track_id = Column(String(80), nullable=True)                             # OxaPay track id
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
