"""
Models for the SECOND (claims) database.

These are registered on `ClaimsBase` — NOT the primary `Base` — so that
`ClaimsBase.metadata.create_all(bind=claims_engine)` creates ONLY this table on
the claims database and never interferes with the license tables (and the
primary `Base.metadata.create_all` never tries to create this table).

The single `claims` table is the durable backing store for the /count command
(multi-day retention). Each row is self-contained: telegram_id, license_key and
username are all denormalised so /count queries never need a cross-DB join back
to the license database.
"""
from sqlalchemy import (
    BigInteger,
    Column,
    DateTime,
    Float,
    Index,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.sql import func

from app.database import ClaimsBase


class Claim(ClaimsBase):
    """
    One successful, credited claim.

    Idempotency: UNIQUE(username, code) — a given Stake account claims a given
    code at most once. Inserts use ON CONFLICT (username, code) DO NOTHING so a
    reconnect retry / double-tab / corrected follow-up is stored exactly once,
    matching the upstream `_check_and_mark_converted` marker.
    """

    __tablename__ = "claims"

    id = Column(BigInteger, primary_key=True, autoincrement=True)
    # TIMESTAMPTZ default now() — stored in UTC; all window math is done in the
    # query layer (IST windows are converted to UTC before the SQL filter).
    ts = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    license_key = Column(Text, nullable=True)
    telegram_id = Column(BigInteger, nullable=True)
    username = Column(String(64), nullable=False)
    code = Column(String(64), nullable=False)
    amount_usd = Column(Float, nullable=False)
    currency = Column(String(10), nullable=True)
    original_amount = Column(Float, nullable=True)

    __table_args__ = (
        UniqueConstraint("username", "code", name="uq_claims_username_code"),
        Index("ix_claims_tg_ts", "telegram_id", "ts"),
        Index("ix_claims_lic_ts", "license_key", "ts"),
        Index("ix_claims_user_ts", "username", "ts"),
        Index("ix_claims_ts", "ts"),
    )
