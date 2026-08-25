"""
Encryption for the PENDING Stake token held in api_orders before payment.

The token is written encrypted at order/begin, decrypted exactly once inside
order/allocate to move it onto the slot, then wiped. Fernet (AES-128-CBC +
HMAC-SHA256, authenticated) keyed by Config.TOKEN_ENC_KEY.

TOKEN_ENC_KEY may be either a real Fernet key (32 urlsafe-base64 bytes) or any
string — in the latter case we derive a stable Fernet key from SHA-256(secret),
so the system works out of the box while still allowing a dedicated key. Falls
back to LICENSE_JWT_SECRET when TOKEN_ENC_KEY is unset.
"""
import base64
import hashlib

from cryptography.fernet import Fernet, InvalidToken

from app.config import Config

_fernet = None


def _derive_key(secret: str) -> bytes:
    """Accept a real Fernet key as-is; otherwise derive one from the secret."""
    s = (secret or "").strip()
    # A valid Fernet key is 44 urlsafe-b64 chars decoding to 32 bytes.
    try:
        if len(s) == 44:
            raw = base64.urlsafe_b64decode(s.encode("utf-8"))
            if len(raw) == 32:
                return s.encode("utf-8")
    except Exception:
        pass
    digest = hashlib.sha256(s.encode("utf-8")).digest()   # 32 bytes
    return base64.urlsafe_b64encode(digest)


def _get_fernet() -> Fernet:
    global _fernet
    if _fernet is None:
        secret = Config.TOKEN_ENC_KEY or Config.LICENSE_JWT_SECRET or Config.SECRET_KEY
        _fernet = Fernet(_derive_key(secret))
    return _fernet


def encrypt_token(plain: str) -> str:
    """Encrypt a raw token → opaque string for enc_stake_token. '' / None → None."""
    if not plain:
        return None
    return _get_fernet().encrypt(plain.encode("utf-8")).decode("ascii")


def decrypt_token(stored: str):
    """Decrypt enc_stake_token → raw token, or None if empty/tampered/undecryptable."""
    if not stored:
        return None
    try:
        return _get_fernet().decrypt(stored.encode("ascii")).decode("utf-8")
    except (InvalidToken, Exception):
        return None
