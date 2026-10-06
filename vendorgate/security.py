"""Cryptographic helpers -- section 6 of the plan.

Nothing here writes to a log and nothing returns a secret except the functions
whose whole job is to mint one.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import string

import pyotp
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from cryptography.fernet import Fernet, InvalidToken
from itsdangerous import BadSignature, URLSafeSerializer

# Argon2id with the library defaults, which follow the current RFC 9106
# low-memory recommendation.  Tuning belongs in deployment, not here.
_hasher = PasswordHasher()

#: Number of random bytes behind a link token (section 6.1: ~43 url-safe chars).
TOKEN_BYTES = 32

#: Number of random bytes behind a session id.
SESSION_BYTES = 32

_PASSWORD_ALPHABET = string.ascii_letters + string.digits + "!@#$%^&*-_=+"


# --------------------------------------------------------------------------- #
# passwords
# --------------------------------------------------------------------------- #

def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    """Constant-time-ish verify that never raises on a malformed stored hash."""
    try:
        return _hasher.verify(password_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError, TypeError, ValueError):
        return False


def needs_rehash(password_hash: str) -> bool:
    try:
        return _hasher.check_needs_rehash(password_hash)
    except (InvalidHashError, ValueError):
        return False


def generate_password(length: int = 16) -> str:
    """Random vendor password.  At least one character from each class so it
    survives any downstream complexity rule."""
    if length < 12:
        length = 12
    while True:
        pw = "".join(secrets.choice(_PASSWORD_ALPHABET) for _ in range(length))
        if (
            any(c.islower() for c in pw)
            and any(c.isupper() for c in pw)
            and any(c.isdigit() for c in pw)
            and any(c in "!@#$%^&*-_=+" for c in pw)
        ):
            return pw


# --------------------------------------------------------------------------- #
# tokens and hashes
# --------------------------------------------------------------------------- #

def generate_link_token() -> str:
    """URL-safe link token, 32 bytes of OS randomness (~43 characters)."""
    return secrets.token_urlsafe(TOKEN_BYTES)


def generate_session_id() -> str:
    return secrets.token_urlsafe(SESSION_BYTES)


def generate_public_id() -> str:
    """Short, non-secret identifier shown in the dashboard (e.g. ``g-7FQ2K9``)."""
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    return "g-" + "".join(secrets.choice(alphabet) for _ in range(6))


def sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def keyed_hash(secret_key: str, label: str, value: str) -> str:
    """HMAC-SHA256 of *value*, domain-separated by *label*.

    Used for anything stored for later comparison: a raw hash of a short input
    (such as a user-agent string) would be guessable, a keyed one is not.
    """
    mac = hmac.new(secret_key.encode("utf-8"), f"{label}:{value}".encode("utf-8"), hashlib.sha256)
    return mac.hexdigest()


def hash_token(secret_key: str, token: str) -> str:
    return keyed_hash(secret_key, "link-token", token)


def hash_session(secret_key: str, session_id: str) -> str:
    return keyed_hash(secret_key, "session", session_id)


def device_fingerprint(secret_key: str, user_agent: str | None) -> str:
    """Light device fingerprint (section 6.3).

    Deliberately weak: only the user-agent string.  Anything stronger (IP, TLS
    fingerprint) breaks real vendors on mobile networks for no real gain -- the
    password plus the one-login rule do the actual work.
    """
    normalised = " ".join((user_agent or "").split())[:512]
    return keyed_hash(secret_key, "device", normalised)


def constant_time_equals(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


# --------------------------------------------------------------------------- #
# cookie signing
# --------------------------------------------------------------------------- #

def serializer(secret_key: str, salt: str) -> URLSafeSerializer:
    return URLSafeSerializer(secret_key, salt=salt)


def sign_cookie(secret_key: str, salt: str, payload: dict) -> str:
    return serializer(secret_key, salt).dumps(payload)


def unsign_cookie(secret_key: str, salt: str, value: str) -> dict | None:
    try:
        data = serializer(secret_key, salt).loads(value)
    except BadSignature:
        return None
    return data if isinstance(data, dict) else None


# --------------------------------------------------------------------------- #
# TOTP (stored encrypted, section 6.7)
# --------------------------------------------------------------------------- #

def generate_totp_enc_key() -> str:
    return Fernet.generate_key().decode("ascii")


def _fernet(totp_enc_key: str) -> Fernet:
    if not totp_enc_key:
        raise RuntimeError("TOTP_ENC_KEY is not set -- cannot handle TOTP secrets")
    return Fernet(totp_enc_key.encode("ascii"))


def generate_totp_secret() -> str:
    return pyotp.random_base32()


def encrypt_totp_secret(totp_enc_key: str, secret: str) -> str:
    return _fernet(totp_enc_key).encrypt(secret.encode("ascii")).decode("ascii")


def decrypt_totp_secret(totp_enc_key: str, blob: str) -> str | None:
    try:
        return _fernet(totp_enc_key).decrypt(blob.encode("ascii")).decode("ascii")
    except (InvalidToken, ValueError):
        return None


def verify_totp(secret: str, code: str, valid_window: int = 1) -> bool:
    """Check a 6-digit code, tolerating one step of clock drift either way."""
    code = (code or "").strip().replace(" ", "")
    if not code.isdigit() or len(code) != 6:
        return False
    return pyotp.TOTP(secret).verify(code, valid_window=valid_window)


def totp_provisioning_uri(secret: str, email: str, issuer: str = "VendorGate") -> str:
    return pyotp.TOTP(secret).provisioning_uri(name=email, issuer_name=issuer)


def derive_fernet_key_from_secret(secret_key: str) -> str:
    """Last-resort TOTP key derived from SECRET_KEY, for a local dev run only."""
    digest = hashlib.sha256(("totp-enc:" + secret_key).encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii")
