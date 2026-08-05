"""
Encryption for stored scan credentials.

Scan credentials are the most dangerous data Bulwark holds. Unlike a password,
they cannot be hashed — the scanner has to replay them — so they are encrypted
at rest with a key that lives only in the environment, never in the database.
An attacker with a database dump or a stolen backup gets ciphertext and
nothing else.

This module fails closed. With no key configured, encryption raises rather
than falling back to storing plaintext, and the API refuses to accept
credentials at all. A scanner that quietly stores customer session cookies in
cleartext would be worse than one that declines the feature.

Key management:
  - CREDENTIAL_ENCRYPTION_KEY holds a urlsafe-base64 32-byte Fernet key.
  - Generate one with:  python -c "from cryptography.fernet import Fernet;
    print(Fernet.generate_key().decode())"
  - Rotating the key makes existing stored credentials undecryptable; they
    must be re-entered. Decryption failures are surfaced, never silently
    treated as "no credential", so a rotation cannot cause scans to quietly
    run unauthenticated while reporting success.
"""
from functools import lru_cache

import structlog
from cryptography.fernet import Fernet, InvalidToken

from app.config import get_settings

logger = structlog.get_logger()


class CredentialEncryptionUnavailable(RuntimeError):
    """No usable encryption key is configured."""


class CredentialDecryptionError(RuntimeError):
    """Stored ciphertext could not be decrypted with the current key."""


@lru_cache(maxsize=1)
def _cipher() -> Fernet:
    key = (get_settings().credential_encryption_key or "").strip()
    if not key:
        raise CredentialEncryptionUnavailable(
            "CREDENTIAL_ENCRYPTION_KEY is not set. Scan credentials cannot be "
            "stored without it. Generate a key with: python -c \"from "
            "cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\""
        )
    try:
        return Fernet(key.encode("utf-8"))
    except Exception as exc:
        raise CredentialEncryptionUnavailable(
            f"CREDENTIAL_ENCRYPTION_KEY is not a valid Fernet key: {exc}"
        ) from exc


def encryption_available() -> bool:
    """Whether credentials can be stored, without raising."""
    try:
        _cipher()
        return True
    except CredentialEncryptionUnavailable:
        return False


def encrypt_secret(plaintext: str) -> str:
    if not plaintext:
        raise ValueError("Refusing to encrypt an empty secret.")
    return _cipher().encrypt(plaintext.encode("utf-8")).decode("ascii")


def decrypt_secret(token: str) -> str:
    """Decrypt stored ciphertext.

    Raises rather than returning None on failure: a scan that silently drops
    its credential would run unauthenticated and report a clean result for a
    surface it never actually reached.
    """
    try:
        return _cipher().decrypt(token.encode("ascii")).decode("utf-8")
    except InvalidToken as exc:
        # Deliberately no ciphertext or key material in the message.
        raise CredentialDecryptionError(
            "Stored credential could not be decrypted. This usually means "
            "CREDENTIAL_ENCRYPTION_KEY changed since it was saved; re-enter "
            "the credential."
        ) from exc
