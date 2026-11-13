"""Envelope encryption for the secrets sandbox.

Two layers, on purpose:

    master key (KEK)  ──wraps──▶  data key (DEK)  ──encrypts──▶  secret value
    from the environment          random, per secret version       AES-256-GCM

Why not encrypt the values with the master key directly? Because rotation.
Rotating the master key rewraps each DEK — a handful of small blobs — and the
secret ciphertext never has to be decrypted and re-encrypted during a rotation.
The values stay sealed even if the rotation process is interrupted.

What this module refuses to do:

* accept a master key that is not exactly 256 bits;
* decrypt an envelope whose associated data does not match the secret name
  (a ciphertext moved from ``prod/stripe`` to ``dev/stripe`` will not open);
* reuse a nonce for a given key — every seal allocates a fresh DEK *and* fresh
  nonces.
"""

from __future__ import annotations

import base64
import os
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEY_BYTES = 32
NONCE_BYTES = 12
ENVELOPE_VERSION = 1
ALGORITHM = "AES-256-GCM"


class CryptoError(Exception):
    """Raised for any cryptographic failure. Never carries key material."""


def _encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _decode(text: str, *, expected: int | None, field: str) -> bytes:
    if not isinstance(text, str) or not text:
        raise CryptoError(f"{field} is missing or empty.")
    padded = text + "=" * (-len(text) % 4)
    try:
        raw = base64.urlsafe_b64decode(padded.encode("ascii"))
    except Exception as exc:  # noqa: BLE001 - any decode failure is the same error
        raise CryptoError(f"{field} is not valid base64url.") from exc
    if expected is not None and len(raw) != expected:
        raise CryptoError(f"{field} must decode to {expected} bytes.")
    return raw


def generate_master_key() -> str:
    """A fresh, shell-safe master key (43 characters, no padding)."""
    return _encode(os.urandom(KEY_BYTES))


def load_master_key(text: str) -> bytes:
    """Validate a master key from configuration.

    The error message is deliberately about *shape*, never content: a typo in
    the key must not print the key.
    """
    cleaned = (text or "").strip()
    if not cleaned:
        raise CryptoError("Master key is empty; set SECRETSD_MASTER_KEY or SECRETSD_MASTER_KEY_FILE.")
    key = _decode(cleaned, expected=KEY_BYTES, field="Master key")
    if len(set(key)) == 1:
        raise CryptoError("Master key is a single repeated byte; generate one with `secretsd --generate-key`.")
    return key


def fingerprint(master_key: bytes) -> str:
    """Short, non-reversible identifier for logs and health output."""
    import hashlib

    return hashlib.sha256(master_key).hexdigest()[:12]


def _aad(kind: str, name: str) -> bytes:
    # Binding the ciphertext to its name and purpose is what stops an operator
    # (or a bug) from promoting a dev secret into prod by moving the blob.
    return f"{kind}:{name}".encode("utf-8")


def seal(master_key: bytes, plaintext: bytes, name: str) -> dict[str, Any]:
    """Encrypt one secret value into a self-describing envelope."""
    dek = os.urandom(KEY_BYTES)
    value_nonce = os.urandom(NONCE_BYTES)
    ciphertext = AESGCM(dek).encrypt(value_nonce, plaintext, _aad("value", name))

    wrap_nonce = os.urandom(NONCE_BYTES)
    wrapped = AESGCM(master_key).encrypt(wrap_nonce, dek, _aad("dek", name))

    return {
        "v": ENVELOPE_VERSION,
        "alg": ALGORITHM,
        "name": name,
        "dek_wrapped": _encode(wrapped),
        "dek_nonce": _encode(wrap_nonce),
        "nonce": _encode(value_nonce),
        "ciphertext": _encode(ciphertext),
    }


def _unwrap_dek(master_key: bytes, envelope: dict[str, Any], name: str) -> bytes:
    wrapped = _decode(envelope.get("dek_wrapped"), expected=None, field="dek_wrapped")
    nonce = _decode(envelope.get("dek_nonce"), expected=NONCE_BYTES, field="dek_nonce")
    try:
        dek = AESGCM(master_key).decrypt(nonce, wrapped, _aad("dek", name))
    except InvalidTag as exc:
        raise CryptoError("Master key does not unwrap this secret (wrong key or tampered envelope).") from exc
    if len(dek) != KEY_BYTES:
        raise CryptoError("Unwrapped data key has the wrong length.")
    return dek


def open_envelope(master_key: bytes, envelope: dict[str, Any], name: str) -> bytes:
    """Decrypt an envelope, verifying its binding to ``name``."""
    if not isinstance(envelope, dict):
        raise CryptoError("Envelope is not an object.")
    if envelope.get("v") != ENVELOPE_VERSION:
        raise CryptoError(f"Unsupported envelope version: {envelope.get('v')!r}.")
    if envelope.get("alg") != ALGORITHM:
        raise CryptoError(f"Unsupported algorithm: {envelope.get('alg')!r}.")
    if envelope.get("name") != name:
        raise CryptoError("Envelope is bound to a different secret name.")

    dek = _unwrap_dek(master_key, envelope, name)
    nonce = _decode(envelope.get("nonce"), expected=NONCE_BYTES, field="nonce")
    ciphertext = _decode(envelope.get("ciphertext"), expected=None, field="ciphertext")
    try:
        return AESGCM(dek).decrypt(nonce, ciphertext, _aad("value", name))
    except InvalidTag as exc:
        raise CryptoError("Secret ciphertext failed authentication.") from exc


def rewrap(master_old: bytes, master_new: bytes, envelope: dict[str, Any], name: str) -> dict[str, Any]:
    """Re-wrap the data key under a new master key, leaving the value sealed."""
    dek = _unwrap_dek(master_old, envelope, name)
    wrap_nonce = os.urandom(NONCE_BYTES)
    wrapped = AESGCM(master_new).encrypt(wrap_nonce, dek, _aad("dek", name))
    rotated = dict(envelope)
    rotated["dek_wrapped"] = _encode(wrapped)
    rotated["dek_nonce"] = _encode(wrap_nonce)
    return rotated
