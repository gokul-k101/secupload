"""Cryptographic primitives used by the system.

Only established primitives from ``cryptography`` are used (SR-32):

* Ed25519 — authentication and signatures (SR-15)
* X25519 — application key agreement (SR-16)
* HKDF-SHA256 — key derivation
* AES-256-GCM — primary application encryption

The X25519 credential key is never used directly as an AES key; a fresh
AES-256-GCM key is always derived through HKDF (key separation, section 27
of the spec).
"""

from __future__ import annotations

import hashlib
import os

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

ED25519_PRIVATE_SIZE = 32
ED25519_PUBLIC_SIZE = 32
ED25519_SIGNATURE_SIZE = 64
X25519_PRIVATE_SIZE = 32
X25519_PUBLIC_SIZE = 32
AESGCM_KEY_SIZE = 32
AESGCM_NONCE_SIZE = 12

# HKDF parameters: distinct salts/info strings per purpose so that keys from
# different contexts never collide even when the ECDH shared secret repeats.
_APP_SALT = b"sih-app-enc-v1"
_OBJECT_INFO_PREFIX = b"sih-object-key-v1\x00"


class CryptoError(ValueError):
    pass


class SignatureError(CryptoError):
    pass


class AuthenticationError(CryptoError):
    pass


def random_bytes(n: int) -> bytes:
    return os.urandom(n)


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def generate_ed25519_keypair() -> tuple[bytes, bytes]:
    """Return (private, public) raw key bytes."""
    key = Ed25519PrivateKey.generate()
    return (
        key.private_bytes_raw(),
        key.public_key().public_bytes_raw(),
    )


def generate_x25519_keypair() -> tuple[bytes, bytes]:
    """Return (private, public) raw key bytes."""
    key = X25519PrivateKey.generate()
    return (
        key.private_bytes_raw(),
        key.public_key().public_bytes_raw(),
    )


def sign_ed25519(private_key: bytes, data: bytes) -> bytes:
    try:
        key = Ed25519PrivateKey.from_private_bytes(private_key)
    except ValueError as exc:  # pragma: no cover - defensive
        raise CryptoError("invalid Ed25519 private key") from exc
    return key.sign(data)


def verify_ed25519(public_key: bytes, data: bytes, signature: bytes) -> None:
    """Raise SignatureError if the signature is invalid."""
    if len(signature) != ED25519_SIGNATURE_SIZE:
        raise SignatureError("invalid signature length")
    try:
        key = Ed25519PublicKey.from_public_bytes(public_key)
    except ValueError as exc:
        raise CryptoError("invalid Ed25519 public key") from exc
    try:
        key.verify(signature, data)
    except InvalidSignature as exc:
        raise SignatureError("Ed25519 signature verification failed") from exc


def x25519_shared_secret(private_key: bytes, peer_public_key: bytes) -> bytes:
    try:
        priv = X25519PrivateKey.from_private_bytes(private_key)
        pub = X25519PublicKey.from_public_bytes(peer_public_key)
    except ValueError as exc:
        raise CryptoError("invalid X25519 key material") from exc
    return priv.exchange(pub)


def _hkdf(ikm: bytes, info: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=AESGCM_KEY_SIZE,
        salt=_APP_SALT,
        info=info,
    ).derive(ikm)


def object_key_from_shared(shared_secret: bytes, object_uuid: bytes) -> bytes:
    """Derive the per-object AES-256-GCM key from the ECDH shared secret."""
    return _hkdf(shared_secret, _OBJECT_INFO_PREFIX + object_uuid)


def message_key_from_shared(shared_secret: bytes) -> bytes:
    """Derive the per-message AES-256-GCM key from the ECDH shared secret."""
    return _hkdf(shared_secret, b"sih-message-key-v1")


def seal_message(
    recipient_x25519_public: bytes,
    nonce: bytes,
    aad: bytes,
    plaintext: bytes,
) -> tuple[bytes, bytes]:
    """Encrypt ``plaintext`` to the recipient's X25519 public key.

    Returns ``(ephemeral_public_key, ciphertext)``.  A fresh ephemeral
    X25519 key is generated per message so each message gets a fresh
    encryption context (SR-28).
    """
    if len(nonce) != AESGCM_NONCE_SIZE:
        raise CryptoError("invalid AES-GCM nonce size")
    ephemeral = X25519PrivateKey.generate()
    shared = ephemeral.exchange(X25519PublicKey.from_public_bytes(recipient_x25519_public))
    key = message_key_from_shared(shared)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, aad)
    return ephemeral.public_key().public_bytes_raw(), ciphertext


def open_message(
    recipient_x25519_private: bytes,
    ephemeral_public: bytes,
    nonce: bytes,
    aad: bytes,
    ciphertext: bytes,
) -> bytes:
    """Decrypt a message encrypted with :func:`seal_message`.

    Raises AuthenticationError on AAD/ciphertext tampering.
    """
    try:
        shared = x25519_shared_secret(recipient_x25519_private, ephemeral_public)
        key = message_key_from_shared(shared)
        return AESGCM(key).decrypt(nonce, ciphertext, aad)
    except CryptoError as exc:
        raise AuthenticationError("decryption failed") from exc
    except (InvalidTag, ValueError) as exc:
        raise AuthenticationError("AES-GCM authentication failure") from exc


def chunk_nonce(chunk_index: int) -> bytes:
    """Unique nonce for a chunk under the shared per-object key.

    Counter-derived: unique per chunk index, and the key itself is fresh
    per object, so same-key nonce reuse is impossible (SR-28).
    """
    if chunk_index < 0 or chunk_index >= 1 << 96:
        raise CryptoError("chunk index out of range")
    return chunk_index.to_bytes(AESGCM_NONCE_SIZE, "big")


def seal_chunk(
    recipient_x25519_public: bytes,
    object_uuid: bytes,
    chunk_index: int,
    aad: bytes,
    chunk: bytes,
) -> tuple[bytes, bytes]:
    """Encrypt one object chunk; returns (ephemeral_public, ciphertext)."""
    ephemeral = X25519PrivateKey.generate()
    shared = ephemeral.exchange(X25519PublicKey.from_public_bytes(recipient_x25519_public))
    key = object_key_from_shared(shared, object_uuid)
    ciphertext = AESGCM(key).encrypt(chunk_nonce(chunk_index), chunk, aad)
    return ephemeral.public_key().public_bytes_raw(), ciphertext


def open_chunk(
    recipient_x25519_private: bytes,
    object_uuid: bytes,
    chunk_index: int,
    aad: bytes,
    ephemeral_public: bytes,
    ciphertext: bytes,
) -> bytes:
    """Decrypt one object chunk; raises AuthenticationError on tampering."""
    try:
        shared = x25519_shared_secret(recipient_x25519_private, ephemeral_public)
        key = object_key_from_shared(shared, object_uuid)
        return AESGCM(key).decrypt(chunk_nonce(chunk_index), ciphertext, aad)
    except CryptoError as exc:
        raise AuthenticationError("decryption failed") from exc
    except (InvalidTag, ValueError) as exc:
        raise AuthenticationError("AES-GCM authentication failure") from exc
