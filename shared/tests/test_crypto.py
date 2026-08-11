"""Cryptographic tests (spec section 63, the 12 required cases)."""

from __future__ import annotations

import uuid

import pytest
from sih_shared import crypto
from sih_shared.config import CHUNK_SIZE
from sih_shared.crypto import (
    AESGCM_NONCE_SIZE,
    AuthenticationError,
    SignatureError,
    chunk_nonce,
    generate_ed25519_keypair,
    generate_x25519_keypair,
    message_key_from_shared,
    object_key_from_shared,
    open_chunk,
    open_message,
    seal_chunk,
    seal_message,
    sha256,
    sign_ed25519,
    verify_ed25519,
    x25519_shared_secret,
)
from sih_shared.protocol import build_aad

DATA = b"the quick brown fox jumps over the lazy dog"


def _aad(**overrides) -> bytes:
    fields = dict(
        sender_uuid=uuid.uuid4(),
        recipient_uuid=uuid.uuid4(),
        request_id=uuid.uuid4(),
        sender_credential_version=2,
        timestamp=1_700_000_000,
        nonce=b"\x01" * AESGCM_NONCE_SIZE,
        chunk_index=0,
    )
    fields.update(overrides)
    return build_aad(**fields)


def test_1_ed25519_signing() -> None:
    priv, pub = generate_ed25519_keypair()
    sig = sign_ed25519(priv, DATA)
    assert len(sig) == crypto.ED25519_SIGNATURE_SIZE
    verify_ed25519(pub, DATA, sig)  # must not raise


def test_2_ed25519_verification() -> None:
    priv, pub = generate_ed25519_keypair()
    sig = sign_ed25519(priv, DATA)
    verify_ed25519(pub, DATA, sig)  # same key: ok


def test_3_invalid_signature_rejection() -> None:
    priv, pub = generate_ed25519_keypair()
    sig = sign_ed25519(priv, DATA)
    with pytest.raises(SignatureError):
        verify_ed25519(pub, DATA + b"x", sig)  # tampered data
    with pytest.raises(SignatureError):
        other_priv, _ = generate_ed25519_keypair()
        verify_ed25519(pub, DATA, sign_ed25519(other_priv, DATA))  # wrong key
    with pytest.raises(SignatureError):
        verify_ed25519(pub, DATA, b"short")  # bad length


def test_4_x25519_shared_secret_agreement() -> None:
    a_priv, a_pub = generate_x25519_keypair()
    b_priv, b_pub = generate_x25519_keypair()
    assert x25519_shared_secret(a_priv, b_pub) == x25519_shared_secret(b_priv, a_pub)
    assert len(x25519_shared_secret(a_priv, b_pub)) == 32
    c_priv, c_pub = generate_x25519_keypair()
    assert x25519_shared_secret(a_priv, b_pub) != x25519_shared_secret(a_priv, c_pub)


def test_5_hkdf_derivation() -> None:
    shared = b"shared-secret-material"
    assert len(message_key_from_shared(shared)) == 32
    assert message_key_from_shared(shared) == message_key_from_shared(shared)
    assert message_key_from_shared(shared + b"x") != message_key_from_shared(shared)
    obj = uuid.uuid4().bytes
    assert object_key_from_shared(shared, obj) == object_key_from_shared(shared, obj)
    assert object_key_from_shared(shared, obj) != object_key_from_shared(shared, b"other")
    assert object_key_from_shared(shared, obj) != message_key_from_shared(shared)


def test_6_aes_gcm_encryption_decryption() -> None:
    r_priv, r_pub = generate_x25519_keypair()
    nonce = crypto.random_bytes(AESGCM_NONCE_SIZE)
    aad = _aad()
    eph_pub, ct = seal_message(r_pub, nonce, aad, DATA)
    assert len(eph_pub) == 32
    assert ct != DATA
    opened = open_message(r_priv, eph_pub, nonce, aad, ct)
    assert opened == DATA


def test_7_tampered_ciphertext_rejection() -> None:
    r_priv, r_pub = generate_x25519_keypair()
    nonce = crypto.random_bytes(AESGCM_NONCE_SIZE)
    aad = _aad()
    eph_pub, ct = seal_message(r_pub, nonce, aad, DATA)
    tampered = bytearray(ct)
    tampered[-1] ^= 0x01  # flip a ciphertext/tag byte
    with pytest.raises(AuthenticationError):
        open_message(r_priv, eph_pub, nonce, aad, bytes(tampered))


def test_8_aad_mismatch_rejection() -> None:
    r_priv, r_pub = generate_x25519_keypair()
    nonce = crypto.random_bytes(AESGCM_NONCE_SIZE)
    aad = _aad()
    eph_pub, ct = seal_message(r_pub, nonce, aad, DATA)
    with pytest.raises(AuthenticationError):
        open_message(r_priv, eph_pub, nonce, _aad(timestamp=1234), ct)
    with pytest.raises(AuthenticationError):
        open_message(r_priv, eph_pub, nonce, _aad(chunk_index=7), ct)


def test_9_chunk_encryption_decryption() -> None:
    r_priv, r_pub = generate_x25519_keypair()
    obj = uuid.uuid4().bytes
    chunks = [bytes([i % 256]) * (CHUNK_SIZE // 10) for i in range(4)]
    for i, chunk in enumerate(chunks):
        aad = _aad(chunk_index=i)
        eph_pub, ct = seal_chunk(r_pub, obj, i, aad, chunk)
        opened = open_chunk(r_priv, obj, i, aad, eph_pub, ct)
        assert opened == chunk


def test_10_nonce_uniqueness() -> None:
    assert chunk_nonce(0) != chunk_nonce(1)
    assert chunk_nonce(5) == chunk_nonce(5)
    assert all(len(chunk_nonce(i)) == AESGCM_NONCE_SIZE for i in range(1000))
    # distinct indices produce distinct nonces under the same key
    assert len({chunk_nonce(i) for i in range(1000)}) == 1000
    # wrong-index nonce must fail authentication
    r_priv, r_pub = generate_x25519_keypair()
    obj = uuid.uuid4().bytes
    aad = _aad(chunk_index=3)
    eph_pub, ct = seal_chunk(r_pub, obj, 3, aad, DATA)
    with pytest.raises(AuthenticationError):
        open_chunk(r_priv, obj, 4, _aad(chunk_index=4), eph_pub, ct)


def test_11_encryption_context_separation() -> None:
    r_priv, r_pub = generate_x25519_keypair()
    # fresh ephemeral key per message -> fresh encryption context
    eph1, ct1 = seal_message(r_pub, crypto.random_bytes(12), _aad(), DATA)
    eph2, ct2 = seal_message(r_pub, crypto.random_bytes(12), _aad(), DATA)
    assert eph1 != eph2
    assert ct1 != ct2
    # message context and object context derive different keys from the same
    # ECDH shared secret (key separation, spec section 27)
    shared = x25519_shared_secret(generate_x25519_keypair()[0], r_pub)
    obj = uuid.uuid4().bytes
    assert message_key_from_shared(shared) != object_key_from_shared(shared, obj)
    # a message encrypted in the object context cannot be opened as a message
    obj_aad = _aad(chunk_index=0)
    eph, ct = seal_chunk(r_pub, obj, 0, obj_aad, DATA)
    with pytest.raises(AuthenticationError):
        open_message(r_priv, eph, chunk_nonce(0), obj_aad, ct)


def test_12_credential_version_binding() -> None:
    """The AAD binds the credential version: wrong version fails (SR-26)."""
    r_priv, r_pub = generate_x25519_keypair()
    nonce = crypto.random_bytes(AESGCM_NONCE_SIZE)
    aad = _aad(sender_credential_version=3)
    eph_pub, ct = seal_message(r_pub, nonce, aad, DATA)
    with pytest.raises(AuthenticationError):
        open_message(r_priv, eph_pub, nonce, _aad(sender_credential_version=2), ct)
    # canonical AAD: same inputs -> same bytes
    kw = dict(
        sender_uuid=uuid.uuid4(),
        recipient_uuid=uuid.uuid4(),
        request_id=uuid.uuid4(),
        sender_credential_version=1,
        timestamp=123,
        nonce=b"n" * 12,
        chunk_index=9,
    )
    assert build_aad(**kw) == build_aad(**kw)
    assert build_aad(**kw) != build_aad(**{**kw, "nonce": b"m" * 12})


def test_sha256() -> None:
    assert len(sha256(b"x")) == 32
    assert sha256(b"x") == sha256(b"x")
    assert sha256(b"x") != sha256(b"y")
