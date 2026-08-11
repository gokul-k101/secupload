"""Protocol tests: envelopes, AAD, control messages, registry sync, replay."""

from __future__ import annotations

import uuid

import pytest
from sih_shared.crypto import (
    AESGCM_NONCE_SIZE,
    generate_ed25519_keypair,
    generate_x25519_keypair,
)
from sih_shared.models import CredentialPublic, CredentialStatus
from sih_shared.protocol import (
    ControlType,
    Envelope,
    MsgType,
    Op,
    ProtocolError,
    RequestMessage,
    ResponseMessage,
    RespStatus,
    build_aad,
    encode_control,
    encode_enrollment_body,
    encode_registry_entry,
    encode_registry_snapshot,
    encode_request_message,
    encode_response_message,
    envelope_msg_type,
    envelope_recipient,
    new_envelope,
    parse_control,
    parse_enrollment_body,
    parse_envelope,
    parse_registry_entry,
    parse_registry_snapshot,
    parse_request_message,
    parse_response_message,
    registry_entry_from_public,
    status_to_code,
)
from sih_shared.replay import ReplayCache, envelope_replay_key, timestamp_ok

ALICE = uuid.uuid4()
BOB = uuid.uuid4()


def make_envelope(
    msg_type: int = MsgType.REQUEST,
    sender: uuid.UUID = ALICE,
    recipient: uuid.UUID = BOB,
    payload: bytes = b"hello",
) -> Envelope:
    return new_envelope(
        msg_type=msg_type,
        sender_uuid=sender,
        recipient_uuid=recipient,
        request_id=uuid.uuid4(),
        sender_credential_version=2,
        timestamp=1_700_000_000,
        nonce=b"n" * AESGCM_NONCE_SIZE,
        payload=payload,
    )


def test_envelope_roundtrip_and_signature() -> None:
    priv, pub = generate_ed25519_keypair()
    env = make_envelope()
    env.sign(priv)
    parsed = parse_envelope(env.encode())
    assert parsed.msg_type == env.msg_type
    assert parsed.sender_uuid == env.sender_uuid
    assert parsed.recipient_uuid == env.recipient_uuid
    assert parsed.payload == env.payload
    assert parsed.sender_credential_version == env.sender_credential_version
    parsed.verify(pub)  # must not raise


def test_tampered_payload_fails_verification() -> None:
    priv, pub = generate_ed25519_keypair()
    env = make_envelope(payload=b"authentic")
    env.sign(priv)
    env.payload = b"forged"
    with pytest.raises(ProtocolError):
        env.verify(pub)


def test_wrong_key_fails_verification() -> None:
    env = make_envelope()
    env.sign(generate_ed25519_keypair()[0])
    with pytest.raises(ProtocolError):
        env.verify(generate_ed25519_keypair()[1])


def test_signature_covers_metadata() -> None:
    priv, pub = generate_ed25519_keypair()
    env = make_envelope()
    env.sign(priv)
    env.timestamp += 1  # modify signed metadata
    with pytest.raises(ProtocolError):
        env.verify(pub)


def test_parse_rejects_truncated_envelope() -> None:
    priv, _ = generate_ed25519_keypair()
    env = make_envelope()
    env.sign(priv)
    data = env.encode()
    with pytest.raises(ProtocolError):
        parse_envelope(data[: len(data) // 2])


def test_proxy_routing_header() -> None:
    priv, _ = generate_ed25519_keypair()
    env = make_envelope(sender=ALICE, recipient=BOB, msg_type=MsgType.CONTROL)
    env.sign(priv)
    data = env.encode()
    assert envelope_recipient(data) == BOB
    assert envelope_msg_type(data) == MsgType.CONTROL


def test_build_aad_canonical_and_binding() -> None:
    kw = dict(
        sender_uuid=ALICE,
        recipient_uuid=BOB,
        request_id=uuid.uuid4(),
        sender_credential_version=1,
        timestamp=123,
        nonce=b"n" * 12,
        chunk_index=0,
    )
    assert build_aad(**kw) == build_aad(**kw)
    for field in ("sender_credential_version", "timestamp", "chunk_index"):
        mutated = dict(kw)
        mutated[field] = (0 if kw[field] != 0 else 1)
        assert build_aad(**mutated) != build_aad(**kw)


def test_request_response_messages_roundtrip() -> None:
    req = RequestMessage(
        op=Op.WRITE, object_uuid=uuid.uuid4(), file_type="text", file_size=42, metadata="{}"
    )
    parsed = parse_request_message(encode_request_message(req))
    assert parsed.op == req.op
    assert parsed.object_uuid == req.object_uuid
    assert parsed.file_type == req.file_type
    assert parsed.file_size == req.file_size
    assert parsed.metadata == req.metadata

    resp = ResponseMessage(status=RespStatus.OK, message="ok", file_size=7)
    parsed_resp = parse_response_message(encode_response_message(resp))
    assert parsed_resp.status == RespStatus.OK
    assert parsed_resp.message == "ok"
    assert parsed_resp.file_size == 7


def test_control_messages_roundtrip() -> None:
    body = encode_enrollment_body(1, "tok123", 1, b"e" * 32, b"x" * 32)
    data = encode_control(ControlType.ENROLL, body)
    parsed = parse_control(data)
    assert parsed.ctype == ControlType.ENROLL
    kind, token, version, ed_pub, x_pub = parse_enrollment_body(parsed.body)
    assert (kind, token, version) == (1, "tok123", 1)
    assert ed_pub == b"e" * 32


def test_registry_snapshot_roundtrip() -> None:
    ident = uuid.uuid4()
    _, ed_pub = generate_ed25519_keypair()
    _, x_pub = generate_x25519_keypair()
    cred = CredentialPublic(
        identity_uuid=ident,
        version=2,
        ed25519_public=ed_pub,
        x25519_public=x_pub,
        status=CredentialStatus.ACTIVE,
        created_at=100,
        validation_deadline=150,
        activation_time=150,
        expiration_time=250,
    )
    entry = registry_entry_from_public(cred)
    assert entry.status == status_to_code(CredentialStatus.ACTIVE)
    parsed_entry = parse_registry_entry(encode_registry_entry(entry))
    assert parsed_entry == entry
    snapshot = parse_registry_snapshot(encode_registry_snapshot([entry, entry]))
    assert len(snapshot) == 2
    assert snapshot[0] == entry


def test_replay_cache() -> None:
    cache = ReplayCache(max_entries=3)
    key = envelope_replay_key(ALICE.bytes, uuid.uuid4().bytes, b"nonce")
    assert cache.check_and_add(key) is True
    assert cache.check_and_add(key) is False
    assert len(cache) == 1


def test_replay_cache_lru_eviction() -> None:
    cache = ReplayCache(max_entries=2)
    k1 = envelope_replay_key(b"a", b"a", b"a")
    k2 = envelope_replay_key(b"b", b"b", b"b")
    k3 = envelope_replay_key(b"c", b"c", b"c")
    assert cache.check_and_add(k1)
    assert cache.check_and_add(k2)
    assert cache.check_and_add(k1) is False  # refresh k1
    assert cache.check_and_add(k3)  # evicts k2 (LRU)
    assert cache.check_and_add(k2) is True  # k2 no longer cached


def test_timestamp_window() -> None:
    now = 1_700_000_000
    assert timestamp_ok(now, now)
    assert timestamp_ok(now + 299, now)
    assert timestamp_ok(now - 300, now)
    assert not timestamp_ok(now + 301, now)
    assert not timestamp_ok(now - 301, now)


def test_envelope_signing_uses_owner_private_key() -> None:
    """Private keys are never transmitted: only the signature is."""
    priv, pub = generate_ed25519_keypair()
    env = make_envelope()
    env.sign(priv)
    data = env.encode()
    assert priv not in data
