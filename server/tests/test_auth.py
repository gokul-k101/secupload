"""Authenticator tests: envelope signature, timestamp window, replay."""

from __future__ import annotations

import time
import uuid

import pytest
from conftest import enroll_client
from sih_server.auth import AuthError
from sih_shared.crypto import generate_ed25519_keypair
from sih_shared.protocol import MsgType, new_envelope


def make_envelope(
    ident,
    ed_priv,
    version,
    timestamp,
    nonce=None,
    payload=b"",
    recipient=None,
    msg_type=MsgType.REQUEST.value,
):
    env = new_envelope(
        msg_type,
        ident,
        recipient or uuid.UUID(int=1),
        uuid.uuid4(),
        version,
        timestamp,
        nonce or uuid.uuid4().bytes[:12],
        payload,
    )
    env.sign(ed_priv)
    return env


def test_valid_envelope_authenticates(registry, identity, audit, authenticator):
    ident, ed_priv, x_priv, x_pub = enroll_client(registry, identity, audit)
    env = make_envelope(ident, ed_priv, 1, int(time.time()))
    kind, cred = authenticator.authenticate(env)
    assert cred.identity_uuid == ident
    assert cred.version == 1


def test_bad_signature_rejected(registry, identity, audit, authenticator):
    ident, ed_priv, x_priv, x_pub = enroll_client(registry, identity, audit)
    other_priv, _ = generate_ed25519_keypair()
    env = make_envelope(ident, other_priv, 1, int(time.time()))
    with pytest.raises(AuthError) as exc:
        authenticator.authenticate(env)
    assert exc.value.code == "BAD_SIGNATURE"


def test_stale_timestamp_rejected(registry, identity, audit, authenticator):
    ident, ed_priv, x_priv, x_pub = enroll_client(registry, identity, audit)
    env = make_envelope(ident, ed_priv, 1, int(time.time()) - 400)
    with pytest.raises(AuthError) as exc:
        authenticator.authenticate(env)
    assert exc.value.code == "STALE_TIMESTAMP"


def test_replay_rejected(registry, identity, audit, authenticator):
    ident, ed_priv, x_priv, x_pub = enroll_client(registry, identity, audit)
    env = make_envelope(ident, ed_priv, 1, int(time.time()))
    authenticator.authenticate(env)
    with pytest.raises(AuthError) as exc:
        authenticator.authenticate(env)
    assert exc.value.code == "REPLAY"


def test_unknown_version_rejected(registry, identity, audit, authenticator):
    ident, ed_priv, x_priv, x_pub = enroll_client(registry, identity, audit)
    env = make_envelope(ident, ed_priv, 99, int(time.time()))
    with pytest.raises(AuthError) as exc:
        authenticator.authenticate(env)
    assert exc.value.code == "BAD_CREDENTIAL"


def test_unknown_identity_rejected(registry, identity, audit, authenticator):
    ed_priv, ed_pub = generate_ed25519_keypair()
    env = make_envelope(uuid.uuid4(), ed_priv, 1, int(time.time()))
    with pytest.raises(AuthError) as exc:
        authenticator.authenticate(env)
    assert exc.value.code == "BAD_CREDENTIAL"


def test_replay_of_different_message_allowed(
    registry, identity, audit, authenticator
):
    ident, ed_priv, x_priv, x_pub = enroll_client(registry, identity, audit)
    e1 = make_envelope(ident, ed_priv, 1, int(time.time()))
    e2 = make_envelope(ident, ed_priv, 1, int(time.time()), nonce=uuid.uuid4().bytes[:12])
    authenticator.authenticate(e1)
    kind, cred = authenticator.authenticate(e2)  # different nonce -> fresh
    assert cred.version == 1
