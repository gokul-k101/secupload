"""ServerIdentity tests: provisioning and self-rotation."""

from __future__ import annotations

from sih_server.identity import ServerIdentity
from sih_shared.models import CredentialStatus


def test_provision_creates_active_v1(config, session_factory, audit, now=1000):
    identity = ServerIdentity(
        config, session_factory, audit, now_seconds=now
    )
    identity.ensure_loaded()
    cred = identity.credential()
    assert cred.version == 1
    assert cred.status == CredentialStatus.ACTIVE
    ed_priv, x_priv = identity.active_keys()
    assert len(ed_priv) == 32
    assert len(x_priv) == 32


def test_reload_recovers_same_identity(config, session_factory, audit, now=1000):
    identity = ServerIdentity(config, session_factory, audit, now_seconds=now)
    identity.ensure_loaded()
    v1 = identity.credential().version
    reloaded = ServerIdentity(config, session_factory, audit, now_seconds=now)
    reloaded.ensure_loaded()
    assert reloaded.credential().version == v1
    assert reloaded.credential().ed25519_public == identity.credential().ed25519_public


def test_maybe_rotate_produces_successor_and_promotes(config, session_factory, audit, now=1000):
    identity = ServerIdentity(
        config, session_factory, audit, now_seconds=now
    )
    identity.ensure_loaded()
    # T = 60s: rotation starts 2*fallback(30) before expiration(90s) = 30s
    identity._now_seconds = now + 30
    identity.maybe_rotate()
    assert identity.credential().version == 1  # still active
    announcement = identity.successor_announcement()
    assert announcement is not None
    new_version, ed_pub, x_pub, prev_version, sig = announcement
    assert new_version == 2
    assert prev_version == 1
    assert sig
    # after the validation window (T/2 = 30s) the successor becomes ACTIVE
    identity._now_seconds = now + 60
    identity.maybe_rotate()
    assert identity.credential().version == 2
    assert identity.successor_announcement() is None


def test_successor_signature_verifies_with_old_key(config, session_factory, audit, now=1000):
    from sih_shared.credential_state import encode_successor_payload
    from sih_shared.crypto import verify_ed25519

    identity = ServerIdentity(config, session_factory, audit, now_seconds=now)
    identity.ensure_loaded()
    v1 = identity.credential()
    ed_priv_v1, _ = identity.keys(1)
    identity._now_seconds = now + 30
    identity.maybe_rotate()
    new_version, ed_pub, x_pub, prev_version, sig = identity.successor_announcement()
    payload = encode_successor_payload(
        identity.uuid(), prev_version, new_version, ed_pub, x_pub, b""
    )
    verify_ed25519(v1.ed25519_public, payload, sig)
