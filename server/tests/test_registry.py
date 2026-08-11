"""Credential registry tests against a real (in-memory) database."""

from __future__ import annotations

import uuid

import pytest
from sih_server.registry import RegistryError
from sih_shared.models import CredentialStatus, IdentityKind


def test_enroll_persists_and_activates(registry, audit, now=1000):
    ident, ed, x = enroll(registry, now)
    cred = registry.credential_for_auth(ident, 1, now)
    assert cred is not None
    assert cred.status == CredentialStatus.ACTIVE
    assert cred.ed25519_public == ed
    assert cred.x25519_public == x


def test_enroll_requires_unused_token(registry, audit, now=1000):
    token = registry.issue_token("ENROLL", IdentityKind.CLIENT, 900, None)
    ident, ed, x = enroll(registry, now, token=token)
    with pytest.raises(RegistryError) as exc:
        enroll(registry, now, token=token)
    assert exc.value.code == "TOKEN_USED"


def test_enroll_rejects_expired_token(registry, audit, now=1000):
    token = registry.issue_token("ENROLL", IdentityKind.CLIENT, 900, None, now=now)
    with pytest.raises(RegistryError) as exc:
        enroll(registry, now + 901, token=token)
    assert exc.value.code == "TOKEN_EXPIRED"


def test_enroll_rejects_unknown_token(registry, audit, now=1000):
    with pytest.raises(RegistryError) as exc:
        enroll(registry, now, token="no-such-token")
    assert exc.value.code == "BAD_TOKEN"


def test_enroll_rejects_duplicate_identity(registry, audit, now=1000):
    ident, ed, x = enroll(registry, now)
    token2 = registry.issue_token("ENROLL", IdentityKind.CLIENT, 900, None)
    with pytest.raises(RegistryError) as exc:
        registry.enroll(ident, IdentityKind.CLIENT, token2, 2, ed, x, now=now)
    assert exc.value.code == "ALREADY_ENROLLED"


def test_recovery_revokes_old_and_provisions_next_version(registry, audit, now=1000):
    ident, ed, x = enroll(registry, now)
    # recover with version 2
    token = registry.issue_token(
        "RECOVER", IdentityKind.CLIENT, 900, identity_uuid=ident
    )
    from sih_shared.crypto import generate_ed25519_keypair, generate_x25519_keypair

    ed2, _ = generate_ed25519_keypair()
    x2, _ = generate_x25519_keypair()
    registry.enroll(ident, IdentityKind.CLIENT, token, 2, ed2, x2, now=now)
    assert registry.get_credential(ident, 1).status == CredentialStatus.REVOKED
    assert registry.get_credential(ident, 2).status == CredentialStatus.ACTIVE
    assert registry.credential_for_auth(ident, 1, now) is None
    assert registry.credential_for_auth(ident, 2, now) is not None


def test_recovery_token_must_match_identity(registry, audit, now=1000):
    ident, ed, x = enroll(registry, now)
    other = uuid.uuid4()
    token = registry.issue_token(
        "RECOVER", IdentityKind.CLIENT, 900, identity_uuid=ident
    )
    with pytest.raises(RegistryError) as exc:
        registry.enroll(other, IdentityKind.CLIENT, token, 2, ed, x, now=now)
    assert exc.value.code == "TOKEN_MISMATCH"


def test_submit_successor_then_checkpoint(registry, audit, now=1000):
    ident, ed_priv, x_priv, x_pub = enroll(registry, now, return_keys=True)
    from sih_shared.credential_state import encode_successor_payload
    from sih_shared.crypto import (
        generate_ed25519_keypair,
        generate_x25519_keypair,
        sign_ed25519,
    )

    ed2, ed_pub2 = generate_ed25519_keypair()
    x2, x_pub2 = generate_x25519_keypair()
    payload = encode_successor_payload(ident, 1, 2, ed_pub2, x_pub2, b"")
    sig = sign_ed25519(ed_priv, payload)
    registry.submit_successor(ident, 2, ed_pub2, x_pub2, sig, b"", now)
    assert registry.get_credential(ident, 2).status == CredentialStatus.VALIDATING

    # checkpoint before the validation window closes must fail
    with pytest.raises(RegistryError):
        registry.checkpoint(ident, now + 1)
    # the successor stays in the window
    registry.checkpoint(ident, now + 30)
    assert registry.get_credential(ident, 2).status == CredentialStatus.ACTIVE
    assert registry.get_credential(ident, 1).status == CredentialStatus.FALLBACK


def test_checkpoint_requires_validating(registry, audit, now=1000):
    ident, ed, x = enroll(registry, now)
    with pytest.raises(RegistryError):
        registry.checkpoint(ident, now + 30)


def test_rollback_terminates_validating(registry, audit, now=1000):
    ident, ed_priv, x_priv, x_pub = enroll(registry, now, return_keys=True)
    from sih_shared.credential_state import encode_successor_payload
    from sih_shared.crypto import (
        generate_ed25519_keypair,
        generate_x25519_keypair,
        sign_ed25519,
    )

    ed2, ed_pub2 = generate_ed25519_keypair()
    x2, x_pub2 = generate_x25519_keypair()
    payload = encode_successor_payload(ident, 1, 2, ed_pub2, x_pub2, b"")
    sig = sign_ed25519(ed_priv, payload)
    registry.submit_successor(ident, 2, ed_pub2, x_pub2, sig, b"", now)
    rolled = registry.rollback(ident, now + 5)
    assert rolled.version == 2
    assert rolled.status == CredentialStatus.TERMINATED
    assert registry.get_credential(ident, 2).status == CredentialStatus.TERMINATED
    assert registry.credential_for_auth(ident, 1, now + 5) is not None


def test_submit_successor_rejects_bad_signature(registry, audit, now=1000):
    ident, ed_priv, x_priv, x_pub = enroll(registry, now, return_keys=True)
    from sih_shared.credential_state import encode_successor_payload
    from sih_shared.crypto import (
        generate_ed25519_keypair,
        generate_x25519_keypair,
        sign_ed25519,
    )

    ed2, ed_pub2 = generate_ed25519_keypair()
    x2, x_pub2 = generate_x25519_keypair()
    payload = encode_successor_payload(ident, 1, 2, ed_pub2, x_pub2, b"")
    other_priv, _ = generate_ed25519_keypair()
    bad_sig = sign_ed25519(other_priv, payload)
    with pytest.raises(RegistryError) as exc:
        registry.submit_successor(ident, 2, ed_pub2, x_pub2, bad_sig, b"", now)
    assert exc.value.code == "BAD_SUCCESSOR_SIGNATURE"


def test_expire_all_marks_expired(registry, audit, now=1000):
    ident, ed, x = enroll(registry, now)
    # rotation_duration=60 => total validity 90s
    expired = registry.expire_all(now + 91)
    assert any(i == ident for i, _ in expired)
    assert registry.credential_for_auth(ident, 1, now + 91) is None


def test_identity_kind_detection(registry, audit, now=1000):
    ident, ed, x = enroll(registry, now, kind="CLIENT")
    proxy, ed2, x2 = enroll(registry, now, kind="PROXY")
    assert registry.identity_kind(ident) == IdentityKind.CLIENT
    assert registry.identity_kind(proxy) == IdentityKind.PROXY
    assert registry.identity_kind(uuid.uuid4()) is None


def test_public_entries_only_registered_identities(registry, audit, now=1000):
    ident, ed, x = enroll(registry, now, kind="CLIENT")
    proxy, ed2, x2 = enroll(registry, now, kind="PROXY")
    client_entries = registry.client_entries()
    proxy_entries = registry.proxy_entries()
    assert {e.identity_uuid for e in client_entries} == {ident}
    assert {e.identity_uuid for e in proxy_entries} == {proxy}


# --------------------------------------------------------------------- #


def enroll(registry, now, token=None, kind="CLIENT", return_keys=False):
    from sih_shared.crypto import generate_ed25519_keypair, generate_x25519_keypair
    from sih_shared.models import IdentityKind

    issued = token or registry.issue_token("ENROLL", IdentityKind(kind), 900, None)
    ident = uuid.uuid4()
    ed_priv, ed_pub = generate_ed25519_keypair()
    x_priv, x_pub = generate_x25519_keypair()
    registry.enroll(ident, IdentityKind(kind), issued, 1, ed_pub, x_pub, now=now)
    if return_keys:
        return ident, ed_priv, x_priv, x_pub
    return ident, ed_pub, x_pub
