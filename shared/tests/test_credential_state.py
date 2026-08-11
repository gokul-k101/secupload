"""Credential-state tests (spec section 62.1, the 10 required cases)."""

from __future__ import annotations

import uuid

import pytest
from sih_shared.config import RotationParams
from sih_shared.credential_state import (
    RotationEngine,
    RotationError,
    encode_successor_payload,
)
from sih_shared.crypto import generate_ed25519_keypair, generate_x25519_keypair, sign_ed25519
from sih_shared.models import CredentialPublic, CredentialStatus

T = 100  # tiny rotation duration for tests; T/2 = 50
NOW = 1_000_000


def make_credential(
    identity: uuid.UUID, version: int
) -> tuple[CredentialPublic, bytes]:
    """Return (public registration record, matching Ed25519 private key)."""
    ed_priv, ed_pub = generate_ed25519_keypair()
    _, x_pub = generate_x25519_keypair()
    cred = CredentialPublic(
        identity_uuid=identity,
        version=version,
        ed25519_public=ed_pub,
        x25519_public=x_pub,
        status=CredentialStatus.GENERATED,
    )
    return cred, ed_priv


class Identity:
    """A provisioned identity plus its private keys (owner simulation)."""

    def __init__(self) -> None:
        self.identity_uuid = uuid.uuid4()
        self.engine = RotationEngine(RotationParams(rotation_duration=T))
        self.ed_privs: dict[int, bytes] = {}
        v1, ed_priv = make_credential(self.identity_uuid, 1)
        self.engine.provision_initial(v1, NOW)
        self.ed_privs[1] = ed_priv

    def next_version(self) -> int:
        return max(c.version for c in self.engine.all()) + 1

    def submit(self, signer_version: int, now: int) -> int:
        version = self.next_version()
        new, ed_priv = make_credential(self.identity_uuid, version)
        payload = encode_successor_payload(
            self.identity_uuid,
            signer_version,
            version,
            new.ed25519_public,
            new.x25519_public,
            b"test-metadata",
        )
        signature = sign_ed25519(self.ed_privs[signer_version], payload)
        self.engine.submit_successor(new, signature, b"test-metadata", now)
        self.ed_privs[version] = ed_priv
        return version


def test_1_initial_v1_activation() -> None:
    """Initial V1 provisioning -> ACTIVE; exactly one active credential."""
    ident = Identity()
    v1 = ident.engine.get(1)
    assert v1 is not None
    assert v1.status == CredentialStatus.ACTIVE
    assert v1.activation_time == NOW
    assert v1.expiration_time == NOW + (3 * T) // 2
    assert ident.engine.active() is v1
    assert ident.engine.fallback() is None
    assert ident.engine.validating() is None


def test_2_v3_generation() -> None:
    """Submitting a successor -> VALIDATING with a T/2 validation deadline."""
    ident = Identity()
    v2 = ident.submit(1, NOW)
    v2c = ident.engine.get(v2)
    assert v2c is not None
    assert v2c.status == CredentialStatus.VALIDATING
    assert v2c.validation_deadline == NOW + T // 2
    assert v2c.activation_time is None


def test_3_v3_validation() -> None:
    """A successor with a bad signature is rejected (SR-26)."""
    ident = Identity()
    ed_priv, ed_pub = generate_ed25519_keypair()
    _, x_pub = generate_x25519_keypair()
    new = CredentialPublic(
        identity_uuid=ident.identity_uuid,
        version=2,
        ed25519_public=ed_pub,
        x25519_public=x_pub,
        status=CredentialStatus.GENERATED,
    )
    payload = encode_successor_payload(
        ident.identity_uuid, 1, 2, ed_pub, x_pub, b"meta"
    )
    bad_sig = sign_ed25519(ident.ed_privs[1], payload + b"tampered")
    with pytest.raises(RotationError) as exc:
        ident.engine.submit_successor(new, bad_sig, b"meta", NOW)
    assert exc.value.code == "BAD_SUCCESSOR_SIGNATURE"
    assert ident.engine.validating() is None


def test_4_early_promotion_rejection() -> None:
    """Checkpoint before T/2 is rejected (SR-07/08)."""
    ident = Identity()
    ident.submit(1, NOW)
    with pytest.raises(RotationError) as exc:
        ident.engine.checkpoint(NOW + T // 2 - 1)
    assert exc.value.code == "CHECKPOINT_NOT_REACHED"


def test_5_promotion_at_half() -> None:
    """First rotation: promotion succeeds exactly at T/2.

    V1 (ACTIVE) -> FALLBACK, V2 (VALIDATING) -> ACTIVE.
    """
    ident = Identity()
    ident.submit(1, NOW)
    changed = ident.engine.checkpoint(NOW + T // 2)
    assert len(changed) == 2
    assert ident.engine.get(1).status == CredentialStatus.FALLBACK  # type: ignore[union-attr]
    assert ident.engine.get(2).status == CredentialStatus.ACTIVE  # type: ignore[union-attr]


def test_6_successful_v3_promotion() -> None:
    """Full three-version rotation: V1 TERMINATED, V2 FALLBACK, V3 ACTIVE (SR-11)."""
    ident = Identity()
    v2 = ident.submit(1, NOW)
    ident.engine.checkpoint(NOW + T // 2)  # V1 FALLBACK, V2 ACTIVE
    v3 = ident.submit(v2, NOW + T // 2)  # V3 VALIDATING
    changed = ident.engine.checkpoint(NOW + T)  # T/2 after V3 submission
    assert len(changed) == 3
    assert ident.engine.get(1).status == CredentialStatus.TERMINATED  # type: ignore[union-attr]
    assert ident.engine.get(v2).status == CredentialStatus.FALLBACK  # type: ignore[union-attr]
    assert ident.engine.get(v3).status == CredentialStatus.ACTIVE  # type: ignore[union-attr]
    # the promoted credential can authorize the next rotation
    v4 = ident.submit(v3, NOW + T)
    assert ident.engine.get(v4).status == CredentialStatus.VALIDATING  # type: ignore[union-attr]


def test_7_v3_rollback() -> None:
    """Rollback: V3 TERMINATED, V2 stays ACTIVE, V1 stays FALLBACK (SR-10)."""
    ident = Identity()
    ident.submit(1, NOW)
    rolled = ident.engine.rollback(NOW)
    assert rolled.status == CredentialStatus.TERMINATED
    assert ident.engine.validating() is None
    assert ident.engine.active().version == 1  # type: ignore[union-attr]
    # a replacement can subsequently be generated
    ident.submit(1, NOW + 1)
    assert ident.engine.validating() is not None


def test_8_credential_revocation() -> None:
    """Credentials are individually revocable (SR-30)."""
    ident = Identity()
    v2 = ident.submit(1, NOW)
    revoked = ident.engine.revoke(v2, NOW)
    assert revoked.status == CredentialStatus.REVOKED
    assert ident.engine.credential_for_auth(v2, NOW) is None
    with pytest.raises(RotationError):
        ident.engine.revoke(99, NOW)


def test_9_three_version_enforcement() -> None:
    """At most three versions in the window (SR-03)."""
    ident = Identity()
    ident.submit(1, NOW)  # V2 VALIDATING -> window has V1 ACTIVE + V2
    with pytest.raises(RotationError) as exc:
        ident.submit(1, NOW + 1)  # cannot submit while one is validating
    assert exc.value.code == "WINDOW_FULL"


def test_10_invalid_fallback_transition() -> None:
    """Promotion refused when the active credential cannot cover the
    fallback period (SR-14)."""
    ident = Identity()
    ident.submit(1, NOW)
    ident.engine.checkpoint(NOW + T // 2)  # V1 FALLBACK, V2 ACTIVE
    # V2 expires at NOW + 1.5T; submit V3 so late that V2's remaining
    # validity at the checkpoint is below the fallback period (T/2).
    ident.submit(2, NOW + 120)
    with pytest.raises(RotationError) as exc:
        ident.engine.checkpoint(NOW + 170)
    assert exc.value.code == "FALLBACK_VALIDITY"
    # nothing was promoted
    assert ident.engine.active().version == 2  # type: ignore[union-attr]


def test_auth_lookup_requires_active_or_fallback() -> None:
    """Only ACTIVE/FALLBACK, unexpired credentials authenticate (SR-12)."""
    ident = Identity()
    assert ident.engine.credential_for_auth(1, NOW) is not None
    v2 = ident.submit(1, NOW)
    assert ident.engine.credential_for_auth(v2, NOW) is None  # VALIDATING
    ident.engine.checkpoint(NOW + T // 2)
    assert ident.engine.credential_for_auth(1, NOW + T // 2) is not None  # FALLBACK
    assert ident.engine.credential_for_auth(v2, NOW + T // 2) is not None  # ACTIVE
    assert ident.engine.credential_for_auth(1, NOW + 10 * T) is None  # EXPIRED


def test_expiry_of_validating_credential() -> None:
    """A validating credential that expires before promotion is EXPIRED."""
    ident = Identity()
    ident.submit(1, NOW)
    with pytest.raises(RotationError) as exc:
        ident.engine.checkpoint(NOW + 2 * T)
    assert exc.value.code == "V3_EXPIRED"


def test_provisioning_requires_empty_state() -> None:
    ident = Identity()
    with pytest.raises(RotationError) as exc:
        ident.engine.provision_initial(make_credential(ident.identity_uuid, 2)[0], NOW)
    assert exc.value.code == "ALREADY_PROVISIONED"


def test_successor_must_be_sequential() -> None:
    ident = Identity()
    ed_priv, ed_pub = generate_ed25519_keypair()
    _, x_pub = generate_x25519_keypair()
    new = CredentialPublic(
        identity_uuid=ident.identity_uuid,
        version=5,  # skip versions
        ed25519_public=ed_pub,
        x25519_public=x_pub,
        status=CredentialStatus.GENERATED,
    )
    payload = encode_successor_payload(
        ident.identity_uuid, 1, 5, ed_pub, x_pub, b"meta"
    )
    sig = sign_ed25519(ident.ed_privs[1], payload)
    with pytest.raises(RotationError) as exc:
        ident.engine.submit_successor(new, sig, b"meta", NOW)
    assert exc.value.code == "VERSION_ORDER"
