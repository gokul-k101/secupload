"""Server-authoritative credential rotation state machine.

Implements the three-version rotation window (SRS section 12, 14-21):

* exactly one ACTIVE credential (SR-04)
* one previous FALLBACK credential (SR-05)
* one VALIDATING credential (SR-06)
* promotion only at or after T/2, enforced with the server clock (SR-07/08)
* failed validation -> V3 TERMINATED, V2 stays ACTIVE (SR-09/10)
* successful promotion -> V1 TERMINATED, V2 FALLBACK, V3 ACTIVE (SR-11)
* a credential never enters FALLBACK unless its validity covers the whole
  fallback period (SR-14)

The engine is pure logic: time is injected, and it never touches storage or
sockets.  All credential records are :class:`~sih_shared.models.CredentialPublic`
(public information only; private keys never leave the owner).
"""

from __future__ import annotations

import uuid

from .codec import Decoder, Encoder
from .config import RotationParams
from .crypto import SignatureError, verify_ed25519
from .models import WINDOW_STATUSES, CredentialPublic, CredentialStatus

SUCCESSOR_TAG = b"SIH-SUCC-1"


class RotationError(Exception):
    """Raised when a requested transition is not permitted."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def encode_successor_payload(
    identity_uuid: uuid.UUID,
    old_version: int,
    new_version: int,
    new_ed25519_public: bytes,
    new_x25519_public: bytes,
    transition_metadata: bytes,
) -> bytes:
    """Canonical successor-transition payload (binds identity and keys)."""
    return (
        Encoder()
        .bytes_(SUCCESSOR_TAG)
        .uuid_(identity_uuid)
        .u32(old_version)
        .u32(new_version)
        .bytes_(new_ed25519_public)
        .bytes_(new_x25519_public)
        .bytes_(transition_metadata)
        .finish()
    )


def parse_successor_payload(data: bytes) -> tuple[
    uuid.UUID, int, int, bytes, bytes, bytes
]:
    """Inverse of :func:`encode_successor_payload`.

    Returns (identity_uuid, old_version, new_version, new_ed25519_public,
    new_x25519_public, transition_metadata).
    """
    dec = Decoder(data)
    tag = dec.bytes_()
    if tag != SUCCESSOR_TAG:
        raise RotationError("BAD_TAG", "not a successor payload")
    return (
        dec.uuid_() or uuid.UUID(int=0),
        dec.u32(),
        dec.u32(),
        dec.bytes_(),
        dec.bytes_(),
        dec.bytes_(),
    )


class RotationEngine:
    """State machine over the credential versions of a single identity."""

    def __init__(self, params: RotationParams) -> None:
        self._params = params
        self._creds: dict[int, CredentialPublic] = {}

    @classmethod
    def load(cls, params: RotationParams, creds: list[CredentialPublic]) -> RotationEngine:
        """Reconstruct an engine from persisted public records."""
        engine = cls(params)
        for cred in creds:
            engine._creds[cred.version] = cred
        return engine

    # ------------------------------------------------------------------ #
    # inspection
    # ------------------------------------------------------------------ #

    def get(self, version: int) -> CredentialPublic | None:
        return self._creds.get(version)

    def all(self) -> list[CredentialPublic]:
        return [self._creds[v] for v in sorted(self._creds)]

    def versions_in_window(self) -> int:
        return sum(1 for c in self._creds.values() if c.status in WINDOW_STATUSES)

    def active(self) -> CredentialPublic | None:
        return self._by_status(CredentialStatus.ACTIVE)

    def fallback(self) -> CredentialPublic | None:
        return self._by_status(CredentialStatus.FALLBACK)

    def validating(self) -> CredentialPublic | None:
        return self._by_status(CredentialStatus.VALIDATING)

    def _by_status(self, status: CredentialStatus) -> CredentialPublic | None:
        for c in self._creds.values():
            if c.status == status:
                return c
        return None

    # ------------------------------------------------------------------ #
    # transitions
    # ------------------------------------------------------------------ #

    def provision_initial(self, cred: CredentialPublic, now: int) -> None:
        """Register the first credential as ACTIVE (initial provisioning).

        Also used after recovery: historical records (REVOKED/TERMINATED/
        EXPIRED) may exist, but no credential may be in the rotation window.
        """
        if self._by_status(CredentialStatus.ACTIVE) is not None or self._by_status(
            CredentialStatus.VALIDATING
        ) is not None:
            raise RotationError("ALREADY_PROVISIONED", "identity already provisioned")
        if self._creds and cred.version != max(self._creds) + 1:
            raise RotationError(
                "VERSION_ORDER",
                f"provisioned version must be {max(self._creds) + 1}",
            )
        if cred.status != CredentialStatus.GENERATED:
            raise RotationError("INVALID_STATUS", "initial credential must be GENERATED")
        self._creds[cred.version] = CredentialPublic(
            identity_uuid=cred.identity_uuid,
            version=cred.version,
            ed25519_public=cred.ed25519_public,
            x25519_public=cred.x25519_public,
            status=CredentialStatus.ACTIVE,
            created_at=now,
            validation_deadline=None,
            activation_time=now,
            expiration_time=self._params.expiration_from(now),
        )

    def submit_successor(
        self,
        new_cred: CredentialPublic,
        signature: bytes,
        transition_metadata: bytes,
        now: int,
    ) -> None:
        """Submit a new credential (V3) authorized by the current ACTIVE one.

        The successor signature must be produced by the ACTIVE credential's
        Ed25519 key over the canonical successor payload (SR-26).
        """
        signer = self.active()
        if signer is None:
            raise RotationError("NO_ACTIVE", "no active credential to authorize rotation")
        if self._expired(signer, now):
            raise RotationError("SIGNER_EXPIRED", "active credential is expired")
        if self.validating() is not None:
            raise RotationError("WINDOW_FULL", "a validating credential already exists")
        if new_cred.version != max(self._creds) + 1:
            raise RotationError(
                "VERSION_ORDER",
                f"new version must be sequential (expected {max(self._creds) + 1})",
            )
        if new_cred.identity_uuid != signer.identity_uuid:
            raise RotationError("IDENTITY_MISMATCH", "new credential has a different identity")
        if self.versions_in_window() >= 3:
            raise RotationError("WINDOW_FULL", "three-version window is full (SR-03)")

        payload = encode_successor_payload(
            signer.identity_uuid,
            signer.version,
            new_cred.version,
            new_cred.ed25519_public,
            new_cred.x25519_public,
            transition_metadata,
        )
        try:
            verify_ed25519(signer.ed25519_public, payload, signature)
        except SignatureError as exc:
            raise RotationError("BAD_SUCCESSOR_SIGNATURE", "successor signature invalid") from exc

        self._creds[new_cred.version] = CredentialPublic(
            identity_uuid=new_cred.identity_uuid,
            version=new_cred.version,
            ed25519_public=new_cred.ed25519_public,
            x25519_public=new_cred.x25519_public,
            status=CredentialStatus.VALIDATING,
            created_at=now,
            validation_deadline=self._params.validation_deadline_from(now),
            activation_time=None,
            expiration_time=self._params.expiration_from(now),
        )

    def checkpoint(self, now: int) -> list[CredentialPublic]:
        """Promote the validating credential once T/2 has passed (SR-07/08).

        Returns the credentials whose status changed.
        """
        v3 = self.validating()
        if v3 is None:
            raise RotationError("NO_VALIDATING", "no validating credential")
        if now < (v3.validation_deadline or 0):
            raise RotationError("CHECKPOINT_NOT_REACHED", "promotion checkpoint not reached")
        if self._expired(v3, now):
            self._creds[v3.version] = self._replace(v3, status=CredentialStatus.EXPIRED)
            raise RotationError("V3_EXPIRED", "validating credential expired before promotion")

        v2 = self.active()
        if v2 is None:
            raise RotationError("NO_ACTIVE", "no active credential to demote")
        if self._expired(v2, now):
            raise RotationError(
                "FALLBACK_VALIDITY",
                "active credential cannot cover the fallback period (SR-14)",
            )

        changed: list[CredentialPublic] = []
        v1 = self.fallback()
        if v1 is not None:
            self._creds[v1.version] = self._replace(v1, status=CredentialStatus.TERMINATED)
            changed.append(self._creds[v1.version])
        new_exp = max(v2.expiration_time or 0, now + self._params.fallback_period)
        self._creds[v2.version] = self._replace(
            v2, status=CredentialStatus.FALLBACK, expiration_time=new_exp
        )
        changed.append(self._creds[v2.version])
        self._creds[v3.version] = self._replace(
            v3, status=CredentialStatus.ACTIVE, activation_time=now
        )
        changed.append(self._creds[v3.version])
        return changed

    def rollback(self, now: int) -> CredentialPublic:
        """Terminate the validating credential; V2 remains ACTIVE (SR-10)."""
        v3 = self.validating()
        if v3 is None:
            raise RotationError("NO_VALIDATING", "no validating credential to roll back")
        self._creds[v3.version] = self._replace(v3, status=CredentialStatus.TERMINATED)
        return self._creds[v3.version]

    def revoke(self, version: int, now: int) -> CredentialPublic:
        """Revoke an individual credential (SR-30)."""
        cred = self._creds.get(version)
        if cred is None:
            raise RotationError("UNKNOWN_VERSION", "no such credential version")
        self._creds[version] = self._replace(cred, status=CredentialStatus.REVOKED)
        return self._creds[version]

    def expire_all(self, now: int) -> list[CredentialPublic]:
        """Mark any expired non-terminal credentials as EXPIRED (SR-12)."""
        changed: list[CredentialPublic] = []
        for version, cred in self._creds.items():
            if (
                cred.status in (CredentialStatus.ACTIVE, CredentialStatus.FALLBACK)
                and self._expired(cred, now)
            ):
                self._creds[version] = self._replace(cred, status=CredentialStatus.EXPIRED)
                changed.append(self._creds[version])
        return changed

    # ------------------------------------------------------------------ #
    # authentication lookup
    # ------------------------------------------------------------------ #

    def credential_for_auth(self, version: int, now: int) -> CredentialPublic | None:
        """Return the credential usable to authenticate a message.

        Only ACTIVE/FALLBACK, unexpired credentials are usable.
        """
        cred = self._creds.get(version)
        if cred is None:
            return None
        if cred.status not in (CredentialStatus.ACTIVE, CredentialStatus.FALLBACK):
            return None
        if self._expired(cred, now):
            return None
        return cred

    # ------------------------------------------------------------------ #
    # helpers
    # ------------------------------------------------------------------ #

    def _expired(self, cred: CredentialPublic, now: int) -> bool:
        return cred.expiration_time is not None and now >= cred.expiration_time

    @staticmethod
    def _replace(
        cred: CredentialPublic, **changes: object
    ) -> CredentialPublic:
        return CredentialPublic(
            identity_uuid=cred.identity_uuid,
            version=cred.version,
            ed25519_public=cred.ed25519_public,
            x25519_public=cred.x25519_public,
            status=changes.get("status", cred.status),  # type: ignore[arg-type]
            created_at=cred.created_at,
            validation_deadline=cred.validation_deadline,
            activation_time=changes.get("activation_time", cred.activation_time),  # type: ignore[arg-type]
            expiration_time=changes.get("expiration_time", cred.expiration_time),  # type: ignore[arg-type]
        )
