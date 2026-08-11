"""Server-side authentication of signed envelopes.

Every request must arrive in a :class:`sih_shared.protocol.Envelope` signed
by the sender's ACTIVE (or, during window transition, VALIDATING) Ed25519
key, with a fresh timestamp and no prior replay.
"""

from __future__ import annotations

import time
import uuid

from sih_shared.models import (
    AUTHENTICATING_STATUSES,
    CredentialPublic,
    IdentityKind,
)
from sih_shared.protocol import Envelope, ProtocolError
from sih_shared.replay import ReplayCache, envelope_replay_key, timestamp_ok

from . import audit as audit_mod
from .registry import CredentialRegistry, RegistryError


class AuthError(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class Authenticator:
    def __init__(
        self,
        registry: CredentialRegistry,
        audit: audit_mod.AuditLog,
        now_seconds: float | None = None,
    ) -> None:
        self._registry = registry
        self._audit = audit
        self._replay = ReplayCache()
        self._now_seconds = now_seconds

    def _now(self) -> int:
        if callable(self._now_seconds):
            return int(self._now_seconds())
        return int(self._now_seconds if self._now_seconds is not None else time.time())

    def authenticate(self, envelope: Envelope) -> tuple[IdentityKind, CredentialPublic]:
        """Verify an envelope and return (identity kind, credential)."""
        now = self._now()
        identity_uuid = envelope.sender_uuid
        version = envelope.sender_credential_version

        if not timestamp_ok(envelope.timestamp, now):
            self._audit.record(
                audit_mod.EVENT_AUTH_FAILURE, identity_uuid, version, result="DENY"
            )
            raise AuthError("STALE_TIMESTAMP", "envelope timestamp outside window")

        if not self._replay.check_and_add(
            envelope_replay_key(
                envelope.sender_uuid.bytes, envelope.request_id.bytes, envelope.nonce
            )
        ):
            self._audit.record(
                audit_mod.EVENT_REPLAY_REJECTION,
                identity_uuid,
                version,
                result="DENY",
            )
            raise AuthError("REPLAY", "duplicate envelope detected")

        cred = None
        try:
            cred = self._registry.credential_for_auth(identity_uuid, version, now)
        except RegistryError:
            cred = None
        if cred is None or cred.status not in AUTHENTICATING_STATUSES:
            self._audit.record(
                audit_mod.EVENT_AUTH_FAILURE, identity_uuid, version, result="DENY"
            )
            raise AuthError("BAD_CREDENTIAL", "credential not usable for authentication")

        try:
            envelope.verify(cred.ed25519_public)
        except ProtocolError as exc:
            self._audit.record(
                audit_mod.EVENT_AUTH_FAILURE, identity_uuid, version, result="DENY"
            )
            raise AuthError(
                "BAD_SIGNATURE", "envelope signature verification failed"
            ) from exc

        self._audit.record(
            audit_mod.EVENT_AUTH_SUCCESS, identity_uuid, version, result="OK"
        )
        return self._identity_kind(identity_uuid), cred

    def _identity_kind(self, identity_uuid: uuid.UUID) -> IdentityKind:
        kind = self._registry.identity_kind(identity_uuid)
        if kind is None:
            raise AuthError(
                "UNKNOWN_IDENTITY", "identity is not registered with the server"
            )
        return kind
