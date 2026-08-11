"""Core data models shared by client, proxy and server."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from enum import StrEnum


class CredentialStatus(StrEnum):
    GENERATED = "GENERATED"
    VALIDATING = "VALIDATING"
    ACTIVE = "ACTIVE"
    FALLBACK = "FALLBACK"
    EXPIRED = "EXPIRED"
    TERMINATED = "TERMINATED"
    REVOKED = "REVOKED"


class IdentityKind(StrEnum):
    CLIENT = "CLIENT"
    PROXY = "PROXY"
    SERVER = "SERVER"


#: Statuses whose public keys may still be used to authenticate a message.
AUTHENTICATING_STATUSES = frozenset(
    {CredentialStatus.ACTIVE, CredentialStatus.FALLBACK}
)

#: Statuses that count toward the three-version rotation window (SR-03).
WINDOW_STATUSES = frozenset(
    {CredentialStatus.VALIDATING, CredentialStatus.ACTIVE, CredentialStatus.FALLBACK}
)


@dataclass(frozen=True)
class CredentialKeys:
    """Full key material for one credential version (owner side only)."""

    ed25519_private: bytes
    ed25519_public: bytes
    x25519_private: bytes
    x25519_public: bytes


@dataclass(frozen=True)
class CredentialPublic:
    """Public registration record for one credential version (registry side)."""

    identity_uuid: uuid.UUID
    version: int
    ed25519_public: bytes
    x25519_public: bytes
    status: CredentialStatus = CredentialStatus.GENERATED
    created_at: int = 0  # unix seconds
    validation_deadline: int | None = None
    activation_time: int | None = None
    expiration_time: int | None = None


@dataclass(frozen=True)
class Credential:
    """Owner-side credential: public record plus private key material."""

    identity_uuid: uuid.UUID
    version: int
    keys: CredentialKeys
    status: CredentialStatus = CredentialStatus.GENERATED
    created_at: int = 0
    validation_deadline: int | None = None
    activation_time: int | None = None
    expiration_time: int | None = None

    @property
    def public(self) -> CredentialPublic:
        return CredentialPublic(
            identity_uuid=self.identity_uuid,
            version=self.version,
            ed25519_public=self.keys.ed25519_public,
            x25519_public=self.keys.x25519_public,
            status=self.status,
            created_at=self.created_at,
            validation_deadline=self.validation_deadline,
            activation_time=self.activation_time,
            expiration_time=self.expiration_time,
        )


@dataclass(frozen=True)
class ObjectInfo:
    object_uuid: uuid.UUID
    file_type: str = ""
    file_size: int = 0
    metadata: str = ""
    content_integrity: str = ""
    storage_reference: str = ""
