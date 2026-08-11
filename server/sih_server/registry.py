"""Server-side credential registry.

Persistence of the RotationEngine state per identity in the ``credentials``
table; enrollment/recovery; authentication-key lookup; registry snapshots
for proxy synchronization.

Private keys are never stored here (spec section 53).
"""

from __future__ import annotations

import hashlib
import secrets
import time
import uuid

from sih_shared.config import RotationParams
from sih_shared.credential_state import RotationEngine, RotationError
from sih_shared.models import (
    CredentialPublic,
    CredentialStatus,
    IdentityKind,
)
from sqlalchemy.orm import Session

from . import audit as audit_mod
from .database import Clients, Credentials, EnrollmentTokens, Proxies


class RegistryError(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class CredentialRegistry:
    def __init__(self, session_factory, params: RotationParams, audit: audit_mod.AuditLog) -> None:
        self._session_factory = session_factory
        self._params = params
        self._audit = audit

    # ------------------------------------------------------------------ #
    # persistence helpers
    # ------------------------------------------------------------------ #

    def _load_engine(self, session: Session, identity_uuid: uuid.UUID) -> RotationEngine | None:
        rows = (
            session.query(Credentials)
            .filter(Credentials.identity_uuid == str(identity_uuid))
            .order_by(Credentials.credential_version)
            .all()
        )
        if not rows:
            return None
        return RotationEngine.load(
            self._params, [self._row_to_public(r) for r in rows]
        )

    @staticmethod
    def _row_to_public(row: Credentials) -> CredentialPublic:
        return CredentialPublic(
            identity_uuid=uuid.UUID(row.identity_uuid),
            version=row.credential_version,
            ed25519_public=bytes(row.signing_public_key),
            x25519_public=bytes(row.encryption_public_key),
            status=CredentialStatus(row.status),
            created_at=row.created_at,
            validation_deadline=row.validation_deadline,
            activation_time=row.activation_time,
            expiration_time=row.expiration_time,
        )

    def _save_public(self, session: Session, cred: CredentialPublic) -> None:
        row = (
            session.query(Credentials)
            .filter(
                Credentials.identity_uuid == str(cred.identity_uuid),
                Credentials.credential_version == cred.version,
            )
            .one_or_none()
        )
        if row is None:
            row = Credentials(
                identity_uuid=str(cred.identity_uuid),
                credential_version=cred.version,
            )
            session.add(row)
        row.signing_public_key = cred.ed25519_public
        row.encryption_public_key = cred.x25519_public
        row.status = cred.status.value
        row.created_at = cred.created_at
        row.validation_deadline = cred.validation_deadline
        row.activation_time = cred.activation_time
        row.expiration_time = cred.expiration_time

    # ------------------------------------------------------------------ #
    # registry API
    # ------------------------------------------------------------------ #

    def engine_for(self, identity_uuid: uuid.UUID) -> RotationEngine:
        with self._session_factory() as session:
            engine = self._load_engine(session, identity_uuid)
        if engine is None:
            raise RegistryError("UNKNOWN_IDENTITY", "no credentials registered for identity")
        return engine

    def get_credential(
        self, identity_uuid: uuid.UUID, version: int
    ) -> CredentialPublic | None:
        with self._session_factory() as session:
            row = (
                session.query(Credentials)
                .filter(
                    Credentials.identity_uuid == str(identity_uuid),
                    Credentials.credential_version == version,
                )
                .one_or_none()
            )
            return self._row_to_public(row) if row else None

    def credential_for_auth(
        self, identity_uuid: uuid.UUID, version: int, now: int
    ) -> CredentialPublic | None:
        """The registry view of :meth:`RotationEngine.credential_for_auth`."""
        engine = self.engine_for(identity_uuid)
        return engine.credential_for_auth(version, now)

    def public_entries(self, kind: IdentityKind) -> list[CredentialPublic]:
        """All registry entries for proxy synchronization."""
        with self._session_factory() as session:
            if kind == IdentityKind.CLIENT:
                uuids = [r[0] for r in session.query(Clients.client_uuid).all()]
            else:
                uuids = [r[0] for r in session.query(Proxies.proxy_uuid).all()]
            if not uuids:
                return []
            rows = (
                session.query(Credentials)
                .filter(Credentials.identity_uuid.in_(uuids))
                .order_by(Credentials.identity_uuid, Credentials.credential_version)
                .all()
            )
        return [self._row_to_public(r) for r in rows]

    def client_entries(self) -> list[CredentialPublic]:
        return self.public_entries(IdentityKind.CLIENT)

    def proxy_entries(self) -> list[CredentialPublic]:
        return self.public_entries(IdentityKind.PROXY)

    # ------------------------------------------------------------------ #
    # transitions (all audited)
    # ------------------------------------------------------------------ #

    def _apply(
        self,
        identity_uuid: uuid.UUID,
        fn,
        allow_unknown: bool = False,
    ) -> list[CredentialPublic]:
        """Run a transition inside a transaction and persist the result."""
        with self._session_factory() as session:
            engine = self._load_engine(session, identity_uuid)
            if engine is None:
                if not allow_unknown:
                    raise RegistryError("UNKNOWN_IDENTITY", "identity not registered")
                engine = RotationEngine(self._params)
            try:
                changed = fn(engine)
            except RotationError as exc:
                raise RegistryError(exc.code, exc.message) from exc
            for cred in engine.all():
                self._save_public(session, cred)
            session.commit()
        return changed

    def enroll(
        self,
        identity_uuid: uuid.UUID,
        kind: IdentityKind,
        token: str,
        version: int,
        ed25519_public: bytes,
        x25519_public: bytes,
        now: int | None = None,
    ) -> CredentialPublic:
        now = now or int(time.time())
        token_hash = self._hash_token(token)
        with self._session_factory() as session:
            row = (
                session.query(EnrollmentTokens)
                .filter(EnrollmentTokens.token_hash == token_hash)
                .one_or_none()
            )
            if row is None:
                raise RegistryError("BAD_TOKEN", "unknown enrollment token")
            if row.used_at is not None:
                raise RegistryError("TOKEN_USED", "token already used")
            if row.expires_at < now:
                raise RegistryError("TOKEN_EXPIRED", "token has expired")
            if row.purpose == "RECOVER" and row.identity_uuid != str(identity_uuid):
                raise RegistryError("TOKEN_MISMATCH", "recovery token not bound to this identity")
            table = Clients if kind == IdentityKind.CLIENT else Proxies
            identity_column = (
                Clients.client_uuid if kind == IdentityKind.CLIENT else Proxies.proxy_uuid
            )
            identity_row = session.query(table).filter(
                identity_column == str(identity_uuid)
            ).one_or_none()
            if row.purpose == "RECOVER" and identity_row is None:
                raise RegistryError("UNKNOWN_IDENTITY", "cannot recover: identity unknown")
            if row.purpose == "ENROLL" and identity_row is not None:
                raise RegistryError("ALREADY_ENROLLED", "identity already enrolled")
            # recovery invalidates unusable credentials first
            engine = self._load_engine(session, identity_uuid)
            if row.purpose == "RECOVER":
                if engine is None:
                    raise RegistryError("UNKNOWN_IDENTITY", "no credentials to recover")
                for cred in engine.all():
                    if cred.status in (CredentialStatus.ACTIVE, CredentialStatus.FALLBACK):
                        engine.revoke(cred.version, now)
                        revoked = engine.get(cred.version)
                        if revoked is None:  # pragma: no cover - revoke() guarantees
                            raise RegistryError("INTERNAL", "revoked credential missing")
                        self._save_public(session, revoked)
            elif engine is not None:
                raise RegistryError("ALREADY_ENROLLED", "identity already enrolled")
            if identity_row is None:
                session.add(
                    table(**{identity_column.name: str(identity_uuid), "status": "ACTIVE"})
                )
            row.used_at = now
            session.commit()

        if row.purpose == "ENROLL" and version != 1:
            raise RegistryError(
                "VERSION_ORDER", "initial enrollment must use credential version 1"
            )
        new_cred = CredentialPublic(
            identity_uuid=identity_uuid,
            version=version,
            ed25519_public=ed25519_public,
            x25519_public=x25519_public,
            status=CredentialStatus.GENERATED,
        )

        def provision(_engine: RotationEngine) -> None:
            _engine.provision_initial(new_cred, now)

        self._apply(identity_uuid, provision, allow_unknown=True)
        result = self.get_credential(identity_uuid, version)
        self._audit.record(
            audit_mod.EVENT_ENROLLMENT
            if row.purpose == "ENROLL"
            else audit_mod.EVENT_RECOVERY,
            identity_uuid,
            version,
            result="OK",
        )
        return result  # type: ignore[return-value]

    def submit_successor(
        self,
        identity_uuid: uuid.UUID,
        new_version: int,
        ed25519_public: bytes,
        x25519_public: bytes,
        signature: bytes,
        transition_metadata: bytes,
        now: int,
    ) -> CredentialPublic:
        new_cred = CredentialPublic(
            identity_uuid=identity_uuid,
            version=new_version,
            ed25519_public=ed25519_public,
            x25519_public=x25519_public,
            status=CredentialStatus.GENERATED,
        )

        def fn(engine: RotationEngine) -> list[CredentialPublic]:
            engine.submit_successor(new_cred, signature, transition_metadata, now)
            return [engine.get(new_version)]  # type: ignore[list-item]

        changed = self._apply(identity_uuid, fn)
        self._audit.record(
            audit_mod.EVENT_CREDENTIAL_GENERATION,
            identity_uuid,
            new_version,
        )
        return changed[0]

    def checkpoint(self, identity_uuid: uuid.UUID, now: int) -> list[CredentialPublic]:
        changed = self._apply(identity_uuid, lambda e: e.checkpoint(now))
        self._audit.record(
            audit_mod.EVENT_CREDENTIAL_PROMOTION, identity_uuid,
            changed[-1].version,
        )
        return changed

    def rollback(self, identity_uuid: uuid.UUID, now: int) -> CredentialPublic:
        rolled = self._apply(identity_uuid, lambda e: [e.rollback(now)])[0]
        self._audit.record(
            audit_mod.EVENT_CREDENTIAL_ROLLBACK, identity_uuid, rolled.version
        )
        return rolled

    def revoke(self, identity_uuid: uuid.UUID, version: int, now: int) -> CredentialPublic:
        revoked = self._apply(identity_uuid, lambda e: [e.revoke(version, now)])[0]
        self._audit.record(
            audit_mod.EVENT_CREDENTIAL_REVOCATION, identity_uuid, version
        )
        return revoked

    def expire_all(self, now: int) -> list[tuple[uuid.UUID, CredentialPublic]]:
        """Mark expired credentials across all identities (SR-12)."""
        with self._session_factory() as session:
            identity_uuids = {uuid.UUID(r.identity_uuid) for r in session.query(Credentials).all()}
        expired: list[tuple[uuid.UUID, CredentialPublic]] = []
        for ident in identity_uuids:
            changed = self._apply(ident, lambda e: e.expire_all(now))
            for cred in changed:
                self._audit.record(
                    audit_mod.EVENT_CREDENTIAL_EXPIRATION, ident, cred.version
                )
                expired.append((ident, cred))
        return expired

    # ------------------------------------------------------------------ #
    # enrollment token management
    # ------------------------------------------------------------------ #

    @staticmethod
    def _hash_token(token: str) -> str:
        return hashlib.sha256(token.encode()).hexdigest()

    def issue_token(
        self,
        purpose: str,
        kind: IdentityKind,
        ttl: int,
        identity_uuid: uuid.UUID | None = None,
        now: int | None = None,
    ) -> str:
        token = secrets.token_urlsafe(32)
        now = now or int(time.time())
        with self._session_factory() as session:
            session.add(
                EnrollmentTokens(
                    token_hash=self._hash_token(token),
                    purpose=purpose,
                    identity_kind=kind.value,
                    identity_uuid=str(identity_uuid) if identity_uuid else None,
                    expires_at=now + ttl,
                )
            )
            session.commit()
        return token

    # ------------------------------------------------------------------ #
    # authorization helpers
    # ------------------------------------------------------------------ #

    def identity_kind(self, identity_uuid: uuid.UUID) -> IdentityKind | None:
        with self._session_factory() as session:
            row = (
                session.query(Clients)
                .filter(Clients.client_uuid == str(identity_uuid))
                .one_or_none()
            )
            if row is not None:
                return IdentityKind.CLIENT
            row = (
                session.query(Proxies)
                .filter(Proxies.proxy_uuid == str(identity_uuid))
                .one_or_none()
            )
            if row is not None:
                return IdentityKind.PROXY
        return None
