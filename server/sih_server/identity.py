"""The server's own rotating application identity.

The server is also a credential holder: it rotates its own Ed25519/X25519
pair on the same schedule as clients, and announces transitions to clients
piggybacked on responses.  Private keys are held in memory and persisted
(plaintext) under ``data_dir`` — the server is the trust root, so its own
keys are not protected by the protocol (spec sections 33, 49).
"""

from __future__ import annotations

import json
import os
import time
import uuid

from sih_shared.config import RotationParams
from sih_shared.credential_state import (
    RotationEngine,
    RotationError,
    encode_successor_payload,
)
from sih_shared.crypto import (
    generate_ed25519_keypair,
    generate_x25519_keypair,
    sign_ed25519,
)
from sih_shared.models import CredentialPublic, CredentialStatus

from . import audit as audit_mod
from .config import ServerConfig
from .database import Credentials


class ServerIdentityError(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class ServerIdentity:
    def __init__(
        self,
        config: ServerConfig,
        session_factory,
        audit: audit_mod.AuditLog,
        now_seconds: float | None = None,
    ) -> None:
        self._config = config
        self._session_factory = session_factory
        self._audit = audit
        self._now_seconds = now_seconds
        self._params = RotationParams(config.rotation_duration)
        self._engine = RotationEngine(self._params)
        self._keys: dict[int, tuple[bytes, bytes]] = {}
        self._key_file = os.path.join(config.data_dir, "server_identity_keys.json")
        self._loaded = False

    # ------------------------------------------------------------------ #

    def _now(self) -> int:
        if callable(self._now_seconds):
            return int(self._now_seconds())
        return int(self._now_seconds if self._now_seconds is not None else time.time())

    def uuid(self) -> uuid.UUID:
        return self._config.server_uuid

    def ensure_loaded(self) -> None:
        if self._loaded:
            return
        with self._session_factory() as session:
            rows = (
                session.query(Credentials)
                .filter(Credentials.identity_uuid == str(self._config.server_uuid))
                .order_by(Credentials.credential_version)
                .all()
            )
        if not rows:
            self._provision()
        else:
            self._engine = RotationEngine.load(
                self._params,
                [
                    CredentialPublic(
                        identity_uuid=uuid.UUID(r.identity_uuid),
                        version=r.credential_version,
                        ed25519_public=bytes(r.signing_public_key),
                        x25519_public=bytes(r.encryption_public_key),
                        status=CredentialStatus(r.status),
                        created_at=r.created_at,
                        validation_deadline=r.validation_deadline,
                        activation_time=r.activation_time,
                        expiration_time=r.expiration_time,
                    )
                    for r in rows
                ],
            )
            self._keys = self._load_keys()
        self._loaded = True

    def _provision(self) -> None:
        now = self._now()
        ed_priv, ed_pub = generate_ed25519_keypair()
        x_priv, x_pub = generate_x25519_keypair()
        self._engine.provision_initial(
            CredentialPublic(
                identity_uuid=self._config.server_uuid,
                version=1,
                ed25519_public=ed_pub,
                x25519_public=x_pub,
                status=CredentialStatus.GENERATED,
            ),
            now,
        )
        self._keys[1] = (ed_priv, x_priv)
        self._persist(now)
        self._audit.record(
            audit_mod.EVENT_ENROLLMENT,
            self._config.server_uuid,
            1,
            source="SERVER",
        )

    def _persist(self, now: int) -> None:
        os.makedirs(self._config.data_dir, exist_ok=True)
        with self._session_factory() as session:
            for cred in self._engine.all():
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
            session.commit()
        self._save_keys()

    def _save_keys(self) -> None:
        payload = {
            str(v): {"ed": e.hex(), "x": x.hex()} for v, (e, x) in self._keys.items()
        }
        tmp = self._key_file + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(payload, f)
        os.replace(tmp, self._key_file)

    def _load_keys(self) -> dict[int, tuple[bytes, bytes]]:
        try:
            with open(self._key_file, encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, json.JSONDecodeError):
            raise ServerIdentityError(
                "KEYS_MISSING",
                "server identity keys file missing; run with an existing database",
            ) from None
        return {
            int(v): (bytes.fromhex(p["ed"]), bytes.fromhex(p["x"]))
            for v, p in data.items()
        }

    # ------------------------------------------------------------------ #
    # accessors
    # ------------------------------------------------------------------ #

    def credential(self) -> CredentialPublic:
        self.ensure_loaded()
        cred = self._engine.active()
        if cred is None:
            raise ServerIdentityError("NO_ACTIVE", "server identity has no active credential")
        return cred

    def keys(self, version: int) -> tuple[bytes, bytes]:
        self.ensure_loaded()
        keys = self._keys.get(version)
        if keys is None:
            raise ServerIdentityError("KEYS_MISSING", f"no private keys for version {version}")
        return keys

    def active_keys(self) -> tuple[bytes, bytes]:
        return self.keys(self.credential().version)

    # ------------------------------------------------------------------ #
    # rotation
    # ------------------------------------------------------------------ #

    def maybe_rotate(self) -> None:
        """Self-rotate when the active credential's window expires.

        Called periodically by the server's rotation tick: generates a
        successor signed by the current credential, then checkpoints it
        once its validation window has passed.
        """
        self.ensure_loaded()
        now = self._now()
        active = self._engine.active()
        if active is None:
            return
        validating = self._engine.validating()
        # begin rotation early enough that promotion at the validation
        # deadline still leaves the demoted credential with full fallback
        # coverage (SR-14): start = expiration - validation - fallback
        rotate_at = (active.expiration_time or now) - 2 * self._params.fallback_period
        if validating is None and now >= rotate_at:
            try:
                self._submit_successor(active, now)
            except RotationError:
                return  # e.g. signer already expired; nothing to promote
            validating = self._engine.validating()
        if validating is not None and now >= (validating.validation_deadline or 0):
            try:
                self._engine.checkpoint(now)
            except RotationError:
                return
            self._persist(now)
            self._audit.record(
                audit_mod.EVENT_CREDENTIAL_PROMOTION,
                self._config.server_uuid,
                validating.version,
            )

    def _submit_successor(self, active: CredentialPublic, now: int) -> None:
        ed_priv, _ = self._keys[active.version]
        ed_priv2, ed_pub2 = generate_ed25519_keypair()
        x_priv2, x_pub2 = generate_x25519_keypair()
        new_version = active.version + 1
        payload = encode_successor_payload(
            self._config.server_uuid,
            active.version,
            new_version,
            ed_pub2,
            x_pub2,
            b"",
        )
        signature = sign_ed25519(ed_priv, payload)
        self._engine.submit_successor(
            CredentialPublic(
                identity_uuid=self._config.server_uuid,
                version=new_version,
                ed25519_public=ed_pub2,
                x25519_public=x_pub2,
                status=CredentialStatus.GENERATED,
            ),
            signature,
            b"",
            now,
        )
        self._keys[new_version] = (ed_priv2, x_priv2)
        self._persist(now)
        self._audit.record(
            audit_mod.EVENT_CREDENTIAL_GENERATION,
            self._config.server_uuid,
            new_version,
        )

    def successor_announcement(self) -> tuple[int, bytes, bytes, int, bytes] | None:
        """Piggyback info for responses: (version, ed25519, x25519, prev, sig).

        Returns None when the identity is stable (no validating successor).
        """
        self.ensure_loaded()
        validating = self._engine.validating()
        if validating is None:
            return None
        prev = self._engine.active()
        if prev is None:
            return None
        payload = encode_successor_payload(
            self._config.server_uuid,
            prev.version,
            validating.version,
            validating.ed25519_public,
            validating.x25519_public,
            b"",
        )
        ed_priv, _ = self._keys[prev.version]
        return (
            validating.version,
            validating.ed25519_public,
            validating.x25519_public,
            prev.version,
            sign_ed25519(ed_priv, payload),
        )

    def rotate_tick(self) -> None:
        self.maybe_rotate()
