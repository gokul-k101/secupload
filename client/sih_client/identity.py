"""Client credential identity: keys, enrollment, recovery, rotation.

The client's own keypairs (Ed25519 + X25519) are generated locally and
persisted under ``data_dir``; the public halves are enrolled with the
server through the proxy using a one-time token (spec section 51).  The
credential state machine mirrors the server's registry view.
"""

from __future__ import annotations

import json
import os
import time
import uuid

from sih_shared.config import RotationParams
from sih_shared.credential_state import RotationEngine
from sih_shared.crypto import (
    generate_ed25519_keypair,
    generate_x25519_keypair,
)
from sih_shared.models import CredentialPublic, CredentialStatus

from .config import ClientConfig


class ClientIdentityError(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class ClientIdentity:
    def __init__(
        self,
        config: ClientConfig,
        now_seconds: float | None = None,
    ) -> None:
        self._config = config
        self._now_seconds = now_seconds
        self._params = RotationParams(config.rotation_duration)
        self._engine = RotationEngine(self._params)
        self._keys: dict[int, tuple[bytes, bytes]] = {}
        self._file = os.path.join(config.data_dir, "client_identity.json")
        self._enrolled = False

    def _now(self) -> int:
        if callable(self._now_seconds):
            return int(self._now_seconds())
        return int(self._now_seconds if self._now_seconds is not None else time.time())

    # ------------------------------------------------------------------ #

    def ensure_loaded(self) -> None:
        if os.path.exists(self._file):
            self._load()
        else:
            self._fresh()

    def identity_uuid(self) -> uuid.UUID:
        """The identity is bound to the enrollment token (same derivation
        as the server: sha256("client" || token), first 16 bytes)."""
        import hashlib

        if self._config.enrollment_token:
            digest = hashlib.sha256(
                b"client" + self._config.enrollment_token.encode()
            ).hexdigest()[:32]
            return uuid.UUID(hex=digest)
        if self._engine.all():
            return self._engine.all()[0].identity_uuid
        return uuid.uuid4()

    def _fresh(self) -> None:
        os.makedirs(self._config.data_dir, exist_ok=True)
        now = self._now()
        ed_priv, ed_pub = generate_ed25519_keypair()
        x_priv, x_pub = generate_x25519_keypair()
        self._engine.provision_initial(
            CredentialPublic(
                identity_uuid=self.identity_uuid(),
                version=1,
                ed25519_public=ed_pub,
                x25519_public=x_pub,
                status=CredentialStatus.GENERATED,
            ),
            now,
        )
        self._keys[1] = (ed_priv, x_priv)
        self._save()

    def _load(self) -> None:
        try:
            with open(self._file, encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, json.JSONDecodeError) as exc:
            raise ClientIdentityError(
                "CORRUPT_IDENTITY", "client identity file is unreadable"
            ) from exc
        self._engine = RotationEngine.load(
            self._params,
            [
                CredentialPublic(
                    identity_uuid=uuid.UUID(data["identity_uuid"]),
                    version=int(v),
                    ed25519_public=bytes.fromhex(rec["ed_pub"]),
                    x25519_public=bytes.fromhex(rec["x_pub"]),
                    status=CredentialStatus(rec["status"]),
                    created_at=rec["created_at"],
                    validation_deadline=rec.get("validation_deadline"),
                    activation_time=rec.get("activation_time"),
                    expiration_time=rec.get("expiration_time"),
                )
                for v, rec in sorted(data["credentials"].items())
            ],
        )
        self._keys = {
            int(v): (bytes.fromhex(p["ed"]), bytes.fromhex(p["x"]))
            for v, p in data["keys"].items()
        }
        if not self._keys:
            raise ClientIdentityError(
                "KEYS_MISSING", "client identity has no private keys"
            )
        self._enrolled = data.get("enrolled", False)

    def _save(self) -> None:
        creds = {}
        for cred in self._engine.all():
            creds[str(cred.version)] = {
                "ed_pub": cred.ed25519_public.hex(),
                "x_pub": cred.x25519_public.hex(),
                "status": cred.status.value,
                "created_at": cred.created_at,
                "validation_deadline": cred.validation_deadline,
                "activation_time": cred.activation_time,
                "expiration_time": cred.expiration_time,
            }
        data = {
            "identity_uuid": str(
                self._engine.all()[0].identity_uuid if self._engine.all() else uuid.UUID(int=0)
            ),
            "credentials": creds,
            "keys": {
                str(v): {"ed": e.hex(), "x": x.hex()}
                for v, (e, x) in self._keys.items()
            },
            "enrolled": self._enrolled,
        }
        os.makedirs(self._config.data_dir, exist_ok=True)
        tmp = self._file + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f)
        os.replace(tmp, self._file)

    # ------------------------------------------------------------------ #

    def current(self) -> CredentialPublic:
        cred = self._engine.active()
        if cred is None:
            raise ClientIdentityError("NO_ACTIVE", "no active credential")
        return cred

    def keys(self, version: int) -> tuple[bytes, bytes]:
        keys = self._keys.get(version)
        if keys is None:
            raise ClientIdentityError(
                "KEYS_MISSING", f"no private keys for version {version}"
            )
        return keys

    def current_keys(self) -> tuple[bytes, bytes]:
        return self.keys(self.current().version)

    def mark_enrolled(self) -> None:
        self._enrolled = True
        self._save()

    # ------------------------------------------------------------------ #
    # rotation (state machine only; transport is handled by the session)
    # ------------------------------------------------------------------ #

    def generate_successor(self) -> tuple[CredentialPublic, bytes, bytes]:
        """Create the next credential; returns (cred, signature, payload).

        The successor is signed by the current ACTIVE credential and must
        be submitted to the server, which validates and persists it.
        """
        from sih_shared.credential_state import encode_successor_payload
        from sih_shared.crypto import sign_ed25519

        active = self.current()
        now = self._now()
        ed_priv, _ = self._keys[active.version]
        ed_priv2, ed_pub2 = generate_ed25519_keypair()
        x_priv2, x_pub2 = generate_x25519_keypair()
        new_version = active.version + 1
        new_cred = CredentialPublic(
            identity_uuid=active.identity_uuid,
            version=new_version,
            ed25519_public=ed_pub2,
            x25519_public=x_pub2,
            status=CredentialStatus.GENERATED,
        )
        payload = encode_successor_payload(
            active.identity_uuid,
            active.version,
            new_version,
            ed_pub2,
            x_pub2,
            b"",
        )
        signature = sign_ed25519(ed_priv, payload)
        self._engine.submit_successor(new_cred, signature, b"", now)
        self._keys[new_version] = (ed_priv2, x_priv2)
        self._save()
        return new_cred, signature, payload

    def checkpoint(self) -> None:
        """Promote the validating credential; a no-op before the window
        closes (the scheduler retries; the server enforces the same rule)."""
        from sih_shared.credential_state import RotationError

        validating = self._engine.validating()
        if validating is None:
            return
        try:
            self._engine.checkpoint(self._now())
        except RotationError:
            return
        self._save()

    def rollback(self) -> None:
        """Terminate the validating credential (server refused it)."""
        self._engine.rollback(self._now())
        self._save()

    def should_rotate(self) -> bool:
        """True when the active credential's rotation point has passed.

        Rotation starts at expiration - 2*fallback so promotion at the
        validation deadline leaves the demoted credential with a full
        fallback period (SR-14).
        """
        active = self.current()
        now = self._now()
        return now >= (active.expiration_time or now) - 2 * self._params.fallback_period
