"""Proxy credential identity.

The proxy holds its own rotating Ed25519/X25519 credential pair, bound
to its enrollment token with the ``b"proxy"`` derivation prefix so the
server derives the same identity UUID from the token.  Materially the
same state machine as the client identity, persisted separately.
"""

from __future__ import annotations

import hashlib
import os
import uuid
from typing import cast

from sih_client.config import ClientConfig
from sih_client.identity import ClientIdentity

from .config import ProxyConfig


class ProxyIdentity(ClientIdentity):
    def __init__(
        self,
        config: ProxyConfig,
        now_seconds: float | None = None,
    ) -> None:
        super().__init__(cast(ClientConfig, config), now_seconds)
        self._file = os.path.join(config.data_dir, "proxy_identity.json")

    def identity_uuid(self) -> uuid.UUID:
        """The identity is bound to the enrollment token (same derivation
        as the server: sha256("proxy" || token), first 16 bytes)."""
        if self._config.enrollment_token:
            digest = hashlib.sha256(
                b"proxy" + self._config.enrollment_token.encode()
            ).hexdigest()[:32]
            return uuid.UUID(hex=digest)
        if self._engine.all():
            return self._engine.all()[0].identity_uuid
        return uuid.uuid4()