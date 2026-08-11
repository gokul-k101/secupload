"""Thread-safe registry snapshot cache maintained by the proxy.

The proxy refreshes the server's public registry snapshot over the
control channel on each client connection; entries are served from the
cache (no client traffic is parsed — relay is blind).
"""

from __future__ import annotations

import threading
import time
import uuid

from sih_shared.protocol import RegistryEntry


class RegistryCache:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._entries: list[RegistryEntry] = []
        self._synced_at: float = 0.0

    def update(self, entries: list[RegistryEntry]) -> None:
        with self._lock:
            self._entries = list(entries)
            self._synced_at = time.time()

    def snapshot(self) -> list[RegistryEntry]:
        with self._lock:
            return list(self._entries)

    def synced_at(self) -> float:
        with self._lock:
            return self._synced_at

    def entry(self, identity_uuid: uuid.UUID) -> RegistryEntry | None:
        """Newest entry for ``identity_uuid`` (highest version)."""
        with self._lock:
            best: RegistryEntry | None = None
            for e in self._entries:
                if e.identity_uuid == identity_uuid and (
                    best is None or e.version > best.version
                ):
                    best = e
            return best

    def identities(self) -> set[uuid.UUID]:
        with self._lock:
            return {e.identity_uuid for e in self._entries}