"""Replay protection: timestamp window plus a bounded LRU nonce cache.

Per spec section 38: each authenticated message carries a timestamp and
nonce; the receiver rejects expired timestamps and previously accepted
nonces.  Rejections are audit events.
"""

from __future__ import annotations

from collections import OrderedDict

from .config import TIMESTAMP_WINDOW


class ReplayCache:
    """Bounded LRU cache of recently accepted message nonce keys."""

    def __init__(self, max_entries: int = 100_000) -> None:
        if max_entries <= 0:
            raise ValueError("max_entries must be positive")
        self._max = max_entries
        self._entries: OrderedDict[bytes, None] = OrderedDict()

    def check_and_add(self, key: bytes) -> bool:
        """Return True if ``key`` is new; False if it is a replay."""
        if key in self._entries:
            self._entries.move_to_end(key)
            return False
        self._entries[key] = None
        if len(self._entries) > self._max:
            self._entries.popitem(last=False)
        return True

    def __len__(self) -> int:
        return len(self._entries)


def timestamp_ok(timestamp: int, now: int, window: int = TIMESTAMP_WINDOW) -> bool:
    """Accept a message timestamp only within +/- ``window`` seconds."""
    return abs(now - timestamp) <= window


def envelope_replay_key(
    sender_uuid: bytes, request_id: bytes, nonce: bytes
) -> bytes:
    """Canonical key for the replay cache, derived from message fields."""
    return sender_uuid + nonce
