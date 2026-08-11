"""Deployment timing parameters for the credential lifecycle.

Time values are unix seconds.  With T = rotation duration:

* validation period  = T/2   (V3 must survive until the promotion checkpoint)
* active period      = T/2   (after promotion, before the next rotation)
* fallback period    = T/2   (after demotion, before termination)

A credential therefore stays usable for ``1.5 * T`` from creation, which
covers VALIDATING (T/2) + ACTIVE (T/2) + FALLBACK (T/2).  This satisfies the
requirement that credential validity >= ACTIVE + FALLBACK lifetime.
"""

from __future__ import annotations

from dataclasses import dataclass

DEFAULT_ROTATION_DURATION = 24 * 3600  # T = 24 hours

CHUNK_SIZE = 64 * 1024  # 64 KiB application-encryption chunks
TIMESTAMP_WINDOW = 300  # +/- 5 minutes replay-acceptance window (seconds)
DEFAULT_REPLAY_CACHE_SIZE = 100_000


@dataclass(frozen=True)
class RotationParams:
    rotation_duration: int = DEFAULT_ROTATION_DURATION

    @property
    def validation_period(self) -> int:
        """T/2: the promotion checkpoint offset from V3 submission."""
        return self.rotation_duration // 2

    @property
    def fallback_period(self) -> int:
        """T/2: the minimum remaining validity required to enter FALLBACK."""
        return self.rotation_duration // 2

    @property
    def total_validity(self) -> int:
        """1.5 * T: full VALIDATING + ACTIVE + FALLBACK lifetime."""
        return (3 * self.rotation_duration) // 2

    def validation_deadline_from(self, created_at: int) -> int:
        return created_at + self.validation_period

    def expiration_from(self, created_at: int) -> int:
        return created_at + self.total_validity
