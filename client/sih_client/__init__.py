"""Client library: enrollment, signed+encrypted requests, rotation.

The client holds its own Ed25519/X25519 keypairs, enrolls with the server
through the proxy using a one-time token, and sends all application traffic
through the proxy as primary-encrypted envelopes (spec sections 31-37, 51).
"""

from __future__ import annotations
