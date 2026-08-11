"""SRS v3.0 dual-tunnel secure proxy.

The proxy terminates the client-side TLS (clients pin the proxy endpoint
certificate), maintains a pinned TLS connection to the server per client,
relays frames blindly, and keeps a cached registry snapshot refreshed
over the control channel.
"""

from .cache import RegistryCache
from .config import ProxyConfig
from .identity import ProxyIdentity
from .tunnel import ProxyServer, ProxyTunnel

__all__ = [
    "ProxyConfig",
    "ProxyIdentity",
    "ProxyServer",
    "ProxyTunnel",
    "RegistryCache",
]