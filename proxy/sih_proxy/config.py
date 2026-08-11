"""Proxy configuration.

The proxy terminates the client-facing TLS endpoint (its own endpoint
certificate) and speaks the same framed protocol to the server over a
pinned TLS connection per client (SR-33/SR-37).
"""

from __future__ import annotations

import os
import uuid
from dataclasses import dataclass, field
from pathlib import Path

from sih_shared.config import DEFAULT_ROTATION_DURATION


@dataclass
class ProxyConfig:
    proxy_host: str = "0.0.0.0"
    proxy_port: int = 1443
    cert_file: Path | None = None  # proxy endpoint TLS cert (generated if absent)
    key_file: Path | None = None
    server_host: str = "127.0.0.1"
    server_port: int = 8443
    server_cert_file: Path = field(
        default_factory=lambda: Path(".sih/proxy/server.crt")
    )
    server_uuid: uuid.UUID = field(
        default_factory=lambda: uuid.UUID("00000000-0000-4000-8000-000000000001")
    )
    data_dir: Path = field(default_factory=lambda: Path(".sih/proxy"))
    enrollment_token: str = ""
    rotation_duration: int = DEFAULT_ROTATION_DURATION
    tls_hostname: str = "sih.local"

    @classmethod
    def from_env(cls) -> ProxyConfig:
        cfg = cls()
        if os.environ.get("SIH_PROXY_LISTEN_HOST"):
            cfg.proxy_host = os.environ["SIH_PROXY_LISTEN_HOST"]
        if os.environ.get("SIH_PROXY_LISTEN_PORT"):
            cfg.proxy_port = int(os.environ["SIH_PROXY_LISTEN_PORT"])
        if os.environ.get("SIH_CERT_FILE"):
            cfg.cert_file = Path(os.environ["SIH_CERT_FILE"])
        if os.environ.get("SIH_KEY_FILE"):
            cfg.key_file = Path(os.environ["SIH_KEY_FILE"])
        if os.environ.get("SIH_SERVER_HOST"):
            cfg.server_host = os.environ["SIH_SERVER_HOST"]
        if os.environ.get("SIH_SERVER_PORT"):
            cfg.server_port = int(os.environ["SIH_SERVER_PORT"])
        if os.environ.get("SIH_SERVER_CERT_FILE"):
            cfg.server_cert_file = Path(os.environ["SIH_SERVER_CERT_FILE"])
        if os.environ.get("SIH_SERVER_UUID"):
            cfg.server_uuid = uuid.UUID(os.environ["SIH_SERVER_UUID"])
        if os.environ.get("SIH_DATA_DIR"):
            cfg.data_dir = Path(os.environ["SIH_DATA_DIR"])
        if os.environ.get("SIH_ENROLLMENT_TOKEN"):
            cfg.enrollment_token = os.environ["SIH_ENROLLMENT_TOKEN"]
        if os.environ.get("SIH_ROTATION_DURATION"):
            cfg.rotation_duration = int(os.environ["SIH_ROTATION_DURATION"])
        return cfg

    def default_cert_file(self) -> Path:
        return self.data_dir / "proxy.crt"

    def default_key_file(self) -> Path:
        return self.data_dir / "proxy.key"