"""Client configuration."""

from __future__ import annotations

import os
import uuid
from dataclasses import dataclass, field
from pathlib import Path

from sih_shared.config import DEFAULT_ROTATION_DURATION


@dataclass
class ClientConfig:
    proxy_host: str = "127.0.0.1"
    proxy_port: int = 1443
    server_uuid: uuid.UUID = field(
        default_factory=lambda: uuid.UUID("00000000-0000-4000-8000-000000000001")
    )
    data_dir: Path = field(default_factory=lambda: Path(".sih/client"))
    enrollment_token: str = ""
    rotation_duration: int = DEFAULT_ROTATION_DURATION
    tls_hostname: str = "sih.local"

    @classmethod
    def from_env(cls) -> ClientConfig:
        cfg = cls()
        if os.environ.get("SIH_PROXY_HOST"):
            cfg.proxy_host = os.environ["SIH_PROXY_HOST"]
        if os.environ.get("SIH_PROXY_PORT"):
            cfg.proxy_port = int(os.environ["SIH_PROXY_PORT"])
        if os.environ.get("SIH_SERVER_UUID"):
            cfg.server_uuid = uuid.UUID(os.environ["SIH_SERVER_UUID"])
        if os.environ.get("SIH_DATA_DIR"):
            cfg.data_dir = Path(os.environ["SIH_DATA_DIR"])
        if os.environ.get("SIH_ENROLLMENT_TOKEN"):
            cfg.enrollment_token = os.environ["SIH_ENROLLMENT_TOKEN"]
        if os.environ.get("SIH_ROTATION_DURATION"):
            cfg.rotation_duration = int(os.environ["SIH_ROTATION_DURATION"])
        return cfg

    def proxy_cert_file(self) -> Path:
        return self.data_dir / "proxy.crt"
