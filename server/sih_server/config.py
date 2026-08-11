"""Server configuration."""

from __future__ import annotations

import os
import uuid
from dataclasses import dataclass, field
from pathlib import Path

from sih_shared.config import DEFAULT_ROTATION_DURATION


@dataclass
class ServerConfig:
    database_url: str = "sqlite:///sih_server.db"
    storage_dir: Path = field(default_factory=lambda: Path("object_storage"))
    data_dir: Path = field(default_factory=lambda: Path(".sih/server"))
    server_uuid: uuid.UUID = field(
        default_factory=lambda: uuid.UUID("00000000-0000-4000-8000-000000000001")
    )
    rotation_duration: int = DEFAULT_ROTATION_DURATION
    tunnel2_host: str = "127.0.0.1"
    tunnel2_port: int = 8443
    admin_port: int = 9000
    admin_host: str = "127.0.0.1"
    token_ttl: int = 15 * 60  # enrollment/recovery token lifetime (seconds)
    replay_cache_size: int = 100_000
    #: server rotation tick in seconds; the server rotates its own
    #: application credential on this cadence (T/2 is enforced by the
    #: registry; the tick just triggers the attempt)
    rotation_tick: int = 60

    @classmethod
    def from_env(cls) -> ServerConfig:
        cfg = cls()
        if os.environ.get("SIH_DATABASE_URL"):
            cfg.database_url = os.environ["SIH_DATABASE_URL"]
        if os.environ.get("SIH_STORAGE_DIR"):
            cfg.storage_dir = Path(os.environ["SIH_STORAGE_DIR"])
        if os.environ.get("SIH_DATA_DIR"):
            cfg.data_dir = Path(os.environ["SIH_DATA_DIR"])
        if os.environ.get("SIH_TUNNEL2_HOST"):
            cfg.tunnel2_host = os.environ["SIH_TUNNEL2_HOST"]
        if os.environ.get("SIH_TUNNEL2_PORT"):
            cfg.tunnel2_port = int(os.environ["SIH_TUNNEL2_PORT"])
        if os.environ.get("SIH_ADMIN_PORT"):
            cfg.admin_port = int(os.environ["SIH_ADMIN_PORT"])
        if os.environ.get("SIH_ROTATION_DURATION"):
            cfg.rotation_duration = int(os.environ["SIH_ROTATION_DURATION"])
        if os.environ.get("SIH_TOKEN_TTL"):
            cfg.token_ttl = int(os.environ["SIH_TOKEN_TTL"])
        return cfg

    def endpoint_cert_file(self) -> Path:
        return self.data_dir / "endpoint.crt"

    def endpoint_key_file(self) -> Path:
        return self.data_dir / "endpoint.key"

    def credentials_file(self) -> Path:
        return self.data_dir / "server_credentials.json"

    def identity_file(self) -> Path:
        return self.data_dir / "identity.json"
