"""Server entry point: tunnel2 TLS endpoint + admin HTTP API.

Usage::

    python -m sih_server                     # default config (sqlite, loopback)
    SIH_DATA_DIR=... SIH_DATABASE_URL=... python -m sih_server
"""

from __future__ import annotations

import logging
import os
import threading

import uvicorn
from sih_shared.config import RotationParams
from sih_shared.tls import build_server_context, generate_endpoint_cert, write_pem

from .admin_api import make_default_app
from .audit import AuditLog
from .config import ServerConfig
from .database import make_engine, make_sessionmaker
from .identity import ServerIdentity
from .objects import ObjectStore
from .registry import CredentialRegistry
from .tunnel2 import Tunnel2Server


def _ensure_endpoint_cert(config: ServerConfig) -> None:
    cert_file = config.endpoint_cert_file()
    key_file = config.endpoint_key_file()
    if not (cert_file.exists() and key_file.exists()):
        os.makedirs(config.data_dir, exist_ok=True)
        cert, key = generate_endpoint_cert("sih-server")
        write_pem(cert_file, cert)
        write_pem(key_file, key, private=True)
        print(f"[sih] endpoint certificate written to {cert_file}")


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    config = ServerConfig.from_env()
    _ensure_endpoint_cert(config)

    engine = make_engine(config.database_url)
    session_factory = make_sessionmaker(engine)
    audit = AuditLog(session_factory)
    params = RotationParams(config.rotation_duration)
    registry = CredentialRegistry(session_factory, params, audit)
    identity = ServerIdentity(config, session_factory, audit)
    identity.ensure_loaded()
    objects = ObjectStore(session_factory, str(config.storage_dir), audit)

    ssl_context = build_server_context(
        config.endpoint_cert_file(), config.endpoint_key_file()
    )
    from .auth import Authenticator

    authenticator = Authenticator(registry, audit)
    tunnel = Tunnel2Server(
        config, registry, authenticator, objects, identity, ssl_context
    )
    tunnel.start_tick()
    admin_app = make_default_app(config)

    admin_thread = threading.Thread(
        target=lambda: uvicorn.run(
            admin_app, host=config.admin_host, port=config.admin_port, log_level="warning"
        ),
        daemon=True,
    )
    admin_thread.start()

    cred = identity.credential()
    print(
        f"[sih] tunnel2 listening on {config.tunnel2_host}:{config.tunnel2_port} "
        f"(server identity {cred.version} {cred.status.value})"
    )
    print(f"[sih] admin API on {config.admin_host}:{config.admin_port}")
    try:
        tunnel.serve_forever()
    except KeyboardInterrupt:
        print("\n[sih] shutting down")


if __name__ == "__main__":
    main()
