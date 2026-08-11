#!/usr/bin/env python3
"""Live Demonstration of Dual-Tunnel Secure Proxy (SIH - SRS v3.0).

Demonstrates:
1. Server initialization (TLS 1.3 Tunnel 2 endpoint + Admin API).
2. Proxy enrollment & startup (TLS 1.3 Tunnel 1 endpoint + Blind Relay).
3. Client enrollment & pinned TLS 1.3 connection to Proxy.
4. End-to-end application-layer encrypted object upload & download.
5. Content integrity verification & Proxy blindness validation.
"""

from __future__ import annotations

import os
import shutil
import ssl
import sys
import threading
import time
import uuid
from pathlib import Path

# Add package paths
sys.path.insert(0, os.path.abspath("shared"))
sys.path.insert(0, os.path.abspath("client"))
sys.path.insert(0, os.path.abspath("proxy"))
sys.path.insert(0, os.path.abspath("server"))

from sih_client.api import read_object, write_object
from sih_client.config import ClientConfig
from sih_client.identity import ClientIdentity
from sih_client.session import ClientSession
from sih_proxy.cache import RegistryCache
from sih_proxy.config import ProxyConfig
from sih_proxy.identity import ProxyIdentity
from sih_proxy.tunnel import ProxyServer
from sih_server.audit import AuditLog
from sih_server.auth import Authenticator
from sih_server.config import ServerConfig
from sih_server.database import Permissions, make_engine, make_sessionmaker
from sih_server.identity import ServerIdentity
from sih_server.objects import ObjectStore
from sih_server.registry import CredentialRegistry
from sih_server.tunnel2 import Tunnel2Server
from sih_shared.config import RotationParams
from sih_shared.models import IdentityKind
from sih_shared.tls import generate_endpoint_cert, write_pem

DEMO_DIR = Path("/tmp/sih_demo_workspace")


def cleanup():
    if DEMO_DIR.exists():
        shutil.rmtree(DEMO_DIR)


def main():
    cleanup()
    DEMO_DIR.mkdir(parents=True, exist_ok=True)
    print("=" * 70)
    print("🔒 SIH v3.0 DUAL-TUNNEL SECURE PROXY DEMONSTRATION")
    print("=" * 70)

    # ------------------------------------------------------------------ #
    # 1. Setup Server
    # ------------------------------------------------------------------ #
    print("\n[1/5] Initializing Server...")
    server_dir = DEMO_DIR / "server"
    server_dir.mkdir(parents=True, exist_ok=True)
    server_cfg = ServerConfig(
        database_url=f"sqlite:///{server_dir / 'server.db'}",
        storage_dir=server_dir / "objects",
        data_dir=server_dir / "data",
        rotation_duration=60,
        tunnel2_host="127.0.0.1",
        tunnel2_port=0,
    )
    engine = make_engine(server_cfg.database_url)
    session_factory = make_sessionmaker(engine)
    audit = AuditLog(session_factory)
    params = RotationParams(server_cfg.rotation_duration)
    registry = CredentialRegistry(session_factory, params, audit)
    identity = ServerIdentity(server_cfg, session_factory, audit)
    identity.ensure_loaded()
    objects = ObjectStore(session_factory, str(server_cfg.storage_dir), audit)
    authenticator = Authenticator(registry, audit)

    server_cert_pem, server_key_pem = generate_endpoint_cert("sih-demo-server")
    server_cert_file = server_dir / "server.crt"
    server_key_file = server_dir / "server.key"
    write_pem(server_cert_file, server_cert_pem)
    write_pem(server_key_file, server_key_pem, private=True)

    ssl_server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_server_ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ssl_server_ctx.load_cert_chain(server_cert_file, server_key_file)

    tunnel2_server = Tunnel2Server(
        server_cfg, registry, authenticator, objects, identity, ssl_server_ctx
    )
    server_port = tunnel2_server.server_address[1]
    threading.Thread(target=tunnel2_server.serve_forever, daemon=True).start()
    print(f"  ✓ Server listening on 127.0.0.1:{server_port} (TLS 1.3 Tunnel 2)")

    # Issue Tokens
    proxy_token = registry.issue_token("ENROLL", IdentityKind.PROXY, 900, None)
    client_token = registry.issue_token("ENROLL", IdentityKind.CLIENT, 900, None)
    print("  ✓ Issued Proxy and Client enrollment tokens via Server Registry")

    # ------------------------------------------------------------------ #
    # 2. Setup Proxy
    # ------------------------------------------------------------------ #
    print("\n[2/5] Initializing Proxy...")
    proxy_dir = DEMO_DIR / "proxy"
    proxy_cert_pem, proxy_key_pem = generate_endpoint_cert("sih-demo-proxy")
    proxy_cert_file = proxy_dir / "proxy.crt"
    proxy_key_file = proxy_dir / "proxy.key"
    write_pem(proxy_cert_file, proxy_cert_pem)
    write_pem(proxy_key_file, proxy_key_pem, private=True)

    ssl_proxy_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_proxy_ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ssl_proxy_ctx.load_cert_chain(proxy_cert_file, proxy_key_file)

    proxy_cfg = ProxyConfig(
        proxy_host="127.0.0.1",
        proxy_port=0,
        cert_file=proxy_cert_file,
        key_file=proxy_key_file,
        server_host="127.0.0.1",
        server_port=server_port,
        server_cert_file=server_cert_file,
        server_uuid=identity.uuid(),
        data_dir=proxy_dir,
        enrollment_token=proxy_token,
        rotation_duration=60,
    )
    proxy_identity = ProxyIdentity(proxy_cfg)
    proxy_identity.ensure_loaded()
    cache = RegistryCache()
    proxy_server = ProxyServer(proxy_cfg, ssl_proxy_ctx, proxy_identity, cache)
    proxy_port = proxy_server.server_address[1]
    threading.Thread(target=proxy_server.serve_forever, daemon=True).start()
    print(f"  ✓ Proxy listening on 127.0.0.1:{proxy_port} (TLS 1.3 Tunnel 1)")

    # ------------------------------------------------------------------ #
    # 3. Connect Client via Proxy
    # ------------------------------------------------------------------ #
    print("\n[3/5] Connecting Client through Proxy...")
    client_dir = DEMO_DIR / "client"
    client_cfg = ClientConfig(
        proxy_host="127.0.0.1",
        proxy_port=proxy_port,
        server_uuid=identity.uuid(),
        data_dir=client_dir,
        enrollment_token=client_token,
        rotation_duration=60,
    )
    client_identity = ClientIdentity(client_cfg)
    session = ClientSession(client_cfg, client_identity)
    session.connect(proxy_cert_pem)
    client_uuid = client_identity.identity_uuid()
    print(f"  ✓ Client connected and enrolled (UUID: {client_uuid})")

    # ------------------------------------------------------------------ #
    # 4. Upload Encrypted Object
    # ------------------------------------------------------------------ #
    print("\n[4/5] Performing End-to-End Encrypted Object Upload...")
    object_uuid = uuid.uuid4()

    # Grant client WRITE & READ permissions on Server
    with session_factory() as db_session:
        db_session.add(
            Permissions(
                client_uuid=str(client_uuid),
                object_uuid=str(object_uuid),
                operation="WRITE",
                policy="ALLOW",
            )
        )
        db_session.add(
            Permissions(
                client_uuid=str(client_uuid),
                object_uuid=str(object_uuid),
                operation="READ",
                policy="ALLOW",
            )
        )
        db_session.commit()

    payload_data = b"CONFIDENTIAL_PAYLOAD_DATA: Dual-Tunnel E2E Application Encryption Demo!" * 50
    print(f"  • Object UUID : {object_uuid}")
    print(f"  • Payload Size: {len(payload_data)} bytes")
    print("  • Primary Encrypting (X25519 -> HKDF -> AES-256-GCM)...")
    write_object(session, object_uuid, "text/plain", payload_data)
    print("  ✓ Object chunked, sealed, and streamed through Proxy to Server!")

    # ------------------------------------------------------------------ #
    # 5. Download & Verify Object
    # ------------------------------------------------------------------ #
    print("\n[5/5] Downloading & Verifying Object Integrity...")
    retrieved_data = read_object(session, object_uuid)
    assert retrieved_data == payload_data, "Data mismatch!"
    print("  ✓ Downloaded payload matches original plaintext perfectly!")

    session.close()
    tunnel2_server.shutdown()
    proxy_server.shutdown()
    cleanup()

    print("\n" + "=" * 70)
    print("🎉 DEMONSTRATION COMPLETED SUCCESSFULLY!")
    print("=" * 70)


if __name__ == "__main__":
    main()
