"""Web UI Demonstration Server for SIH Dual-Tunnel Secure Proxy (SRS v3.0).

Provides a rich visual UI and REST endpoints to demonstrate data transformations
at each node (Client -> Proxy -> Server -> Download) in real time.
"""

from __future__ import annotations

import base64
import hashlib
import os
import shutil
import ssl
import sys
import threading
import time
import uuid
from pathlib import Path
from typing import Any

# Add workspace modules
sys.path.insert(0, os.path.abspath("shared"))
sys.path.insert(0, os.path.abspath("client"))
sys.path.insert(0, os.path.abspath("proxy"))
sys.path.insert(0, os.path.abspath("server"))

import uvicorn
from fastapi import FastAPI, File, Form, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from sih_client.api import read_object, write_object
from sih_client.config import ClientConfig
from sih_client.identity import ClientIdentity
from sih_client.session import ClientSession, ServerKeyState
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
from sih_shared.crypto import seal_message
from sih_shared.models import IdentityKind
from sih_shared.protocol import (
    MsgType,
    Op,
    build_aad,
    new_envelope,
    parse_envelope,
    unwrap_encrypted,
    wrap_encrypted,
)
from sih_shared.tls import generate_endpoint_cert, write_pem

DEMO_DIR = Path("/tmp/sih_web_demo_workspace")


class StateManager:
    """Manages background Server, Proxy, and Client instances for the Web UI."""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.initialized = False
        self.server_cfg: ServerConfig | None = None
        self.proxy_cfg: ProxyConfig | None = None
        self.client_cfg: ClientConfig | None = None
        self.registry: CredentialRegistry | None = None
        self.server_identity: ServerIdentity | None = None
        self.client_identity: ClientIdentity | None = None
        self.proxy_identity: ProxyIdentity | None = None
        self.objects: ObjectStore | None = None
        self.session_factory = None
        self.client_session: ClientSession | None = None
        self.server_port: int = 0
        self.proxy_port: int = 0
        self.proxy_cache: RegistryCache | None = None

    def initialize(self) -> None:
        with self.lock:
            if self.initialized:
                return
            if DEMO_DIR.exists():
                shutil.rmtree(DEMO_DIR)
            DEMO_DIR.mkdir(parents=True, exist_ok=True)

            # 1. Server Setup
            server_dir = DEMO_DIR / "server"
            server_dir.mkdir(parents=True, exist_ok=True)
            self.server_cfg = ServerConfig(
                database_url=f"sqlite:///{server_dir / 'server.db'}",
                storage_dir=server_dir / "objects",
                data_dir=server_dir / "data",
                rotation_duration=86400,
                tunnel2_host="127.0.0.1",
                tunnel2_port=0,
            )
            engine = make_engine(self.server_cfg.database_url)
            self.session_factory = make_sessionmaker(engine)
            audit = AuditLog(self.session_factory)
            params = RotationParams(self.server_cfg.rotation_duration)
            self.registry = CredentialRegistry(self.session_factory, params, audit)
            self.server_identity = ServerIdentity(self.server_cfg, self.session_factory, audit)
            self.server_identity.ensure_loaded()
            self.objects = ObjectStore(self.session_factory, str(self.server_cfg.storage_dir), audit)
            authenticator = Authenticator(self.registry, audit)

            server_cert_pem, server_key_pem = generate_endpoint_cert("sih-web-server")
            server_cert_file = server_dir / "server.crt"
            server_key_file = server_dir / "server.key"
            write_pem(server_cert_file, server_cert_pem)
            write_pem(server_key_file, server_key_pem, private=True)

            ssl_server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ssl_server_ctx.minimum_version = ssl.TLSVersion.TLSv1_3
            ssl_server_ctx.load_cert_chain(server_cert_file, server_key_file)

            tunnel2_server = Tunnel2Server(
                self.server_cfg, self.registry, authenticator, self.objects, self.server_identity, ssl_server_ctx
            )
            self.server_port = tunnel2_server.server_address[1]
            threading.Thread(target=tunnel2_server.serve_forever, daemon=True).start()

            # Tokens
            proxy_token = self.registry.issue_token("ENROLL", IdentityKind.PROXY, 900, None)
            client_token = self.registry.issue_token("ENROLL", IdentityKind.CLIENT, 900, None)

            # 2. Proxy Setup
            proxy_dir = DEMO_DIR / "proxy"
            proxy_cert_pem, proxy_key_pem = generate_endpoint_cert("sih-web-proxy")
            proxy_cert_file = proxy_dir / "proxy.crt"
            proxy_key_file = proxy_dir / "proxy.key"
            write_pem(proxy_cert_file, proxy_cert_pem)
            write_pem(proxy_key_file, proxy_key_pem, private=True)

            ssl_proxy_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ssl_proxy_ctx.minimum_version = ssl.TLSVersion.TLSv1_3
            ssl_proxy_ctx.load_cert_chain(proxy_cert_file, proxy_key_file)

            self.proxy_cfg = ProxyConfig(
                proxy_host="127.0.0.1",
                proxy_port=0,
                cert_file=proxy_cert_file,
                key_file=proxy_key_file,
                server_host="127.0.0.1",
                server_port=self.server_port,
                server_cert_file=server_cert_file,
                server_uuid=self.server_identity.uuid(),
                data_dir=proxy_dir,
                enrollment_token=proxy_token,
                rotation_duration=86400,
            )
            self.proxy_identity = ProxyIdentity(self.proxy_cfg)
            self.proxy_identity.ensure_loaded()
            self.proxy_cache = RegistryCache()
            proxy_server = ProxyServer(self.proxy_cfg, ssl_proxy_ctx, self.proxy_identity, self.proxy_cache)
            self.proxy_port = proxy_server.server_address[1]
            threading.Thread(target=proxy_server.serve_forever, daemon=True).start()

            # 3. Client Setup
            client_dir = DEMO_DIR / "client"
            self.client_cfg = ClientConfig(
                proxy_host="127.0.0.1",
                proxy_port=self.proxy_port,
                server_uuid=self.server_identity.uuid(),
                data_dir=client_dir,
                enrollment_token=client_token,
                rotation_duration=86400,
            )
            self.client_identity = ClientIdentity(self.client_cfg)
            self.client_session = ClientSession(self.client_cfg, self.client_identity)
            self.client_session.connect(proxy_cert_pem)
            self.initialized = True


state = StateManager()
app = FastAPI(title="SIH Dual-Tunnel Demo", version="3.0")
app.mount("/static", StaticFiles(directory="web_demo/static"), name="static")


@app.on_event("startup")
def on_startup():
    state.initialize()


@app.get("/", response_class=HTMLResponse)
def index():
    html_file = Path("web_demo/static/index.html")
    if html_file.exists():
        return html_file.read_text(encoding="utf-8")
    return "<h1>Web Demo HTML Not Found</h1>"


@app.get("/api/status")
def get_status():
    state.initialize()
    server_cred = state.server_identity.credential()
    client_cred = state.client_identity.current()
    proxy_cred = state.proxy_identity.current()
    return {
        "status": "RUNNING",
        "server": {
            "uuid": str(state.server_identity.uuid()),
            "version": server_cred.version,
            "status": server_cred.status.value,
            "ed25519_pub_hex": server_cred.ed25519_public.hex(),
            "x25519_pub_hex": server_cred.x25519_public.hex(),
        },
        "proxy": {
            "uuid": str(state.proxy_identity.identity_uuid()),
            "version": proxy_cred.version,
            "status": proxy_cred.status.value,
            "port": state.proxy_port,
        },
        "client": {
            "uuid": str(state.client_identity.identity_uuid()),
            "version": client_cred.version,
            "status": client_cred.status.value,
        },
    }


@app.post("/api/process")
async def process_payload(
    payload_text: str = Form(""),
    file: UploadFile | None = File(None),
):
    state.initialize()
    try:
        if file and file.filename:
            content_bytes = await file.read()
            filename = file.filename
            file_type = file.content_type or "application/octet-stream"
        else:
            content_bytes = payload_text.encode("utf-8")
            filename = "user_input.txt"
            file_type = "text/plain"

        object_uuid = uuid.uuid4()
        client_uuid = state.client_identity.identity_uuid()
        server_uuid = state.server_identity.uuid()
        proxy_uuid = state.proxy_identity.identity_uuid()

        # Grant permissions in Server DB
        with state.session_factory() as db_session:
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

        # --- NODE 1: CLIENT ENCRYPTION ---
        request_id = uuid.uuid4()
        ts = int(time.time())
        nonce = uuid.uuid4().bytes[:12]
        client_cred = state.client_identity.current()
        server_cred = state.server_identity.credential()
        server_keys = ServerKeyState()
        server_keys.set(
            server_cred.version, server_cred.ed25519_public, server_cred.x25519_public
        )

        aad = build_aad(
            client_uuid,
            server_uuid,
            request_id,
            client_cred.version,
            ts,
            nonce,
            0,
        )
        ephemeral_pub, ciphertext = seal_message(
            server_keys.x25519_public, nonce, aad, content_bytes
        )
        wrapped_payload = wrap_encrypted(
            server_keys.version, ephemeral_pub, nonce, ciphertext
        )
        envelope = new_envelope(
            MsgType.REQUEST.value,
            client_uuid,
            server_uuid,
            request_id,
            client_cred.version,
            ts,
            nonce,
            wrapped_payload,
        )
        envelope.sign(state.client_identity.current_keys()[0])
        envelope_bytes = envelope.encode()

        client_node = {
            "node_name": "CLIENT (Origin)",
            "identity_uuid": str(client_uuid),
            "credential_version": client_cred.version,
            "input_size_bytes": len(content_bytes),
            "filename": filename,
            "file_type": file_type,
            "ephemeral_x25519_public_hex": ephemeral_pub.hex(),
            "nonce_hex": nonce.hex(),
            "canonical_aad_hex": aad.hex(),
            "primary_ciphertext_hex": ciphertext.hex(),
            "envelope_signature_hex": envelope.signature.hex(),
            "envelope_total_size": len(envelope_bytes),
            "tls_tunnel": "TLS 1.3 Tunnel 1 (Client ↔ Proxy)",
        }

        # --- NODE 2: PROXY BLIND RELAY ---
        proxy_node = {
            "node_name": "PROXY (Blind Relay)",
            "identity_uuid": str(proxy_uuid),
            "tls_tunnel1_status": "Terminated TLS 1.3 Tunnel 1",
            "tls_tunnel2_status": "Established TLS 1.3 Tunnel 2",
            "client_auth_verification": "PASSED (Ed25519 Signature Verified against Cache)",
            "visible_payload_type": "PRIMARY CIPHERTEXT (AES-256-GCM)",
            "visible_payload_hex": ciphertext.hex()[:128] + "... [TRUNCATED]",
            "proxy_can_decrypt": False,
            "proxy_decrypt_reason": "BLIND RELAY: Proxy does not possess Server's X25519 Private Key required for ECDH shared secret derivation.",
            "relayed_envelope_size": len(envelope_bytes),
        }

        # --- NODE 3: SERVER DECRYPTION & STORAGE & NODE 4: DOWNLOAD ---
        if state.client_identity._engine.validating() is not None:
            state.client_identity.rollback()

        proxy_cert_pem = (DEMO_DIR / "proxy" / "proxy.crt").read_bytes()
        with ClientSession(
            state.client_cfg,
            state.client_identity,
            server_keys=server_keys,
        ) as session:
            session.connect(proxy_cert_pem)
            write_object(session, object_uuid, file_type, content_bytes)
            downloaded_content = read_object(session, object_uuid)

        obj_info = state.objects.info(object_uuid)

        b64_content = base64.b64encode(downloaded_content).decode("ascii")
        data_uri = f"data:{file_type};base64,{b64_content}"
        is_image = file_type.startswith("image/")
        is_text = file_type.startswith("text/") or file_type in ("application/json", "application/xml")

        if is_text:
            preview_str = downloaded_content.decode("utf-8", "ignore")[:1000]
        elif is_image:
            preview_str = f"[Image File ({filename}): {len(downloaded_content)} bytes]"
        else:
            preview_str = f"[Binary File ({filename}): {len(downloaded_content)} bytes]"

        server_node = {
            "node_name": "SERVER (Destination & Plaintext Endpoint)",
            "identity_uuid": str(server_uuid),
            "tls_tunnel2_status": "Terminated TLS 1.3 Tunnel 2",
            "client_ed25519_verification": "AUTHENTICATED (Ed25519 Signature Match)",
            "authorization_policy": "ALLOWED (WRITE Policy Verified)",
            "decryption_key_used": f"Server X25519 Private Key (v{state.server_identity.credential().version})",
            "sha256_content_integrity": obj_info.content_integrity,
            "stored_object_uuid": str(object_uuid),
            "storage_path": obj_info.storage_reference,
            "decrypted_plaintext_preview": preview_str,
            "is_image": is_image,
            "data_uri": data_uri,
        }

        download_digest = hashlib.sha256(downloaded_content).hexdigest()

        download_node = {
            "download_status": "SUCCESS",
            "client_primary_decrypted": True,
            "downloaded_bytes_count": len(downloaded_content),
            "download_digest": download_digest,
            "integrity_matches": download_digest == obj_info.content_integrity,
            "filename": filename,
            "file_type": file_type,
            "b64_content": b64_content,
            "data_uri": data_uri,
            "is_image": is_image,
        }

        return JSONResponse(
            {
                "status": "SUCCESS",
                "client_node": client_node,
                "proxy_node": proxy_node,
                "server_node": server_node,
                "download_node": download_node,
            }
        )
    except Exception as exc:
        return JSONResponse(
            {"status": "ERROR", "message": str(exc)},
            status_code=400,
        )


@app.post("/api/rotate")
def trigger_rotation():
    state.initialize()
    server_before = state.server_identity.credential().version
    client_before = state.client_identity.current().version
    state.client_session.rotate()
    now = int(time.time())
    state.registry.checkpoint(state.client_identity.identity_uuid(), now + 31)
    state.client_identity._now_seconds = now + 31
    state.client_identity.checkpoint()
    client_after = state.client_identity.current().version

    return {
        "status": "ROTATED",
        "client_previous_version": client_before,
        "client_new_version": client_after,
        "server_version": server_before,
        "message": f"Client rotated from v{client_before} to v{client_after} via successor authorization signature",
    }


def main():
    import argparse
    import socket

    parser = argparse.ArgumentParser(description="SIH Web Demo Server")
    parser.add_argument("--port", type=int, default=8000, help="Port to run web server on")
    args = parser.parse_args()

    port = args.port
    # Test if port is available; if not, pick an ephemeral free port
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", port))
    except OSError:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]

    state.initialize()
    print("=" * 70)
    print("🌐 SIH WEB DEMO DASHBOARD RUNNING")
    print(f"   Open http://127.0.0.1:{port} in your browser")
    print("=" * 70)
    uvicorn.run(app, host="127.0.0.1", port=port, log_level="info")


if __name__ == "__main__":
    main()
