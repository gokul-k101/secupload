"""End-to-end tunnel2 tests over real TLS with a running server."""

from __future__ import annotations

import socket
import ssl
import threading
import time
import uuid
from contextlib import suppress

import pytest
from sih_server.audit import AuditLog
from sih_server.auth import Authenticator
from sih_server.config import ServerConfig
from sih_server.database import make_engine, make_sessionmaker
from sih_server.identity import ServerIdentity
from sih_server.objects import ObjectStore
from sih_server.registry import CredentialRegistry
from sih_server.tunnel2 import Tunnel2Server
from sih_shared.config import RotationParams
from sih_shared.crypto import (
    generate_ed25519_keypair,
    generate_x25519_keypair,
    seal_message,
)
from sih_shared.framing import CHANNEL_CONTROL, CHANNEL_RELAY, recv_frame, send_frame
from sih_shared.models import IdentityKind
from sih_shared.protocol import (
    ControlType,
    MsgType,
    Op,
    RespStatus,
    build_aad,
    encode_control,
    encode_enrollment_body,
    encode_request_message,
    new_envelope,
    parse_control,
    parse_enroll_response,
    parse_envelope,
    unwrap_encrypted,
    wrap_encrypted,
)
from sih_shared.tls import build_client_context, generate_endpoint_cert, write_pem


@pytest.fixture
def running_server(tmp_path):
    config = ServerConfig(
        database_url=f"sqlite:///{tmp_path / 'test.db'}",
        storage_dir=tmp_path / "objects",
        data_dir=tmp_path / "data",
        rotation_duration=60,
        rotation_tick=3600,
        tunnel2_port=0,
    )
    engine = make_engine(config.database_url)
    session_factory = make_sessionmaker(engine)
    audit = AuditLog(session_factory)
    params = RotationParams(config.rotation_duration)
    registry = CredentialRegistry(session_factory, params, audit)
    identity = ServerIdentity(config, session_factory, audit)
    identity.ensure_loaded()
    objects = ObjectStore(session_factory, str(config.storage_dir), audit)
    authenticator = Authenticator(registry, audit)

    cert_pem, key_pem = generate_endpoint_cert("sih-test-server")
    cert_file = tmp_path / "endpoint.crt"
    key_file = tmp_path / "endpoint.key"
    write_pem(cert_file, cert_pem)
    write_pem(key_file, key_pem, private=True)
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_context.minimum_version = ssl.TLSVersion.TLSv1_3
    ssl_context.load_cert_chain(cert_file, key_file)

    server = Tunnel2Server(
        config, registry, authenticator, objects, identity, ssl_context
    )
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield {
        "server": server,
        "registry": registry,
        "identity": identity,
        "audit": audit,
        "port": port,
        "cert_pem": cert_pem,
    }
    server.shutdown()
    server.server_close()


class ClientConn:
    """Minimal test client: pinned TLS + control/relay channels."""

    def __init__(self, port: int, cert_pem: bytes) -> None:
        ctx = build_client_context(cert_pem)
        raw = socket.create_connection(("127.0.0.1", port), timeout=5)
        self.sock = ctx.wrap_socket(raw, server_hostname="sih.local")
        self.sock.settimeout(5)

    def close(self) -> None:
        with suppress(OSError):
            self.sock.close()

    def control(self, ctype: int, body: bytes) -> tuple[int, bytes]:
        send_frame(self.sock, CHANNEL_CONTROL, encode_control(ctype, body))
        channel, payload = recv_frame(self.sock)
        assert channel == CHANNEL_CONTROL
        msg = parse_control(payload)
        assert msg.ctype == ctype + 1
        return msg.ctype, msg.body


def enroll_via_tls(conn: ClientConn, token: str, kind=IdentityKind.CLIENT):
    ed_priv, ed_pub = generate_ed25519_keypair()
    x_priv, x_pub = generate_x25519_keypair()
    body = encode_enrollment_body(
        kind_to_code(kind), token, 1, ed_pub, x_pub
    )
    resp_ctype, resp_body = conn.control(ControlType.ENROLL.value, body)
    assert resp_ctype == ControlType.ENROLL_RESP.value
    status, message, key_info = parse_enroll_response(resp_body)
    return status, message, key_info, ed_priv, x_priv


def kind_to_code(kind: IdentityKind) -> int:
    return 1 if kind == IdentityKind.CLIENT else 2


def send_request(
    conn: ClientConn,
    client_id: uuid.UUID,
    ed_priv: bytes,
    x_priv: bytes,
    server_ed_pub: bytes,
    server_x_pub: bytes,
    server_version: int,
    op: int,
    object_uuid: uuid.UUID | None = None,
    file_type: str = "",
    file_size: int = 0,
    metadata: str = "",
) -> bytes:
    """Send a signed+encrypted REQUEST envelope and return the response bytes."""
    request_id = uuid.uuid4()
    ts = int(time.time())
    nonce = uuid.uuid4().bytes[:12]
    inner = encode_request_message(
        RequestMessage(op, object_uuid, file_type, file_size, metadata)
    )
    aad = build_aad(client_id, server_id, request_id, 1, ts, nonce, 0)
    eph, cipher = seal_message(server_x_pub, nonce, aad, inner)
    payload = wrap_encrypted(server_version, eph, nonce, cipher)
    env = new_envelope(
        MsgType.REQUEST.value, client_id, server_id, request_id, 1, ts, nonce, payload
    )
    env.sign(ed_priv)
    send_frame(conn.sock, CHANNEL_RELAY, env.encode())
    channel, resp = recv_frame(conn.sock)
    assert channel == CHANNEL_RELAY
    return resp


def test_enroll_and_write_read(running_server):
    reg = running_server["registry"]
    token = reg.issue_token("ENROLL", IdentityKind.CLIENT, 900, None)
    conn = ClientConn(running_server["port"], running_server["cert_pem"])
    try:
        status, message, key_info, ed_priv, x_priv = enroll_via_tls(conn, token)
        assert status == RespStatus.OK, message

        from sih_shared.protocol import parse_server_key_info

        sver, s_ed, s_x, _, _ = parse_server_key_info(key_info)
        client_id = _client_uuid(token)

        # WRITE (client supplies the object UUID; admin grants permission)
        object_uuid = uuid.uuid4()
        from sih_server.database import Permissions

        with running_server["registry"]._session_factory() as session:
            session.add(
                Permissions(
                    client_uuid=str(client_id),
                    object_uuid=str(object_uuid),
                    operation="WRITE",
                    policy="ALLOW",
                )
            )
            session.add(
                Permissions(
                    client_uuid=str(client_id),
                    object_uuid=str(object_uuid),
                    operation="READ",
                    policy="ALLOW",
                )
            )
            session.commit()
        data = b"chunk-one"
        resp_bytes = send_request(
            conn, client_id, ed_priv, x_priv, s_ed, s_x, sver,
            Op.WRITE.value, object_uuid=object_uuid, file_type="text/plain",
            file_size=len(data), metadata="{}",
        )
        env = parse_envelope(resp_bytes)
        assert env.sender_uuid == running_server["identity"].uuid()
        # decrypt response with client x_priv
        recipient_version, eph, nonce, cipher = unwrap_encrypted(env.payload)
        from sih_shared.crypto import open_message

        aad = build_aad(
            env.sender_uuid, env.recipient_uuid, env.request_id,
            env.sender_credential_version, env.timestamp, env.nonce, 0,
        )
        plain = open_message(x_priv, eph, nonce, aad, cipher)
        from sih_shared.protocol import parse_response_message

        resp = parse_response_message(plain)
        assert resp.status == RespStatus.OK
        object_uuid = resp.object_uuid
        assert object_uuid is not None

        # READ (same metadata back)
        resp_bytes = send_request(
            conn, client_id, ed_priv, x_priv, s_ed, s_x, sver,
            Op.READ.value, object_uuid=object_uuid,
        )
        env = parse_envelope(resp_bytes)
        recipient_version, eph, nonce, cipher = unwrap_encrypted(env.payload)
        plain = open_message(
            x_priv, eph, nonce,
            build_aad(env.sender_uuid, env.recipient_uuid, env.request_id,
                      env.sender_credential_version, env.timestamp, env.nonce, 0),
            cipher,
        )
        resp = parse_response_message(plain)
        assert resp.status == RespStatus.OK
        assert resp.file_size == len(data)
        assert resp.file_type == "text/plain"
    finally:
        conn.close()


def test_enroll_with_bad_token_rejected(running_server):
    conn = ClientConn(running_server["port"], running_server["cert_pem"])
    try:
        status, message, _, _, _ = enroll_via_tls(conn, "not-a-real-token")
        assert status == RespStatus.ERROR
        assert "token" in message.lower()
    finally:
        conn.close()


def test_registry_sync_returns_snapshot(running_server):
    reg = running_server["registry"]
    token = reg.issue_token("ENROLL", IdentityKind.CLIENT, 900, None)
    conn = ClientConn(running_server["port"], running_server["cert_pem"])
    try:
        enroll_via_tls(conn, token)
        from sih_shared.protocol import encode_enrollment_body as _  # noqa: F401

        # registry sync as a proxy
        p_token = reg.issue_token("ENROLL", IdentityKind.PROXY, 900, None)
        p_conn = ClientConn(running_server["port"], running_server["cert_pem"])
        try:
            p_status, p_message, p_key_info, p_ed, p_x = enroll_via_tls(
                p_conn, p_token, kind=IdentityKind.PROXY
            )
            assert p_status == RespStatus.OK

            # sync request is an authenticated envelope with an encrypted body
            from sih_shared.crypto import open_message
            from sih_shared.protocol import (
                encode_control,
                parse_control,
                parse_server_key_info,
                unwrap_encrypted,
                wrap_encrypted,
            )

            sver, s_ed, s_x, _, _ = parse_server_key_info(p_key_info)
            req_id = uuid.uuid4()
            ts = int(time.time())
            nonce = uuid.uuid4().bytes[:12]
            inner = bytes([1])  # CLIENT kind
            aad = build_aad(_proxy_uuid(p_token), server_id, req_id, 1, ts, nonce, 0)
            eph, cipher = seal_message(s_x, nonce, aad, inner)
            payload = wrap_encrypted(sver, eph, nonce, cipher)
            env = new_envelope(
                MsgType.CONTROL.value, _proxy_uuid(p_token), server_id, req_id,
                1, ts, nonce, payload,
            )
            env.sign(p_ed)
            send_frame(
                p_conn.sock, CHANNEL_CONTROL,
                encode_control(ControlType.REGISTRY_SYNC_REQ.value, env.encode()),
            )
            channel, resp = recv_frame(p_conn.sock)
            assert channel == CHANNEL_CONTROL
            msg = parse_control(resp)
            assert msg.ctype == ControlType.REGISTRY_SYNC_RESP.value
            resp_env = parse_envelope(msg.body)
            rv, eph2, nonce2, cipher2 = unwrap_encrypted(resp_env.payload)
            plain = open_message(
                p_x, eph2, nonce2,
                build_aad(resp_env.sender_uuid, resp_env.recipient_uuid,
                          resp_env.request_id, resp_env.sender_credential_version,
                          resp_env.timestamp, resp_env.nonce, 0),
                cipher2,
            )
            from sih_shared.protocol import parse_registry_snapshot

            entries = parse_registry_snapshot(plain)
            assert len(entries) == 1
            assert entries[0].identity_uuid == _client_uuid(token)
        finally:
            p_conn.close()
    finally:
        conn.close()


from sih_shared.protocol import RequestMessage  # noqa: E402

server_id = uuid.UUID("00000000-0000-4000-8000-000000000001")


def _client_uuid(token: str) -> uuid.UUID:
    import hashlib

    return uuid.UUID(hex=hashlib.sha256(b"client" + token.encode()).hexdigest()[:32])


def _proxy_uuid(token: str) -> uuid.UUID:
    import hashlib

    return uuid.UUID(hex=hashlib.sha256(b"proxy" + token.encode()).hexdigest()[:32])
