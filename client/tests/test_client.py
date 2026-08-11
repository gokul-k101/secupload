"""Client library tests against a live server (via TLS, pinned).

The proxy (Phase 4) is not required for these tests: the client speaks the
same framed protocol to whichever pinned TLS peer it reaches, so the server
plays the proxy's role here.
"""

from __future__ import annotations

import ssl
import threading
import time
import uuid

import pytest
from sih_client.api import read_object, write_object
from sih_client.config import ClientConfig
from sih_client.identity import ClientIdentity
from sih_client.session import ClientError, ClientSession
from sih_server.audit import AuditLog
from sih_server.auth import Authenticator
from sih_server.config import ServerConfig
from sih_server.database import make_engine, make_sessionmaker
from sih_server.identity import ServerIdentity
from sih_server.objects import ObjectStore
from sih_server.registry import CredentialRegistry
from sih_server.tunnel2 import Tunnel2Server
from sih_shared.config import RotationParams
from sih_shared.models import IdentityKind
from sih_shared.tls import generate_endpoint_cert, write_pem


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
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield {
        "registry": registry,
        "port": port,
        "cert_pem": cert_pem,
        "server_uuid": identity.uuid(),
    }
    server.shutdown()
    server.server_close()


@pytest.fixture
def client_factory(running_server, tmp_path):
    def make(token: str, data_dir=None) -> ClientSession:
        cfg = ClientConfig(
            proxy_host="127.0.0.1",
            proxy_port=running_server["port"],
            server_uuid=running_server["server_uuid"],
            data_dir=data_dir or tmp_path / f"client-{uuid.uuid4()}",
            enrollment_token=token,
            rotation_duration=60,
        )
        identity = ClientIdentity(cfg)
        session = ClientSession(cfg, identity)
        session.connect(running_server["cert_pem"])
        return session

    return make


def issue_token(running_server, kind=IdentityKind.CLIENT) -> str:
    return running_server["registry"].issue_token("ENROLL", kind, 900, None)


def grant(running_server, client_uuid, object_uuid, operation="WRITE"):
    from sih_server.database import Permissions

    with running_server["registry"]._session_factory() as session:
        session.add(
            Permissions(
                client_uuid=str(client_uuid),
                object_uuid=str(object_uuid),
                operation=operation,
                policy="ALLOW",
            )
        )
        session.commit()


def test_enroll_and_write_read_roundtrip(running_server, client_factory):
    token = issue_token(running_server)
    with client_factory(token) as session:
        object_uuid = uuid.uuid4()
        grant(running_server, session._identity.identity_uuid(), object_uuid, "WRITE")
        grant(running_server, session._identity.identity_uuid(), object_uuid, "READ")
        data = b"payload" * 1000  # under one chunk
        write_object(session, object_uuid, "text/plain", data)
        assert read_object(session, object_uuid) == data


def test_multi_chunk_roundtrip(running_server, client_factory):
    token = issue_token(running_server)
    with client_factory(token) as session:
        object_uuid = uuid.uuid4()
        grant(running_server, session._identity.identity_uuid(), object_uuid, "WRITE")
        grant(running_server, session._identity.identity_uuid(), object_uuid, "READ")
        data = bytes(range(256)) * 3000  # ~768 KiB > one 64 KiB chunk
        write_object(session, object_uuid, "application/octet-stream", data)
        assert read_object(session, object_uuid) == data


def test_unpermitted_write_rejected(running_server, client_factory):
    token = issue_token(running_server)
    with client_factory(token) as session:
        with pytest.raises(ClientError) as exc:
            write_object(session, uuid.uuid4(), "text/plain", b"x")
        assert exc.value.code == "WRITE_REJECTED"


def test_bad_token_rejected(running_server, tmp_path):
    cfg = ClientConfig(
        proxy_host="127.0.0.1",
        proxy_port=running_server["port"],
        server_uuid=running_server["server_uuid"],
        data_dir=tmp_path / "client-bad",
        enrollment_token="not-a-token",
        rotation_duration=60,
    )
    with ClientSession(cfg, ClientIdentity(cfg)) as session:
        with pytest.raises(ClientError) as exc:
            session.connect(running_server["cert_pem"])
        assert exc.value.code == "ENROLL_REJECTED"


def test_identity_persists_across_sessions(running_server, tmp_path):
    token = issue_token(running_server)
    data_dir = tmp_path / "client-persist"

    def open_session():
        cfg = ClientConfig(
            proxy_host="127.0.0.1",
            proxy_port=running_server["port"],
            server_uuid=running_server["server_uuid"],
            data_dir=data_dir,
            enrollment_token=token,
            rotation_duration=60,
        )
        session = ClientSession(cfg, ClientIdentity(cfg))
        session.connect(running_server["cert_pem"])
        return session

    with open_session() as session:
        first_uuid = session._identity.identity_uuid()
    # a new session with the same data dir reuses the identity
    with open_session() as session:
        assert session._identity.identity_uuid() == first_uuid


def test_rotate_cycles_credential(running_server, client_factory, tmp_path):
    token = issue_token(running_server)
    with client_factory(token) as session:
        v1 = session._identity.current().version
        session.rotate()
        # the successor is VALIDATING; promotion requires the T/2 window
        assert session._identity.current().version == v1
        # simulate the validation window passing on both sides (the server
        # promotes when *its* clock passes the deadline), then checkpoint
        now = int(time.time())
        running_server["registry"].checkpoint(
            session._identity.identity_uuid(), now + 31
        )
        session._identity._now_seconds = now + 31
        session._identity.checkpoint()
        assert session._identity.current().version == v1 + 1
        # still able to talk with the rotated credential
        object_uuid = uuid.uuid4()
        grant(running_server, session._identity.identity_uuid(), object_uuid, "WRITE")
        grant(running_server, session._identity.identity_uuid(), object_uuid, "READ")
        write_object(session, object_uuid, "text/plain", b"post-rotation")
        assert read_object(session, object_uuid) == b"post-rotation"
