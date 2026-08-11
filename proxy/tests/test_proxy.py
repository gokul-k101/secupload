"""End-to-end tests: Client -> Proxy -> Server over pinned TLS.

The proxy is exercised as a real process object (not the relay-only
server the client tests use), so every request here crosses two pinned
TLS hops and the blind splice.
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
        "cert_file": cert_file,
        "server_uuid": identity.uuid(),
    }
    server.shutdown()
    server.server_close()


@pytest.fixture
def running_proxy(running_server, tmp_path):
    cert_pem, key_pem = generate_endpoint_cert("sih-test-proxy")
    cert_file = tmp_path / "proxy.crt"
    key_file = tmp_path / "proxy.key"
    write_pem(cert_file, cert_pem)
    write_pem(key_file, key_pem, private=True)
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_context.minimum_version = ssl.TLSVersion.TLSv1_3
    ssl_context.load_cert_chain(cert_file, key_file)

    proxy_token = running_server["registry"].issue_token(
        "ENROLL", IdentityKind.PROXY, 900, None
    )
    cfg = ProxyConfig(
        proxy_host="127.0.0.1",
        proxy_port=0,
        cert_file=cert_file,
        key_file=key_file,
        server_host="127.0.0.1",
        server_port=running_server["port"],
        server_cert_file=running_server["cert_file"],
        server_uuid=running_server["server_uuid"],
        data_dir=tmp_path / "proxy-data",
        enrollment_token=proxy_token,
        rotation_duration=60,
    )
    identity = ProxyIdentity(cfg)
    identity.ensure_loaded()
    cache = RegistryCache()
    proxy = ProxyServer(cfg, ssl_context, identity, cache)
    port = proxy.server_address[1]
    threading.Thread(target=proxy.serve_forever, daemon=True).start()
    yield {
        "port": port,
        "cert_pem": cert_pem,
        "cache": cache,
        "identity": identity,
        "config": cfg,
        "proxy": proxy,
    }
    proxy.shutdown()
    proxy.server_close()


@pytest.fixture
def client_factory(running_proxy, tmp_path):
    def make(token: str, data_dir=None) -> ClientSession:
        cfg = ClientConfig(
            proxy_host="127.0.0.1",
            proxy_port=running_proxy["port"],
            server_uuid=running_proxy["config"].server_uuid,
            data_dir=data_dir or tmp_path / f"client-{uuid.uuid4()}",
            enrollment_token=token,
            rotation_duration=60,
        )
        session = ClientSession(cfg, ClientIdentity(cfg))
        session.connect(running_proxy["cert_pem"])
        return session

    return make


def issue_token(running_server, kind=IdentityKind.CLIENT) -> str:
    return running_server["registry"].issue_token("ENROLL", kind, 900, None)


def grant(running_server, client_uuid, object_uuid, operation="WRITE"):
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


def test_enroll_write_read_through_proxy(running_server, running_proxy, client_factory):
    token = issue_token(running_server)
    with client_factory(token) as session:
        object_uuid = uuid.uuid4()
        grant(running_server, session._identity.identity_uuid(), object_uuid, "WRITE")
        grant(running_server, session._identity.identity_uuid(), object_uuid, "READ")
        data = b"payload" * 1000
        write_object(session, object_uuid, "text/plain", data)
        assert read_object(session, object_uuid) == data


def test_multi_chunk_through_proxy(running_server, running_proxy, client_factory):
    token = issue_token(running_server)
    with client_factory(token) as session:
        object_uuid = uuid.uuid4()
        grant(running_server, session._identity.identity_uuid(), object_uuid, "WRITE")
        grant(running_server, session._identity.identity_uuid(), object_uuid, "READ")
        data = bytes(range(256)) * 3000
        write_object(session, object_uuid, "application/octet-stream", data)
        assert read_object(session, object_uuid) == data


def test_bad_token_rejected_through_proxy(running_server, running_proxy, tmp_path):
    cfg = ClientConfig(
        proxy_host="127.0.0.1",
        proxy_port=running_proxy["port"],
        server_uuid=running_proxy["config"].server_uuid,
        data_dir=tmp_path / "client-bad",
        enrollment_token="not-a-token",
        rotation_duration=60,
    )
    with ClientSession(cfg, ClientIdentity(cfg)) as session:
        with pytest.raises(ClientError) as exc:
            session.connect(running_proxy["cert_pem"])
        assert exc.value.code == "ENROLL_REJECTED"


def test_unpermitted_write_rejected_through_proxy(
    running_server, running_proxy, client_factory
):
    token = issue_token(running_server)
    with client_factory(token) as session:
        with pytest.raises(ClientError) as exc:
            write_object(session, uuid.uuid4(), "text/plain", b"x")
        assert exc.value.code == "WRITE_REJECTED"


def test_registry_sync_caches_snapshot(running_server, running_proxy, client_factory):
    token = issue_token(running_server)
    # first client enrolls through the proxy; the pre-relay sync ran before
    # that enrollment landed, so its identity must appear after a later sync
    with client_factory(token) as session:
        first_uuid = session._identity.identity_uuid()
    with client_factory(issue_token(running_server)):
        pass
    entries = running_proxy["cache"].snapshot()
    uuids = {e.identity_uuid for e in entries}
    assert first_uuid in uuids
    proxy_uuid = running_proxy["identity"].identity_uuid()
    assert proxy_uuid in uuids


def test_proxy_rotates_identity(running_server, running_proxy, client_factory):
    # a fresh identity on one clock timebase so every window (created_at,
    # validation deadline, SR-14 fallback coverage) is consistent
    base = int(time.time())
    identity = ProxyIdentity(running_proxy["config"], now_seconds=base)
    identity.ensure_loaded()
    running_proxy["proxy"].proxy_identity = identity
    v1 = identity.current().version
    # landing on the rotation point (expiry - 2*fallback): the pre-relay
    # burst of the next client connection submits the successor
    identity._now_seconds = base + 30
    with client_factory(issue_token(running_server)):
        pass
    # the T/2 validation window closes on both sides; promote both
    running_server["registry"].checkpoint(identity.identity_uuid(), base + 31)
    identity._now_seconds = base + 60
    identity.checkpoint()
    assert identity.current().version == v1 + 1
    # back to real time: a fresh client still round-trips through the proxy
    identity._now_seconds = None
    token = issue_token(running_server)
    with client_factory(token) as session:
        object_uuid = uuid.uuid4()
        grant(running_server, session._identity.identity_uuid(), object_uuid, "WRITE")
        write_object(session, object_uuid, "text/plain", b"rotated-proxy")
        grant(running_server, session._identity.identity_uuid(), object_uuid, "READ")
        assert read_object(session, object_uuid) == b"rotated-proxy"
