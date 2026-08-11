"""Shared fixtures for server tests (in-memory SQLite)."""

from __future__ import annotations

import uuid

import pytest
from sih_server.audit import AuditLog
from sih_server.auth import Authenticator
from sih_server.config import ServerConfig
from sih_server.database import make_engine, make_sessionmaker
from sih_server.identity import ServerIdentity
from sih_server.objects import ObjectStore
from sih_server.registry import CredentialRegistry
from sih_shared.config import RotationParams
from sih_shared.tls import generate_endpoint_cert


@pytest.fixture
def params():
    return RotationParams(rotation_duration=60)


@pytest.fixture
def session_factory():
    engine = make_engine("sqlite:///:memory:")
    return make_sessionmaker(engine)


@pytest.fixture
def audit(session_factory):
    return AuditLog(session_factory)


@pytest.fixture
def config(tmp_path):
    cfg = ServerConfig(
        database_url="sqlite:///:memory:",
        storage_dir=tmp_path / "objects",
        data_dir=tmp_path / "data",
        rotation_duration=60,
        rotation_tick=60,
    )
    return cfg


@pytest.fixture
def registry(session_factory, params, audit):
    return CredentialRegistry(session_factory, params, audit)


@pytest.fixture
def identity(session_factory, config, audit):
    return ServerIdentity(config, session_factory, audit)


@pytest.fixture
def objects(session_factory, config, audit):
    return ObjectStore(session_factory, str(config.storage_dir), audit)


@pytest.fixture
def authenticator(registry, audit):
    return Authenticator(registry, audit)


@pytest.fixture
def endpoint_cert(tmp_path):
    cert_pem, key_pem = generate_endpoint_cert("sih-test-server")
    cert_file = tmp_path / "endpoint.crt"
    key_file = tmp_path / "endpoint.key"
    cert_file.write_bytes(cert_pem)
    key_file.write_bytes(key_pem)
    return cert_file, key_file, cert_pem


def enroll_client(
    registry, identity, audit, kind="CLIENT", token=None, now=None
) -> tuple[uuid.UUID, int, bytes, bytes]:
    """Issue a token and enroll a fresh identity; returns its keys."""
    from sih_shared.crypto import generate_ed25519_keypair, generate_x25519_keypair
    from sih_shared.models import IdentityKind

    issued = registry.issue_token("ENROLL", IdentityKind(kind), 900, None)
    token = token or issued
    ident = uuid.uuid4()
    ed_priv, ed_pub = generate_ed25519_keypair()
    x_priv, x_pub = generate_x25519_keypair()
    registry.enroll(
        ident, IdentityKind(kind), token, 1, ed_pub, x_pub, now=now
    )
    return ident, ed_priv, x_priv, x_pub
