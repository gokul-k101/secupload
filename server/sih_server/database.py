"""SQLAlchemy engine/session setup and ORM tables.

Development database is SQLite; production uses PostgreSQL.  Switching is
configuration-driven via ``database_url`` (spec section 52/55).
"""

from __future__ import annotations

from sqlalchemy import (
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
    create_engine,
)
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker


class Base(DeclarativeBase):
    pass


class Clients(Base):
    __tablename__ = "clients"
    client_uuid: Mapped[str] = mapped_column(String(36), primary_key=True)
    status: Mapped[str] = mapped_column(String(16), default="ACTIVE")


class Proxies(Base):
    __tablename__ = "proxies"
    proxy_uuid: Mapped[str] = mapped_column(String(36), primary_key=True)
    status: Mapped[str] = mapped_column(String(16), default="ACTIVE")


class Credentials(Base):
    __tablename__ = "credentials"
    __table_args__ = (
        UniqueConstraint(
            "identity_uuid", "credential_version", name="uq_identity_version"
        ),
    )
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    identity_uuid: Mapped[str] = mapped_column(String(36), index=True)
    credential_version: Mapped[int] = mapped_column()
    signing_public_key: Mapped[bytes] = mapped_column(LargeBinary(32))
    encryption_public_key: Mapped[bytes] = mapped_column(LargeBinary(32))
    status: Mapped[str] = mapped_column(String(16))
    created_at: Mapped[int] = mapped_column()
    validation_deadline: Mapped[int | None] = mapped_column()
    activation_time: Mapped[int | None] = mapped_column()
    expiration_time: Mapped[int | None] = mapped_column()


class Permissions(Base):
    __tablename__ = "permissions"
    __table_args__ = (
        UniqueConstraint(
            "client_uuid", "object_uuid", "operation", name="uq_permission"
        ),
    )
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    client_uuid: Mapped[str] = mapped_column(String(36), index=True)
    object_uuid: Mapped[str] = mapped_column(String(36), index=True)
    operation: Mapped[str] = mapped_column(String(16))
    policy: Mapped[str] = mapped_column(String(64), default="ALLOW")


class Objects(Base):
    __tablename__ = "objects"
    object_uuid: Mapped[str] = mapped_column(String(36), primary_key=True)
    file_type: Mapped[str] = mapped_column(String(128), default="")
    file_size: Mapped[int] = mapped_column(default=0)
    object_metadata: Mapped[str] = mapped_column("metadata", Text, default="")
    content_integrity: Mapped[str] = mapped_column(String(64), default="")
    storage_reference: Mapped[str] = mapped_column(String(512), default="")


class AuditEvents(Base):
    __tablename__ = "audit_events"
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    identity_uuid: Mapped[str | None] = mapped_column(String(36), index=True)
    credential_version: Mapped[int | None] = mapped_column()
    event_type: Mapped[str] = mapped_column(String(64), index=True)
    timestamp: Mapped[int] = mapped_column()
    source: Mapped[str] = mapped_column(String(32), default="SERVER")
    result: Mapped[str] = mapped_column(String(16), default="OK")


class EnrollmentTokens(Base):
    __tablename__ = "enrollment_tokens"
    token_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    purpose: Mapped[str] = mapped_column(String(16))  # ENROLL | RECOVER
    identity_kind: Mapped[str] = mapped_column(String(16))  # CLIENT | PROXY
    identity_uuid: Mapped[str | None] = mapped_column(String(36))  # recovery only
    expires_at: Mapped[int] = mapped_column()
    used_at: Mapped[int | None] = mapped_column()


class EndpointCerts(Base):
    __tablename__ = "endpoint_certs"
    endpoint_uuid: Mapped[str] = mapped_column(String(36), primary_key=True)
    pem: Mapped[str] = mapped_column(Text)
    fingerprint: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[int] = mapped_column()


def make_engine(database_url: str) -> Engine:
    kwargs = (
        {"connect_args": {"check_same_thread": False}}
        if database_url.startswith("sqlite")
        else {}
    )
    engine = create_engine(database_url, **kwargs)
    Base.metadata.create_all(engine)
    return engine


def make_sessionmaker(engine: Engine) -> sessionmaker:
    return sessionmaker(bind=engine, expire_on_commit=False)
