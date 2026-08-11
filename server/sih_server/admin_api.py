"""Admin HTTP API (FastAPI on port 9000, loopback only).

Issues enrollment/recovery tokens, reports server status, and exposes the
audit trail.  Administration is out-of-band; the API is bound to localhost
and guarded by a shared admin secret (``SIH_ADMIN_SECRET``) when set.
"""

from __future__ import annotations

import os
import time

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field
from sih_shared.config import RotationParams

from . import audit as audit_mod
from .config import ServerConfig
from .database import make_engine, make_sessionmaker
from .identity import ServerIdentity
from .registry import CredentialRegistry

ADMIN_SECRET_ENV = "SIH_ADMIN_SECRET"


class TokenRequest(BaseModel):
    purpose: str = Field(pattern="^(ENROLL|RECOVER)$")
    kind: str = Field(pattern="^(CLIENT|PROXY)$")
    identity_uuid: str | None = None


class TokenResponse(BaseModel):
    token: str
    expires_at: int


class StatusResponse(BaseModel):
    server_uuid: str
    credential_version: int
    credential_status: str
    next_rotation: int | None
    identities: dict


def _require_admin(authorization: str | None) -> None:
    secret = os.environ.get(ADMIN_SECRET_ENV)
    if secret and authorization != f"Bearer {secret}":
        raise HTTPException(status_code=401, detail="unauthorized")


def build_app(
    config: ServerConfig,
    registry: CredentialRegistry,
    audit: audit_mod.AuditLog,
    server_identity: ServerIdentity,
) -> FastAPI:
    app = FastAPI(title="SIH Admin", version="0.1.0")

    @app.post("/admin/tokens", response_model=TokenResponse)
    def issue_token(req: TokenRequest, authorization: str | None = Header(None)):
        _require_admin(authorization)
        from sih_shared.models import IdentityKind

        identity_uuid = None
        if req.identity_uuid:
            import uuid

            identity_uuid = uuid.UUID(req.identity_uuid)
        token = registry.issue_token(
            req.purpose,
            IdentityKind(req.kind),
            config.token_ttl,
            identity_uuid,
        )
        audit.record(audit_mod.EVENT_ENROLLMENT, source="ADMIN")
        return TokenResponse(token=token, expires_at=int(time.time()) + config.token_ttl)

    @app.get("/admin/status", response_model=StatusResponse)
    def status(authorization: str | None = Header(None)):
        _require_admin(authorization)
        cred = server_identity.credential()
        return StatusResponse(
            server_uuid=str(server_identity.uuid()),
            credential_version=cred.version,
            credential_status=cred.status.value,
            next_rotation=cred.expiration_time,
            identities={},
        )

    @app.get("/admin/audit")
    def audit_log(limit: int = 100, authorization: str | None = Header(None)):
        _require_admin(authorization)
        return [
            {
                "id": e.id,
                "identity_uuid": e.identity_uuid,
                "credential_version": e.credential_version,
                "event_type": e.event_type,
                "timestamp": e.timestamp,
                "source": e.source,
                "result": e.result,
            }
            for e in audit.recent(min(limit, 1000))
        ]

    return app


def make_default_app(config: ServerConfig) -> FastAPI:
    """Build a fully wired app (engine + registry + identity) from config."""
    engine = make_engine(config.database_url)
    session_factory = make_sessionmaker(engine)
    audit = audit_mod.AuditLog(session_factory)
    params = RotationParams(config.rotation_duration)
    registry = CredentialRegistry(session_factory, params, audit)
    identity = ServerIdentity(config, session_factory, audit)
    identity.ensure_loaded()
    return build_app(config, registry, audit, identity)
