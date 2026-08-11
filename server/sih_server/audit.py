"""Audit logging (spec section 55-56)."""

from __future__ import annotations

import time
import uuid

from .database import AuditEvents

# event type constants
EVENT_ENROLLMENT = "ENROLLMENT"
EVENT_RECOVERY = "RECOVERY"
EVENT_AUTH_SUCCESS = "AUTH_SUCCESS"
EVENT_AUTH_FAILURE = "AUTH_FAILURE"
EVENT_CREDENTIAL_GENERATION = "CREDENTIAL_GENERATION"
EVENT_CREDENTIAL_VALIDATION = "CREDENTIAL_VALIDATION"
EVENT_CREDENTIAL_PROMOTION = "CREDENTIAL_PROMOTION"
EVENT_CREDENTIAL_ROLLBACK = "CREDENTIAL_ROLLBACK"
EVENT_CREDENTIAL_REVOCATION = "CREDENTIAL_REVOCATION"
EVENT_CREDENTIAL_EXPIRATION = "CREDENTIAL_EXPIRATION"
EVENT_AUTHORIZATION_FAILURE = "AUTHORIZATION_FAILURE"
EVENT_OBJECT_ACCESS = "OBJECT_ACCESS"
EVENT_INTEGRITY_FAILURE = "INTEGRITY_FAILURE"
EVENT_REPLAY_REJECTION = "REPLAY_REJECTION"
EVENT_REGISTRY_SYNC = "REGISTRY_SYNC"
EVENT_TLS_FAILURE = "TLS_FAILURE"
EVENT_TRANSITION_FAILURE = "TRANSITION_FAILURE"


class AuditLog:
    def __init__(self, session_factory) -> None:
        self._session_factory = session_factory

    def record(
        self,
        event_type: str,
        identity_uuid: uuid.UUID | str | None = None,
        credential_version: int | None = None,
        source: str = "SERVER",
        result: str = "OK",
    ) -> None:
        with self._session_factory() as session:
            session.add(
                AuditEvents(
                    identity_uuid=str(identity_uuid) if identity_uuid else None,
                    credential_version=credential_version,
                    event_type=event_type,
                    timestamp=int(time.time()),
                    source=source,
                    result=result,
                )
            )
            session.commit()

    def recent(self, limit: int = 100) -> list[AuditEvents]:
        with self._session_factory() as session:
            return (
                session.query(AuditEvents)
                .order_by(AuditEvents.id.desc())
                .limit(limit)
                .all()
            )
