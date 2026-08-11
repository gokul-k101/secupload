"""Server-side authorization (deny by default, spec section 43).

Permissions are granted per object (``object_uuid``) and per operation
(``READ`` / ``WRITE``); an explicit ``DENY`` policy always wins.
"""

from __future__ import annotations

import uuid

from sqlalchemy.orm import Session

from .database import Permissions


class AuthorizationError(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def check_permission(
    session: Session,
    client_uuid: uuid.UUID,
    object_uuid: uuid.UUID,
    operation: str,
) -> None:
    """Deny by default; allow only with an explicit ALLOW permission."""
    row = (
        session.query(Permissions)
        .filter(
            Permissions.client_uuid == str(client_uuid),
            Permissions.object_uuid == str(object_uuid),
            Permissions.operation == operation,
        )
        .one_or_none()
    )
    if row is None or row.policy != "ALLOW":
        raise AuthorizationError(
            "FORBIDDEN", f"{operation} on {object_uuid} not permitted"
        )
