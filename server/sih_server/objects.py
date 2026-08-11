"""Server-side object storage (plaintext at rest, spec section 45-49).

Objects are stored as a single file per object under ``data_dir``;
``content_integrity`` is the SHA-256 of the full plaintext, set when the
object is finalized (size matches the declared file_size).
"""

from __future__ import annotations

import hashlib
import os
import uuid

from sih_shared.models import ObjectInfo

from . import audit as audit_mod
from .database import Objects


class ObjectStoreError(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class ObjectStore:
    def __init__(self, session_factory, data_dir: str, audit: audit_mod.AuditLog) -> None:
        self._session_factory = session_factory
        self._data_dir = data_dir
        self._audit = audit
        os.makedirs(data_dir, exist_ok=True)

    # ------------------------------------------------------------------ #

    def _path(self, object_uuid: uuid.UUID) -> str:
        return os.path.join(self._data_dir, f"{object_uuid}.obj")

    def _row_to_info(self, row: Objects) -> ObjectInfo:
        return ObjectInfo(
            object_uuid=uuid.UUID(row.object_uuid),
            file_type=row.file_type,
            file_size=row.file_size,
            metadata=row.object_metadata,
            content_integrity=row.content_integrity,
            storage_reference=row.storage_reference,
        )

    # ------------------------------------------------------------------ #

    def create(
        self,
        owner_uuid: uuid.UUID,
        object_uuid: uuid.UUID,
        file_type: str,
        file_size: int,
        metadata: str,
    ) -> ObjectInfo:
        if self.exists(object_uuid):
            raise ObjectStoreError("ALREADY_EXISTS", "object already exists")
        storage_reference = self._path(object_uuid)
        with self._session_factory() as session:
            session.add(
                Objects(
                    object_uuid=str(object_uuid),
                    file_type=file_type,
                    file_size=file_size,
                    object_metadata=metadata,
                    content_integrity="",
                    storage_reference=storage_reference,
                )
            )
            session.commit()
        self._audit.record(
            audit_mod.EVENT_OBJECT_ACCESS, owner_uuid, result="OK"
        )
        return self._row_to_info(self._get_row(object_uuid))

    def _get_row(self, object_uuid: uuid.UUID) -> Objects:
        with self._session_factory() as session:
            row = (
                session.query(Objects)
                .filter(Objects.object_uuid == str(object_uuid))
                .one_or_none()
            )
        if row is None:
            raise ObjectStoreError("NOT_FOUND", "object does not exist")
        return row

    def info(self, object_uuid: uuid.UUID) -> ObjectInfo:
        return self._row_to_info(self._get_row(object_uuid))

    def exists(self, object_uuid: uuid.UUID) -> bool:
        with self._session_factory() as session:
            row = (
                session.query(Objects)
                .filter(Objects.object_uuid == str(object_uuid))
                .one_or_none()
            )
        return row is not None

    def write_chunk(
        self,
        object_uuid: uuid.UUID,
        chunk_index: int,
        data: bytes,
    ) -> None:
        info = self.info(object_uuid)
        if info.content_integrity:
            raise ObjectStoreError("FINALIZED", "object is already finalized")
        path = self._path(object_uuid)
        with open(path, "ab") as f:
            f.write(data)
        self._audit.record(
            audit_mod.EVENT_OBJECT_ACCESS, object_uuid, result="OK"
        )

    def read_chunk(
        self,
        object_uuid: uuid.UUID,
        chunk_index: int,
        chunk_size: int = 64 * 1024,
    ) -> bytes:
        self.info(object_uuid)
        path = self._path(object_uuid)
        with open(path, "rb") as f:
            f.seek(chunk_index * chunk_size)
            return f.read(chunk_size)

    def finalize(self, object_uuid: uuid.UUID) -> ObjectInfo:
        """Verify size and compute content integrity (SR-21)."""
        info = self.info(object_uuid)
        if info.content_integrity:
            return info
        path = self._path(object_uuid)
        with open(path, "rb") as f:
            digest = hashlib.sha256(f.read()).hexdigest()
        size = os.path.getsize(path)
        if size != info.file_size:
            raise ObjectStoreError(
                "INTEGRITY_FAILURE",
                f"size mismatch: expected {info.file_size}, got {size}",
            )
        with self._session_factory() as session:
            row = (
                session.query(Objects)
                .filter(Objects.object_uuid == str(object_uuid))
                .one()
            )
            row.content_integrity = digest
            session.commit()
        return self.info(object_uuid)

    def delete(self, object_uuid: uuid.UUID) -> None:
        path = self._path(object_uuid)
        if os.path.exists(path):
            os.remove(path)
        with self._session_factory() as session:
            session.query(Objects).filter(
                Objects.object_uuid == str(object_uuid)
            ).delete()
            session.commit()
        self._audit.record(audit_mod.EVENT_OBJECT_ACCESS, object_uuid)
