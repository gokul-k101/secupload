"""High-level client API: chunked object write/read with integrity checks."""

from __future__ import annotations

import hashlib
import uuid

from sih_shared.protocol import (
    Op,
    RespStatus,
)

from .session import CHUNK_SIZE, ClientError, ClientSession


def write_object(
    session: ClientSession,
    object_uuid: uuid.UUID,
    file_type: str,
    data: bytes,
    metadata: str = "",
) -> None:
    """Create an object and stream all its chunks (SR-22..24)."""
    response = session.request(
        Op.WRITE.value,
        object_uuid=object_uuid,
        file_type=file_type,
        file_size=len(data),
        metadata=metadata,
    )
    if response.status != RespStatus.OK:
        raise ClientError("WRITE_REJECTED", response.message)

    index = 0
    while index < len(data):
        chunk = data[index : index + CHUNK_SIZE]
        resp = session.send_chunk(object_uuid, index // CHUNK_SIZE, chunk)
        if resp.status != RespStatus.OK:
            raise ClientError("CHUNK_REJECTED", resp.message)
        index += CHUNK_SIZE


def read_object(
    session: ClientSession,
    object_uuid: uuid.UUID,
) -> bytes:
    """Fetch an object's full content and verify its integrity (SR-21)."""
    response = session.request(Op.READ.value, object_uuid=object_uuid)
    if response.status != RespStatus.OK:
        raise ClientError("READ_REJECTED", response.message)

    expected = response.content_integrity or ""
    size = response.file_size
    data = bytearray()
    index = 0
    while len(data) < size:
        chunk = session.request_chunk(object_uuid, index)
        if not chunk:
            break
        data.extend(chunk)
        index += 1

    content = bytes(data)
    if expected:
        digest = hashlib.sha256(content).hexdigest()
        if digest != expected:
            raise ClientError(
                "INTEGRITY_FAILURE",
                f"content digest mismatch: {digest} != {expected}",
            )
    return content


def read_chunk_content(
    session: ClientSession,
    object_uuid: uuid.UUID,
    chunk_index: int,
) -> bytes:
    """Fetch one chunk; returns b'' when the chunk is out of range."""
    return session.request_chunk(object_uuid, chunk_index)
