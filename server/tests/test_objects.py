"""Object store tests."""

from __future__ import annotations

import uuid

import pytest
from sih_server.objects import ObjectStoreError


def test_create_write_finalize_read(objects, session_factory):
    owner = uuid.uuid4()
    data = b"hello world" * 100
    info = objects.create(owner, uuid.uuid4(), "text/plain", len(data), "{}")
    assert info.file_size == len(data)
    objects.write_chunk(info.object_uuid, 0, data)
    finalized = objects.finalize(info.object_uuid)
    assert len(finalized.content_integrity) == 64
    assert finalized.content_integrity == __import__(
        "hashlib"
    ).sha256(data).hexdigest()
    assert objects.read_chunk(info.object_uuid, 0) == data


def test_size_mismatch_fails_finalize(objects, session_factory):
    owner = uuid.uuid4()
    info = objects.create(owner, uuid.uuid4(), "text/plain", 100, "{}")
    objects.write_chunk(info.object_uuid, 0, b"short")
    with pytest.raises(ObjectStoreError) as exc:
        objects.finalize(info.object_uuid)
    assert exc.value.code == "INTEGRITY_FAILURE"


def test_finalized_object_rejects_writes(objects, session_factory):
    owner = uuid.uuid4()
    info = objects.create(owner, uuid.uuid4(), "text/plain", 3, "{}")
    objects.write_chunk(info.object_uuid, 0, b"abc")
    objects.finalize(info.object_uuid)
    with pytest.raises(ObjectStoreError) as exc:
        objects.write_chunk(info.object_uuid, 1, b"x")
    assert exc.value.code == "FINALIZED"


def test_chunks_are_append_ordered(objects, session_factory):
    owner = uuid.uuid4()
    info = objects.create(owner, uuid.uuid4(), "text/plain", 6, "{}")
    objects.write_chunk(info.object_uuid, 0, b"abc")
    objects.write_chunk(info.object_uuid, 1, b"def")
    objects.finalize(info.object_uuid)
    assert objects.read_chunk(info.object_uuid, 0, 3) == b"abc"
    assert objects.read_chunk(info.object_uuid, 1, 3) == b"def"


def test_missing_object_raises(objects, session_factory):
    with pytest.raises(ObjectStoreError) as exc:
        objects.info(uuid.uuid4())
    assert exc.value.code == "NOT_FOUND"


def test_delete_removes(objects, session_factory):
    owner = uuid.uuid4()
    info = objects.create(owner, uuid.uuid4(), "text/plain", 1, "{}")
    objects.write_chunk(info.object_uuid, 0, b"x")
    objects.delete(info.object_uuid)
    with pytest.raises(ObjectStoreError):
        objects.info(info.object_uuid)
