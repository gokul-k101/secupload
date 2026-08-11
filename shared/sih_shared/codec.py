"""Canonical binary encoding used for all signed and authenticated structures.

Every structure in the protocol is encoded through this module so that
signatures and AAD are computed over byte-identical serializations on every
end (SR-31 in v2.2, canonical AAD requirement in the spec).

All integers are big-endian.  Byte strings are length-prefixed with u32.
"""

from __future__ import annotations

import struct
import uuid


class EncodeError(ValueError):
    pass


class DecodeError(ValueError):
    pass


class Encoder:
    def __init__(self) -> None:
        self._buf = bytearray()

    def u8(self, v: int) -> Encoder:
        self._buf += struct.pack(">B", v)
        return self

    def u16(self, v: int) -> Encoder:
        self._buf += struct.pack(">H", v)
        return self

    def u32(self, v: int) -> Encoder:
        self._buf += struct.pack(">I", v)
        return self

    def u64(self, v: int) -> Encoder:
        self._buf += struct.pack(">Q", v)
        return self

    def i64(self, v: int) -> Encoder:
        self._buf += struct.pack(">q", v)
        return self

    def bytes_(self, b: bytes) -> Encoder:
        self.u32(len(b))
        self._buf += b
        return self

    def str_(self, s: str) -> Encoder:
        return self.bytes_(s.encode("utf-8"))

    def uuid_(self, u: uuid.UUID | None) -> Encoder:
        if u is None:
            self._buf += b"\x00" + b"\x00" * 16
        else:
            self._buf += b"\x01" + u.bytes
        return self

    def finish(self) -> bytes:
        return bytes(self._buf)


class Decoder:
    def __init__(self, data: bytes, offset: int = 0) -> None:
        self._data = data
        self._off = offset

    @property
    def remaining(self) -> int:
        return len(self._data) - self._off

    def _take(self, n: int) -> bytes:
        if self.remaining < n:
            raise DecodeError(f"truncated: need {n} bytes, have {self.remaining}")
        out = self._data[self._off : self._off + n]
        self._off += n
        return out

    def u8(self) -> int:
        return self._take(1)[0]

    def u16(self) -> int:
        return struct.unpack(">H", self._take(2))[0]

    def u32(self) -> int:
        return struct.unpack(">I", self._take(4))[0]

    def u64(self) -> int:
        return struct.unpack(">Q", self._take(8))[0]

    def i64(self) -> int:
        return struct.unpack(">q", self._take(8))[0]

    def bytes_(self) -> bytes:
        return self._take(self.u32())

    def str_(self) -> str:
        return self.bytes_().decode("utf-8")

    def uuid_(self) -> uuid.UUID | None:
        if self.u8() == 0:
            self._take(16)
            return None
        return uuid.UUID(bytes=self._take(16))

    def eof(self) -> bool:
        return self.remaining == 0


def encode_uuid_optional(u: uuid.UUID | None) -> bytes:
    return Encoder().uuid_(u).finish()
