"""Application-layer protocol: signed envelopes, canonical AAD, messages.

Envelope layout (fixed header + payload + Ed25519 signature):

    u8   version
    u8   msg_type
    16B  sender_uuid
    16B  recipient_uuid
    16B  request_id
    u32  sender_credential_version
    i64  timestamp (unix seconds)
    12B  nonce            (replay protection)
    u32  payload_len
    ...  payload
    64B  Ed25519 signature over everything before it

The signature is verified by the direct application peer (server verifies
client, client verifies server); the proxy only reads the header for routing
(recipient UUID) and relays the payload byte-for-byte.
"""

from __future__ import annotations

import struct
import uuid
from dataclasses import dataclass
from enum import IntEnum

from .codec import DecodeError, Decoder, Encoder
from .crypto import (
    AESGCM_NONCE_SIZE,
    ED25519_SIGNATURE_SIZE,
    SignatureError,
    sign_ed25519,
    verify_ed25519,
)

ENVELOPE_VERSION = 1
NONCE_SIZE = AESGCM_NONCE_SIZE
HEADER_SIZE = 1 + 1 + 16 + 16 + 16 + 4 + 8 + 12 + 4


class MsgType(IntEnum):
    REQUEST = 1
    RESPONSE = 2
    OBJ_CHUNK = 3
    CONTROL = 4


class Op(IntEnum):
    READ = 1
    WRITE = 2
    READ_CHUNK = 3


class ControlType(IntEnum):
    ENROLL = 1
    ENROLL_RESP = 2
    RECOVER = 3
    ROTATE_SUBMIT = 4
    ROTATE_SUBMIT_RESP = 5
    ROTATE_CHECKPOINT = 6
    ROTATE_CHECKPOINT_RESP = 7
    ROTATE_ROLLBACK = 8
    ROTATE_ROLLBACK_RESP = 9
    ROTATE_REVOKE = 10
    ROTATE_REVOKE_RESP = 11
    REGISTRY_SYNC_REQ = 12
    REGISTRY_SYNC_RESP = 13
    REGISTRY_UPDATE = 14


class RespStatus(IntEnum):
    OK = 0
    ERROR = 1
    UNAUTHORIZED = 2
    FORBIDDEN = 3
    NOT_FOUND = 4
    INVALID = 5
    REPLAY = 6
    INTEGRITY = 7


class ProtocolError(ValueError):
    pass


# --------------------------------------------------------------------- #
# canonical AAD
# --------------------------------------------------------------------- #

_AAD_TAG = b"SIH-AAD-1"


def build_aad(
    sender_uuid: uuid.UUID,
    recipient_uuid: uuid.UUID,
    request_id: uuid.UUID,
    sender_credential_version: int,
    timestamp: int,
    nonce: bytes,
    chunk_index: int,
) -> bytes:
    """Canonical authenticated-associated data (spec section 37)."""
    return (
        Encoder()
        .bytes_(_AAD_TAG)
        .uuid_(sender_uuid)
        .uuid_(recipient_uuid)
        .uuid_(request_id)
        .u32(sender_credential_version)
        .i64(timestamp)
        .bytes_(nonce)
        .u64(chunk_index)
        .finish()
    )


# --------------------------------------------------------------------- #
# envelope
# --------------------------------------------------------------------- #

@dataclass
class Envelope:
    msg_type: int
    sender_uuid: uuid.UUID
    recipient_uuid: uuid.UUID
    request_id: uuid.UUID
    sender_credential_version: int
    timestamp: int
    nonce: bytes
    payload: bytes
    version: int = ENVELOPE_VERSION
    signature: bytes = b""

    def signed_bytes(self) -> bytes:
        """The exact bytes covered by the Ed25519 signature."""
        return _pack_header(self) + self.payload

    def sign(self, ed25519_private: bytes) -> None:
        self.signature = sign_ed25519(ed25519_private, self.signed_bytes())

    def verify(self, ed25519_public: bytes) -> None:
        try:
            verify_ed25519(ed25519_public, self.signed_bytes(), self.signature)
        except SignatureError as exc:
            raise ProtocolError(f"envelope signature invalid: {exc}") from exc

    def encode(self) -> bytes:
        return self.signed_bytes() + self.signature


def _pack_header(env: Envelope) -> bytes:
    return struct.pack(
        ">BB16s16s16sIq12sI",
        env.version,
        env.msg_type,
        env.sender_uuid.bytes,
        env.recipient_uuid.bytes,
        env.request_id.bytes,
        env.sender_credential_version,
        env.timestamp,
        env.nonce,
        len(env.payload),
    )


def new_envelope(
    msg_type: int,
    sender_uuid: uuid.UUID,
    recipient_uuid: uuid.UUID,
    request_id: uuid.UUID,
    sender_credential_version: int,
    timestamp: int,
    nonce: bytes,
    payload: bytes = b"",
) -> Envelope:
    return Envelope(
        msg_type=msg_type,
        sender_uuid=sender_uuid,
        recipient_uuid=recipient_uuid,
        request_id=request_id,
        sender_credential_version=sender_credential_version,
        timestamp=timestamp,
        nonce=nonce,
        payload=payload,
    )


def parse_envelope(data: bytes) -> Envelope:
    if len(data) < HEADER_SIZE + ED25519_SIGNATURE_SIZE:
        raise ProtocolError("envelope too short")
    (
        version,
        msg_type,
        sender,
        recipient,
        request_id,
        cred_version,
        timestamp,
        nonce,
        payload_len,
    ) = struct.unpack(">BB16s16s16sIq12sI", data[:HEADER_SIZE])
    if version != ENVELOPE_VERSION:
        raise ProtocolError(f"unsupported envelope version {version}")
    payload = data[HEADER_SIZE : HEADER_SIZE + payload_len]
    if len(payload) != payload_len:
        raise ProtocolError("envelope payload truncated")
    signature = data[HEADER_SIZE + payload_len :]
    if len(signature) != ED25519_SIGNATURE_SIZE:
        raise ProtocolError("envelope signature truncated")
    return Envelope(
        version=version,
        msg_type=msg_type,
        sender_uuid=uuid.UUID(bytes=sender),
        recipient_uuid=uuid.UUID(bytes=recipient),
        request_id=uuid.UUID(bytes=request_id),
        sender_credential_version=cred_version,
        timestamp=timestamp,
        nonce=nonce,
        payload=payload,
        signature=signature,
    )


def envelope_recipient(data: bytes) -> uuid.UUID:
    """Extract the recipient UUID from an encoded envelope (proxy routing)."""
    if len(data) < HEADER_SIZE:
        raise ProtocolError("envelope too short for header")
    return uuid.UUID(bytes=data[18:34])


def envelope_msg_type(data: bytes) -> int:
    if len(data) < HEADER_SIZE:
        raise ProtocolError("envelope too short for header")
    return data[1]


# --------------------------------------------------------------------- #
# application request / response messages (primary-encrypted payloads)
# --------------------------------------------------------------------- #

@dataclass
class RequestMessage:
    """Plaintext content of an application request (client -> server)."""

    op: int
    object_uuid: uuid.UUID | None = None
    file_type: str = ""
    file_size: int = 0
    metadata: str = ""


def encode_request_message(msg: RequestMessage) -> bytes:
    return (
        Encoder()
        .u8(msg.op)
        .uuid_(msg.object_uuid)
        .str_(msg.file_type)
        .u64(msg.file_size)
        .str_(msg.metadata)
        .finish()
    )


def parse_request_message(data: bytes) -> RequestMessage:
    dec = Decoder(data)
    op = dec.u8()
    return RequestMessage(
        op=op,
        object_uuid=dec.uuid_(),
        file_type=dec.str_(),
        file_size=dec.u64(),
        metadata=dec.str_(),
    )


@dataclass
class ResponseMessage:
    """Plaintext content of an application response (server -> client).

    Carries piggybacked server credential rotation information so the
    client can follow the server's application identity through authorized
    transitions without an extra channel.
    """

    status: int = RespStatus.OK
    message: str = ""
    object_uuid: uuid.UUID | None = None
    file_type: str = ""
    file_size: int = 0
    content_integrity: str = ""
    server_key_version: int = 0
    server_ed25519_public: bytes = b""
    server_x25519_public: bytes = b""
    server_successor_signature: bytes = b""
    server_prev_version: int = 0


def encode_response_message(msg: ResponseMessage) -> bytes:
    return (
        Encoder()
        .u8(msg.status)
        .str_(msg.message)
        .uuid_(msg.object_uuid)
        .str_(msg.file_type)
        .u64(msg.file_size)
        .str_(msg.content_integrity)
        .u32(msg.server_key_version)
        .bytes_(msg.server_ed25519_public)
        .bytes_(msg.server_x25519_public)
        .bytes_(msg.server_successor_signature)
        .u32(msg.server_prev_version)
        .finish()
    )


def parse_response_message(data: bytes) -> ResponseMessage:
    dec = Decoder(data)
    return ResponseMessage(
        status=dec.u8(),
        message=dec.str_(),
        object_uuid=dec.uuid_(),
        file_type=dec.str_(),
        file_size=dec.u64(),
        content_integrity=dec.str_(),
        server_key_version=dec.u32(),
        server_ed25519_public=dec.bytes_(),
        server_x25519_public=dec.bytes_(),
        server_successor_signature=dec.bytes_(),
        server_prev_version=dec.u32(),
    )


# --------------------------------------------------------------------- #
# control messages (rotation, enrollment, registry sync)
# --------------------------------------------------------------------- #

@dataclass
class ControlMessage:
    ctype: int
    body: bytes = b""


def encode_control(ctype: int, body: bytes = b"") -> bytes:
    return Encoder().u8(ctype).bytes_(body).finish()


def parse_control(data: bytes) -> ControlMessage:
    dec = Decoder(data)
    ctype = dec.u8()
    return ControlMessage(ctype=ctype, body=dec.bytes_())


# --------------------------------------------------------------------- #
# registry entry (for proxy synchronization)
# --------------------------------------------------------------------- #

@dataclass
class RegistryEntry:
    identity_uuid: uuid.UUID
    version: int
    status: int
    ed25519_public: bytes
    x25519_public: bytes
    created_at: int
    validation_deadline: int
    activation_time: int
    expiration_time: int


def encode_registry_entry(entry: RegistryEntry) -> bytes:
    return (
        Encoder()
        .uuid_(entry.identity_uuid)
        .u32(entry.version)
        .u8(entry.status)
        .bytes_(entry.ed25519_public)
        .bytes_(entry.x25519_public)
        .i64(entry.created_at)
        .i64(entry.validation_deadline)
        .i64(entry.activation_time)
        .i64(entry.expiration_time)
        .finish()
    )


def parse_registry_entry(data: bytes) -> RegistryEntry:
    dec = Decoder(data)
    return RegistryEntry(
        identity_uuid=dec.uuid_() or uuid.UUID(int=0),
        version=dec.u32(),
        status=dec.u8(),
        ed25519_public=dec.bytes_(),
        x25519_public=dec.bytes_(),
        created_at=dec.i64(),
        validation_deadline=dec.i64(),
        activation_time=dec.i64(),
        expiration_time=dec.i64(),
    )


def encode_registry_snapshot(entries: list[RegistryEntry]) -> bytes:
    enc = Encoder().u32(len(entries))
    for entry in entries:
        enc.bytes_(encode_registry_entry(entry))
    return enc.finish()


def parse_registry_snapshot(data: bytes) -> list[RegistryEntry]:
    dec = Decoder(data)
    count = dec.u32()
    entries: list[RegistryEntry] = []
    for _ in range(count):
        entries.append(parse_registry_entry(dec.bytes_()))
    if not dec.eof():
        raise DecodeError("trailing data in registry snapshot")
    return entries


_KIND_CODES: dict[str, int] = {"CLIENT": 1, "PROXY": 2, "SERVER": 3}


def kind_to_code(kind) -> int:
    name = kind.value if hasattr(kind, "value") else str(kind)
    code = _KIND_CODES.get(name)
    if code is None:
        raise ProtocolError(f"unknown identity kind {name}")
    return code


def kind_from_code(code: int):
    from .models import IdentityKind

    for name, c in _KIND_CODES.items():
        if c == code:
            return IdentityKind(name)
    raise ProtocolError(f"unknown identity kind code {code}")


# Numeric wire codes for credential statuses.
_STATUS_CODES: dict[str, int] = {
    "GENERATED": 0,
    "VALIDATING": 1,
    "ACTIVE": 2,
    "FALLBACK": 3,
    "EXPIRED": 4,
    "TERMINATED": 5,
    "REVOKED": 6,
}


def status_to_code(status) -> int:
    name = status.value if hasattr(status, "value") else str(status)
    code = _STATUS_CODES.get(name)
    if code is None:
        raise ProtocolError(f"unknown credential status {name}")
    return code


def status_from_code(code: int) -> str:
    for name, c in _STATUS_CODES.items():
        if c == code:
            return name
    raise ProtocolError(f"unknown status code {code}")


def registry_entry_from_public(cred) -> RegistryEntry:
    """Convert a CredentialPublic into a wire RegistryEntry."""
    return RegistryEntry(
        identity_uuid=cred.identity_uuid,
        version=cred.version,
        status=status_to_code(cred.status),
        ed25519_public=cred.ed25519_public,
        x25519_public=cred.x25519_public,
        created_at=cred.created_at,
        validation_deadline=cred.validation_deadline or 0,
        activation_time=cred.activation_time or 0,
        expiration_time=cred.expiration_time or 0,
    )


def encode_enrollment_body(
    identity_kind: int,
    token: str,
    version: int,
    ed25519_public: bytes,
    x25519_public: bytes,
) -> bytes:
    return (
        Encoder()
        .u8(identity_kind)
        .str_(token)
        .u32(version)
        .bytes_(ed25519_public)
        .bytes_(x25519_public)
        .finish()
    )


def parse_enrollment_body(data: bytes) -> tuple[int, str, int, bytes, bytes]:
    dec = Decoder(data)
    return (
        dec.u8(),
        dec.str_(),
        dec.u32(),
        dec.bytes_(),
        dec.bytes_(),
    )


# --------------------------------------------------------------------- #
# encrypted payload wrapper
# --------------------------------------------------------------------- #
# The primary-encrypted bytes inside an envelope are prefixed with the
# recipient's credential version so the recipient can pick the matching
# X25519 private key without guessing:
#
#   u32  recipient_credential_version
#   32B  ephemeral X25519 public key
#   12B  AES-GCM nonce            (message contexts only)
#   ...  ciphertext + tag

EPH_PUBLIC_SIZE = 32


def wrap_encrypted(
    recipient_credential_version: int,
    ephemeral_public: bytes,
    nonce: bytes,
    ciphertext: bytes,
) -> bytes:
    return (
        Encoder()
        .u32(recipient_credential_version)
        .bytes_(ephemeral_public)
        .bytes_(nonce)
        .bytes_(ciphertext)
        .finish()
    )


def unwrap_encrypted(data: bytes) -> tuple[int, bytes, bytes, bytes]:
    """Return (recipient_version, ephemeral_public, nonce, ciphertext)."""
    dec = Decoder(data)
    recipient_version = dec.u32()
    ephemeral_public = dec.bytes_()
    nonce = dec.bytes_()
    ciphertext = dec.bytes_()
    if not dec.eof():
        raise ProtocolError("trailing data in encrypted payload")
    return recipient_version, ephemeral_public, nonce, ciphertext


def wrap_encrypted_chunk(
    recipient_credential_version: int,
    object_uuid: uuid.UUID,
    chunk_index: int,
    ephemeral_public: bytes,
    ciphertext: bytes,
) -> bytes:
    """Chunk payload: object + index (for AAD/nonce), no explicit nonce."""
    return (
        Encoder()
        .u32(recipient_credential_version)
        .uuid_(object_uuid)
        .u64(chunk_index)
        .bytes_(ephemeral_public)
        .bytes_(ciphertext)
        .finish()
    )


def unwrap_encrypted_chunk(
    data: bytes,
) -> tuple[int, uuid.UUID, int, bytes, bytes]:
    """Return (recipient_version, object_uuid, chunk_index, ephemeral, ciphertext)."""
    dec = Decoder(data)
    recipient_version = dec.u32()
    object_uuid = dec.uuid_() or uuid.UUID(int=0)
    chunk_index = dec.u64()
    ephemeral_public = dec.bytes_()
    ciphertext = dec.bytes_()
    if not dec.eof():
        raise ProtocolError("trailing data in encrypted chunk payload")
    return recipient_version, object_uuid, chunk_index, ephemeral_public, ciphertext


# --------------------------------------------------------------------- #
# server application-identity update (piggybacked in responses)
# --------------------------------------------------------------------- #

def encode_server_key_info(
    version: int,
    ed25519_public: bytes,
    x25519_public: bytes,
    prev_version: int,
    successor_signature: bytes,
) -> bytes:
    return (
        Encoder()
        .u32(version)
        .bytes_(ed25519_public)
        .bytes_(x25519_public)
        .u32(prev_version)
        .bytes_(successor_signature)
        .finish()
    )


def parse_server_key_info(data: bytes) -> tuple[int, bytes, bytes, int, bytes]:
    dec = Decoder(data)
    return (
        dec.u32(),
        dec.bytes_(),
        dec.bytes_(),
        dec.u32(),
        dec.bytes_(),
    )


def encode_enroll_response(
    status: int,
    message: str,
    server_key_info: bytes,
) -> bytes:
    return (
        Encoder()
        .u8(status)
        .str_(message)
        .bytes_(server_key_info)
        .finish()
    )


def parse_enroll_response(data: bytes) -> tuple[int, str, bytes]:
    dec = Decoder(data)
    return dec.u8(), dec.str_(), dec.bytes_()
