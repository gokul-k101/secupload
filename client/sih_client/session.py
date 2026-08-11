"""Client transport session.

Connects to the proxy over pinned TLS (the proxy's endpoint cert is the
sole trust anchor), enrolls on the control channel, and exchanges
signed+encrypted envelopes on the relay channel.  Server application
credential updates are adopted from piggybacked responses after the
chain-of-version check.
"""

from __future__ import annotations

import logging
import socket
import time
import uuid

from sih_shared.crypto import seal_chunk, seal_message
from sih_shared.framing import (
    CHANNEL_CONTROL,
    CHANNEL_RELAY,
    recv_frame,
    send_frame,
)
from sih_shared.models import IdentityKind
from sih_shared.protocol import (
    ControlType,
    Envelope,
    MsgType,
    Op,
    RegistryEntry,
    RequestMessage,
    ResponseMessage,
    build_aad,
    encode_control,
    encode_enrollment_body,
    encode_request_message,
    kind_to_code,
    new_envelope,
    parse_control,
    parse_enroll_response,
    parse_envelope,
    parse_response_message,
    parse_server_key_info,
    unwrap_encrypted,
    wrap_encrypted,
    wrap_encrypted_chunk,
)
from sih_shared.tls import build_client_context

from .config import ClientConfig
from .identity import ClientIdentity

log = logging.getLogger("sih.client.session")

NONCE_SIZE = 12
CHUNK_SIZE = 64 * 1024


class ClientError(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class ServerKeyState:
    """Tracked server application credential (enrollment + piggybacks)."""

    def __init__(self) -> None:
        self.version: int = 0
        self.ed25519_public: bytes = b""
        self.x25519_public: bytes = b""

    def set(self, version: int, ed25519_public: bytes, x25519_public: bytes) -> None:
        self.version = version
        self.ed25519_public = ed25519_public
        self.x25519_public = x25519_public


class ClientSession:
    """One persistent TLS connection through the proxy to the server."""

    def __init__(
        self,
        config: ClientConfig,
        identity: ClientIdentity,
        server_keys: ServerKeyState | None = None,
        kind: IdentityKind = IdentityKind.CLIENT,
        now_seconds: float | None = None,
    ) -> None:
        self._config = config
        self._identity = identity
        self._server_keys = server_keys or ServerKeyState()
        self._kind = kind
        self._now_seconds = now_seconds
        self._sock: socket.socket | None = None

    def _now(self) -> int:
        if callable(self._now_seconds):
            return int(self._now_seconds())
        return int(self._now_seconds if self._now_seconds is not None else time.time())

    # ------------------------------------------------------------------ #
    # connection lifecycle
    # ------------------------------------------------------------------ #

    def connect(self, proxy_cert_pem: bytes) -> None:
        self._identity.ensure_loaded()
        ctx = build_client_context(proxy_cert_pem)
        raw = socket.create_connection(
            (self._config.proxy_host, self._config.proxy_port), timeout=10
        )
        self._sock = ctx.wrap_socket(raw, server_hostname=self._config.tls_hostname)
        self._sock.settimeout(30)
        if not self._identity._enrolled:
            self._enroll()

    def close(self) -> None:
        if self._sock is not None:
            self._sock.close()
        self._sock = None

    def __enter__(self) -> ClientSession:
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # ------------------------------------------------------------------ #
    # enrollment
    # ------------------------------------------------------------------ #

    def _enroll(self) -> None:
        if not self._config.enrollment_token:
            raise ClientError(
                "NO_TOKEN", "enrollment token required (SIH_ENROLLMENT_TOKEN)"
            )
        cred = self._identity.current()
        body = encode_enrollment_body(
            kind_to_code(self._kind),
            self._config.enrollment_token,
            cred.version,
            cred.ed25519_public,
            cred.x25519_public,
        )
        ctype, resp = self._control(ControlType.ENROLL.value, body)
        if ctype != ControlType.ENROLL_RESP.value:
            raise ClientError("BAD_PROTOCOL", "unexpected control response")
        status, message, key_info = parse_enroll_response(resp)
        if status != 0:
            raise ClientError("ENROLL_REJECTED", message)
        version, ed_pub, x_pub, _, _ = parse_server_key_info(key_info)
        self._server_keys.set(version, ed_pub, x_pub)
        self._identity.mark_enrolled()

    def sync_registry(
        self, kind: IdentityKind = IdentityKind.CLIENT
    ) -> list[RegistryEntry]:
        """Fetch the server's public registry snapshot (REGISTRY_SYNC_REQ).

        Used by the proxy to maintain its snapshot cache; returns the
        decoded wire entries.
        """
        from sih_shared.protocol import (
            kind_to_code,
            parse_registry_snapshot,
        )

        inner = bytes([kind_to_code(kind)])
        env = self._signed_envelope(
            MsgType.CONTROL.value, self._server_keys.version, inner
        )
        ctype, resp = self._control(ControlType.REGISTRY_SYNC_REQ.value, env.encode())
        if ctype != ControlType.REGISTRY_SYNC_RESP.value:
            raise ClientError("BAD_PROTOCOL", "unexpected control response")
        resp_env = parse_envelope(resp)
        plain = self._decrypt_control_response(resp_env)
        return parse_registry_snapshot(plain)

    # ------------------------------------------------------------------ #
    # rotation
    # ------------------------------------------------------------------ #

    def rotate(self) -> None:
        """Submit a successor; on success the credential enters VALIDATING
        and is checkpointed once the server's window passes."""
        new_cred, signature, payload = self._identity.generate_successor()
        env = self._signed_envelope(
            MsgType.CONTROL.value, self._server_keys.version, payload + signature
        )
        ctype, resp = self._control(ControlType.ROTATE_SUBMIT.value, env.encode())
        if ctype != ControlType.ROTATE_SUBMIT_RESP.value:
            raise ClientError("BAD_PROTOCOL", "unexpected control response")
        resp_env = parse_envelope(resp)
        inner = self._decrypt_control_response(resp_env)
        status, message = parse_status_inner(inner)
        if status != 0:
            self._identity.rollback()
            raise ClientError(
                "ROTATE_REJECTED", message.decode("utf-8", "replace")
            )
        self._identity.checkpoint()

    def checkpoint_rotation(self) -> bool:
        """Ask the server to promote the validating credential (SR-08).

        The server promotes only once its own clock has passed T/2;
        returns True when promoted, False when the window has not closed
        (the scheduler retries).
        """
        env = self._signed_envelope(
            MsgType.CONTROL.value, self._server_keys.version, b""
        )
        ctype, resp = self._control(
            ControlType.ROTATE_CHECKPOINT.value, env.encode()
        )
        if ctype != ControlType.ROTATE_CHECKPOINT_RESP.value:
            raise ClientError("BAD_PROTOCOL", "unexpected control response")
        resp_env = parse_envelope(resp)
        inner = self._decrypt_control_response(resp_env)
        status, message = parse_status_inner(inner)
        if status != 0:
            return False
        self._identity.checkpoint()
        return True

    def rollback_rotation(self) -> None:
        """Terminate the validating credential on the server (SR-10).

        V2 remains ACTIVE; the client mirrors the rollback locally.
        """
        env = self._signed_envelope(
            MsgType.CONTROL.value, self._server_keys.version, b""
        )
        ctype, resp = self._control(
            ControlType.ROTATE_ROLLBACK.value, env.encode()
        )
        if ctype != ControlType.ROTATE_ROLLBACK_RESP.value:
            raise ClientError("BAD_PROTOCOL", "unexpected control response")
        resp_env = parse_envelope(resp)
        inner = self._decrypt_control_response(resp_env)
        status, message = parse_status_inner(inner)
        if status != 0:
            raise ClientError(
                "ROTATE_REJECTED", message.decode("utf-8", "replace")
            )
        self._identity.rollback()

    # ------------------------------------------------------------------ #
    # control helpers
    # ------------------------------------------------------------------ #

    def _sock_required(self) -> socket.socket:
        if self._sock is None:
            raise ClientError("NOT_CONNECTED", "call connect() first")
        return self._sock

    def _control(self, ctype: int, body: bytes) -> tuple[int, bytes]:
        sock = self._sock_required()
        send_frame(sock, CHANNEL_CONTROL, encode_control(ctype, body))
        channel, payload = recv_frame(sock)
        if channel != CHANNEL_CONTROL:
            raise ClientError("BAD_CHANNEL", "expected control frame")
        msg = parse_control(payload)
        return msg.ctype, msg.body

    def _decrypt_control_response(self, env: Envelope) -> bytes:
        from sih_shared.crypto import open_message

        recipient_version, ephemeral, nonce, ciphertext = unwrap_encrypted(env.payload)
        aad = build_aad(
            env.sender_uuid,
            env.recipient_uuid,
            env.request_id,
            env.sender_credential_version,
            env.timestamp,
            env.nonce,
            0,
        )
        return open_message(
            self._identity.current_keys()[1], ephemeral, nonce, aad, ciphertext
        )

    # ------------------------------------------------------------------ #
    # application requests
    # ------------------------------------------------------------------ #

    def request(
        self,
        op: int,
        object_uuid: uuid.UUID | None = None,
        file_type: str = "",
        file_size: int = 0,
        metadata: str = "",
    ) -> ResponseMessage:
        inner = encode_request_message(
            RequestMessage(op, object_uuid, file_type, file_size, metadata)
        )
        env = self._signed_envelope(
            MsgType.REQUEST.value, self._server_keys.version, inner
        )
        sock = self._sock_required()
        send_frame(sock, CHANNEL_RELAY, env.encode())
        return self._recv_relay_response()

    def send_chunk(
        self,
        object_uuid: uuid.UUID,
        chunk_index: int,
        data: bytes,
    ) -> ResponseMessage:
        ts = int(time.time())
        nonce = uuid.uuid4().bytes[:NONCE_SIZE]
        request_id = uuid.uuid4()
        env = self._signed_envelope(
            MsgType.OBJ_CHUNK.value,
            self._server_keys.version,
            b"",
            encrypt=False,
            request_id=request_id,
            timestamp=ts,
            nonce=nonce,
        )
        aad = build_aad(
            self._identity.identity_uuid(),
            self._config.server_uuid,
            request_id,
            env.sender_credential_version,
            ts,
            nonce,
            chunk_index,
        )
        ephemeral, ciphertext = seal_chunk(
            self._server_keys.x25519_public,
            object_uuid.bytes,
            chunk_index,
            aad,
            data,
        )
        env.payload = wrap_encrypted_chunk(
            self._server_keys.version,
            object_uuid,
            chunk_index,
            ephemeral,
            ciphertext,
        )
        env.sign(self._identity.current_keys()[0])
        sock = self._sock_required()
        send_frame(sock, CHANNEL_RELAY, env.encode())
        return self._recv_relay_response()

    def request_chunk(self, object_uuid: uuid.UUID, chunk_index: int) -> bytes:
        """Request one object chunk; returns b'' when out of range."""
        from sih_shared.crypto import open_chunk
        from sih_shared.protocol import unwrap_encrypted_chunk

        inner = encode_request_message(
            RequestMessage(
                Op.READ_CHUNK.value,
                object_uuid=object_uuid,
                file_size=chunk_index,
            )
        )
        env = self._signed_envelope(
            MsgType.REQUEST.value, self._server_keys.version, inner
        )
        sock = self._sock_required()
        send_frame(sock, CHANNEL_RELAY, env.encode())
        channel, payload = recv_frame(sock)
        if channel != CHANNEL_RELAY:
            raise ClientError("BAD_CHANNEL", "expected relay frame")
        resp_env = parse_envelope(payload)
        if resp_env.msg_type != MsgType.OBJ_CHUNK.value:
            plain = self._decrypt_relay_response(resp_env)
            response = parse_response_message(plain)
            raise ClientError("CHUNK_READ_REJECTED", response.message)
        (
            recipient_version,
            obj,
            resp_index,
            ephemeral,
            ciphertext,
        ) = unwrap_encrypted_chunk(resp_env.payload)
        if obj != object_uuid or resp_index != chunk_index:
            raise ClientError("BAD_CHUNK", "chunk identity mismatch")
        aad = build_aad(
            resp_env.sender_uuid,
            resp_env.recipient_uuid,
            resp_env.request_id,
            resp_env.sender_credential_version,
            resp_env.timestamp,
            resp_env.nonce,
            chunk_index,
        )
        return open_chunk(
            self._identity.current_keys()[1],
            object_uuid.bytes,
            chunk_index,
            aad,
            ephemeral,
            ciphertext,
        )

    def _recv_relay_response(self) -> ResponseMessage:
        sock = self._sock_required()
        channel, payload = recv_frame(sock)
        if channel != CHANNEL_RELAY:
            raise ClientError("BAD_CHANNEL", "expected relay frame")
        resp_env = parse_envelope(payload)
        plain = self._decrypt_relay_response(resp_env)
        response = parse_response_message(plain)
        self._adopt_piggyback(response)
        return response

    # ------------------------------------------------------------------ #
    # envelope plumbing
    # ------------------------------------------------------------------ #

    def _signed_envelope(
        self,
        msg_type: int,
        server_version: int,
        inner: bytes,
        encrypt: bool = True,
        request_id: uuid.UUID | None = None,
        timestamp: int | None = None,
        nonce: bytes | None = None,
    ) -> Envelope:
        ident = self._identity
        request_id = request_id or uuid.uuid4()
        ts = timestamp if timestamp is not None else self._now()
        nonce = nonce or uuid.uuid4().bytes[:NONCE_SIZE]
        if encrypt:
            aad = build_aad(
                ident.identity_uuid(),
                self._config.server_uuid,
                request_id,
                ident.current().version,
                ts,
                nonce,
                0,
            )
            ephemeral, ciphertext = seal_message(
                self._server_keys.x25519_public, nonce, aad, inner
            )
            payload = wrap_encrypted(server_version, ephemeral, nonce, ciphertext)
        else:
            payload = inner
        env = new_envelope(
            msg_type,
            ident.identity_uuid(),
            self._config.server_uuid,
            request_id,
            ident.current().version,
            ts,
            nonce,
            payload,
        )
        env.sign(ident.current_keys()[0])
        return env

    def _decrypt_relay_response(self, env: Envelope) -> bytes:
        from sih_shared.crypto import open_message

        recipient_version, ephemeral, nonce, ciphertext = unwrap_encrypted(env.payload)
        aad = build_aad(
            env.sender_uuid,
            env.recipient_uuid,
            env.request_id,
            env.sender_credential_version,
            env.timestamp,
            env.nonce,
            0,
        )
        return open_message(
            self._identity.current_keys()[1], ephemeral, nonce, aad, ciphertext
        )

    def _adopt_piggyback(self, response: ResponseMessage) -> None:
        if response.server_key_version:
            self._server_keys.set(
                response.server_key_version,
                response.server_ed25519_public,
                response.server_x25519_public,
            )


def parse_status_inner(inner: bytes) -> tuple[int, bytes]:
    """(status, message) from an encoded ROTATE_*_RESP inner body."""
    from sih_shared.codec import Decoder

    dec = Decoder(inner)
    status = dec.u8()
    message = dec.bytes_()
    return status, message
