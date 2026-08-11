"""Tunnel 2 endpoint: TLS 1.3 server (port 8443).

The server accepts one connection per client (relayed by a proxy).  Each
connection carries two channels:

* channel 0 - control: enrollment (token-based, unauthenticated), credential
  rotation and registry sync (authenticated envelopes with encrypted payloads)
* channel 1 - relay: application envelopes (READ / WRITE requests)

Every authenticated message arrives inside a signed :class:`Envelope` whose
payload is primary-encrypted to the server's X25519 key.  Control responses
are sent as envelopes from the server, encrypted to the requester's current
X25519 key (spec sections 31-37).
"""

from __future__ import annotations

import logging
import os
import socketserver
import ssl
import threading
import time
import uuid
from functools import partial

from sih_shared.credential_state import (
    RotationError,
    parse_successor_payload,
)
from sih_shared.crypto import open_message, seal_chunk, seal_message
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
    RespStatus,
    build_aad,
    encode_control,
    encode_enroll_response,
    encode_registry_snapshot,
    encode_response_message,
    encode_server_key_info,
    kind_from_code,
    new_envelope,
    parse_control,
    parse_enrollment_body,
    parse_envelope,
    parse_request_message,
    registry_entry_from_public,
    unwrap_encrypted,
    wrap_encrypted,
    wrap_encrypted_chunk,
)

from . import audit as audit_mod
from .auth import Authenticator, AuthError
from .authorization import AuthorizationError, check_permission
from .config import ServerConfig
from .identity import ServerIdentity
from .objects import ObjectStore, ObjectStoreError
from .registry import CredentialRegistry, RegistryError

CHUNK_SIZE = 64 * 1024

log = logging.getLogger("sih.server.tunnel2")

NONCE_SIZE = 12


class Tunnel2Error(Exception):
    pass


def _decrypt_to(env: Envelope, x25519_private: bytes, sender_uuid: uuid.UUID) -> bytes:
    """Primary-decrypt an envelope payload addressed to ``sender``."""
    recipient_version, ephemeral, nonce, ciphertext = unwrap_encrypted(env.payload)
    if recipient_version != env.sender_credential_version:
        # the recipient's version is carried in the wrapping header; for the
        # server's own messages it must match the sender credential version
        pass
    aad = build_aad(
        env.sender_uuid,
        env.recipient_uuid,
        env.request_id,
        env.sender_credential_version,
        env.timestamp,
        env.nonce,
        0,
    )
    return open_message(x25519_private, ephemeral, nonce, aad, ciphertext)


def _decrypt_chunk_to(
    env: Envelope,
    x25519_private: bytes,
    payload: bytes,
) -> tuple[uuid.UUID, int, bytes]:
    """Primary-decrypt an OBJ_CHUNK payload.

    Returns (object_uuid, chunk_index, plaintext).
    """
    from sih_shared.crypto import open_chunk
    from sih_shared.protocol import unwrap_encrypted_chunk

    (
        recipient_version,
        object_uuid,
        chunk_index,
        ephemeral,
        ciphertext,
    ) = unwrap_encrypted_chunk(payload)
    aad = build_aad(
        env.sender_uuid,
        env.recipient_uuid,
        env.request_id,
        env.sender_credential_version,
        env.timestamp,
        env.nonce,
        chunk_index,
    )
    plaintext = open_chunk(
        x25519_private,
        object_uuid.bytes,
        chunk_index,
        aad,
        ephemeral,
        ciphertext,
    )
    return object_uuid, chunk_index, plaintext


class _Connection:
    """Stateful handling of a single client connection (via a proxy)."""

    def __init__(
        self,
        sock,
        server_identity: ServerIdentity,
        registry: CredentialRegistry,
        authenticator: Authenticator,
        objects: ObjectStore,
        audit: audit_mod.AuditLog,
        now_seconds: float | None = None,
    ) -> None:
        self.sock = sock
        self.server = server_identity
        self.registry = registry
        self.authenticator = authenticator
        self.objects = objects
        self.audit = audit
        self._now_seconds = now_seconds

    def _now(self) -> int:
        if callable(self._now_seconds):
            return int(self._now_seconds())
        return int(self._now_seconds if self._now_seconds is not None else time.time())

    # ------------------------------------------------------------------ #

    def run(self) -> None:
        try:
            while True:
                channel, payload = recv_frame(self.sock)
                if channel == CHANNEL_CONTROL:
                    self._handle_control(payload)
                elif channel == CHANNEL_RELAY:
                    self._handle_relay(payload)
                else:
                    raise Tunnel2Error(f"unknown channel {channel}")
        except (EOFError, ConnectionError, OSError, ssl.SSLError):
            log.debug("connection closed")
        except Tunnel2Error as exc:
            log.warning("tunnel2 protocol error: %s", exc)
        finally:
            self.sock.close()

    # ------------------------------------------------------------------ #
    # control channel
    # ------------------------------------------------------------------ #

    def _handle_control(self, payload: bytes) -> None:
        msg = parse_control(payload)
        ctype = msg.ctype
        if ctype == ControlType.ENROLL.value:
            self._handle_enroll(msg.body)
        elif ctype == ControlType.REGISTRY_SYNC_REQ.value:
            self._handle_authenticated(ctype, msg.body, self._handle_registry_sync)
        elif ctype == ControlType.ROTATE_SUBMIT.value:
            self._handle_authenticated(ctype, msg.body, self._handle_rotate_submit)
        elif ctype in (
            ControlType.ROTATE_CHECKPOINT.value,
            ControlType.ROTATE_ROLLBACK.value,
            ControlType.ROTATE_REVOKE.value,
        ):
            self._handle_authenticated(
                ctype, msg.body, partial(self._handle_rotate_action, ctype)
            )
        else:
            raise Tunnel2Error(f"unsupported control type {ctype}")

    def _handle_authenticated(self, ctype: int, body: bytes, handler) -> None:
        """Dispatch an authenticated control message.

        ``body`` is a signed envelope; its payload is primary-encrypted.
        ``handler(env, cred, inner_plaintext)`` returns the response inner
        plaintext, which is encrypted back to the sender.
        """
        try:
            env = parse_envelope(body)
        except Exception as exc:
            raise Tunnel2Error(f"malformed control envelope: {exc}") from exc
        kind, cred = self.authenticator.authenticate(env)
        _, x25519_priv = self.server.active_keys()
        try:
            inner = _decrypt_to(env, x25519_priv, env.sender_uuid)
        except Exception as exc:
            raise Tunnel2Error(f"control payload decrypt failed: {exc}") from exc
        try:
            response_inner = handler(env, cred, inner)
        except (RegistryError, RotationError) as exc:
            response_inner = encode_control(
                1, exc.message.encode() if hasattr(exc, "message") else str(exc).encode()
            )
        self._send_control_response(ctype, env, response_inner)

    def _handle_enroll(self, body: bytes) -> None:
        kind_code, token, version, ed25519_pub, x25519_pub = parse_enrollment_body(body)
        kind = kind_from_code(kind_code)
        identity_uuid = _token_identity(token, kind)
        try:
            self.registry.enroll(
                identity_uuid, kind, token, version, ed25519_pub, x25519_pub,
                self._now(),
            )
            server_cred = self.server.credential()
            key_info = encode_server_key_info(
                server_cred.version,
                server_cred.ed25519_public,
                server_cred.x25519_public,
                0,
                b"",
            )
            response = encode_enroll_response(RespStatus.OK, "enrolled", key_info)
        except RegistryError as exc:
            response = encode_enroll_response(
                RespStatus.ERROR, exc.message, b""
            )
        self._send_control_raw(ControlType.ENROLL_RESP.value, response)

    def _handle_registry_sync(self, env: Envelope, cred, inner: bytes) -> bytes:
        kind = kind_from_code(inner[0]) if inner else IdentityKind.CLIENT
        entries = [
            registry_entry_from_public(c)
            for c in self.registry.public_entries(kind)
        ]
        self.audit.record(
            audit_mod.EVENT_REGISTRY_SYNC, env.sender_uuid, cred.version
        )
        return encode_registry_snapshot(entries)

    def _handle_rotate_submit(self, env: Envelope, cred, inner: bytes) -> bytes:
        payload, signature = inner[:-64], inner[-64:]
        (
            payload_identity,
            old_version,
            new_version,
            new_ed25519,
            new_x25519,
            metadata,
        ) = parse_successor_payload(payload)
        if payload_identity != env.sender_uuid:
            raise RegistryError(
                "TOKEN_MISMATCH", "successor payload identity mismatch"
            )
        self.registry.submit_successor(
            env.sender_uuid,
            new_version,
            new_ed25519,
            new_x25519,
            signature,
            metadata,
            self._now(),
        )
        return encode_control(0, b"ok")

    def _handle_rotate_action(
        self, ctype: int, env: Envelope, cred, inner: bytes
    ) -> bytes:
        """Server-authoritative promotion/rollback/revocation (SR-07..10).

        The server uses its own clock to decide whether the promotion
        checkpoint has been reached; the requester cannot force early
        promotion (SR-08).
        """
        identity = env.sender_uuid
        now = self._now()
        if ctype == ControlType.ROTATE_CHECKPOINT.value:
            self.registry.checkpoint(identity, now)
        elif ctype == ControlType.ROTATE_ROLLBACK.value:
            self.registry.rollback(identity, now)
        elif ctype == ControlType.ROTATE_REVOKE.value:
            from sih_shared.codec import Decoder

            version = Decoder(inner).u32()
            self.registry.revoke(identity, version, now)
        else:  # pragma: no cover - dispatch is fixed above
            raise Tunnel2Error(f"unsupported rotation action {ctype}")
        return encode_control(0, b"ok")

    def _send_control_raw(self, ctype: int, plaintext: bytes) -> None:
        send_frame(self.sock, CHANNEL_CONTROL, encode_control(ctype, plaintext))

    def _send_control_response(self, request_ctype: int, req_env: Envelope, inner: bytes) -> None:
        """Reply with an envelope from the server, encrypted to the requester."""
        resp_ctype = _RESP_TYPE[request_ctype]
        server_cred = self.server.credential()
        client_cred = self.registry.get_credential(
            req_env.sender_uuid, req_env.sender_credential_version
        )
        if client_cred is None:
            raise Tunnel2Error("unknown sender credential for control response")
        envelope = self._build_outgoing(
            req_env,
            server_cred.version,
            inner,
            client_cred.x25519_public,
            encrypt=True,
        )
        self._send_control_raw(resp_ctype, envelope.encode())

    # ------------------------------------------------------------------ #
    # relay channel: application requests
    # ------------------------------------------------------------------ #

    def _handle_relay(self, payload: bytes) -> None:
        try:
            env = parse_envelope(payload)
        except Exception as exc:
            raise Tunnel2Error(f"malformed relay envelope: {exc}") from exc
        try:
            kind, cred = self.authenticator.authenticate(env)
            if env.msg_type == MsgType.OBJ_CHUNK.value:
                response = self._handle_obj_chunk(env, cred)
            else:
                response = self._dispatch(env, kind, cred)
        except (AuthError, AuthorizationError, ObjectStoreError) as exc:
            response = encode_response_message(
                _error_response(str(getattr(exc, "message", exc)))
            )
        except RegistryError as exc:
            response = encode_response_message(
                _error_response(exc.message)
            )
        server_cred = self.server.credential()
        client_cred = self.registry.get_credential(
            env.sender_uuid, env.sender_credential_version
        )
        if client_cred is None:
            raise Tunnel2Error("unknown sender credential for relay response")
        nonce = uuid.uuid4().bytes[:NONCE_SIZE]
        ts = self._now()
        if isinstance(response, tuple):
            # chunk reply: (OBJ_CHUNK, object_uuid, chunk_index, data)
            _, object_uuid, chunk_index, data = response
            aad = build_aad(
                self.server.uuid(),
                env.sender_uuid,
                env.request_id,
                server_cred.version,
                ts,
                nonce,
                chunk_index,
            )
            ephemeral, ciphertext = seal_chunk(
                client_cred.x25519_public,
                object_uuid.bytes,
                chunk_index,
                aad,
                data,
            )
            payload = wrap_encrypted_chunk(
                env.sender_credential_version,
                object_uuid,
                chunk_index,
                ephemeral,
                ciphertext,
            )
            reply = new_envelope(
                MsgType.OBJ_CHUNK.value,
                self.server.uuid(),
                env.sender_uuid,
                env.request_id,
                server_cred.version,
                ts,
                nonce,
                payload,
            )
            reply.sign(self.server.active_keys()[0])
            send_frame(self.sock, CHANNEL_RELAY, reply.encode())
            return
        reply = self._build_outgoing(
            env,
            server_cred.version,
            response,
            client_cred.x25519_public,
            encrypt=True,
            nonce=nonce,
            timestamp=ts,
        )
        send_frame(self.sock, CHANNEL_RELAY, reply.encode())

    def _handle_obj_chunk(self, env: Envelope, cred) -> bytes:
        """Append one encrypted chunk; finalize when the object is complete."""
        object_uuid, chunk_index, data = _decrypt_chunk_to(
            env, self.server.active_keys()[1], env.payload
        )
        with self.registry._session_factory() as session:
            check_permission(session, env.sender_uuid, object_uuid, "WRITE")
        self.objects.write_chunk(object_uuid, chunk_index, data)
        info = self.objects.info(object_uuid)
        if os.path.getsize(self.objects._path(object_uuid)) >= info.file_size:
            self.objects.finalize(object_uuid)
        self.audit.record(
            audit_mod.EVENT_OBJECT_ACCESS, env.sender_uuid, result="OK"
        )
        return encode_response_message(_info_response(info))

    def _dispatch(self, env: Envelope, kind: IdentityKind, cred):
        request = parse_request_message(
            _decrypt_to(env, self.server.active_keys()[1], env.sender_uuid)
        )
        if request.op == Op.WRITE.value:
            return self._handle_write(env, request)
        if request.op == Op.READ.value:
            return self._handle_read(env, request)
        if request.op == Op.READ_CHUNK.value:
            return self._handle_read_chunk(env, request)
        return encode_response_message(_error_response("unknown operation"))

    def _handle_write(self, env: Envelope, request):
        if request.object_uuid is None:
            raise ObjectStoreError("BAD_REQUEST", "WRITE requires object_uuid")
        with self.registry._session_factory() as session:
            check_permission(session, env.sender_uuid, request.object_uuid, "WRITE")
        info = self.objects.create(
            env.sender_uuid,
            request.object_uuid,
            request.file_type,
            request.file_size,
            request.metadata,
        )
        self.audit.record(
            audit_mod.EVENT_OBJECT_ACCESS, env.sender_uuid, result="OK"
        )
        return encode_response_message(
            _info_response(info)
        )

    def _handle_read(self, env: Envelope, request):

        if request.object_uuid is None:
            raise ObjectStoreError("BAD_REQUEST", "READ requires object_uuid")
        with self.registry._session_factory() as session:
            check_permission(session, env.sender_uuid, request.object_uuid, "READ")
        info = self.objects.info(request.object_uuid)
        self.audit.record(
            audit_mod.EVENT_OBJECT_ACCESS, env.sender_uuid, result="OK"
        )
        return encode_response_message(_info_response(info))

    def _handle_read_chunk(self, env: Envelope, request):
        """Return (OBJ_CHUNK, object_uuid, chunk_index, plaintext) so the
        relay path can re-encrypt with the response envelope's nonce."""
        if request.object_uuid is None:
            raise ObjectStoreError("BAD_REQUEST", "READ_CHUNK requires object_uuid")
        chunk_index = request.file_size
        with self.registry._session_factory() as session:
            check_permission(session, env.sender_uuid, request.object_uuid, "READ")
        data = self.objects.read_chunk(
            request.object_uuid, chunk_index, CHUNK_SIZE
        )
        if not data:
            raise ObjectStoreError("NOT_FOUND", "chunk index out of range")
        self.audit.record(
            audit_mod.EVENT_OBJECT_ACCESS, env.sender_uuid, result="OK"
        )
        return (MsgType.OBJ_CHUNK.value, request.object_uuid, chunk_index, data)

    # ------------------------------------------------------------------ #
    # outgoing envelope construction
    # ------------------------------------------------------------------ #

    def _build_outgoing(
        self,
        req_env: Envelope,
        server_version: int,
        inner: bytes,
        client_x25519_public: bytes,
        encrypt: bool,
        msg_type: int = MsgType.REQUEST.value,
        nonce: bytes | None = None,
        timestamp: int | None = None,
    ) -> Envelope:
        nonce = nonce or uuid.uuid4().bytes[:NONCE_SIZE]
        ts = timestamp if timestamp is not None else self._now()
        aad = build_aad(
            self.server.uuid(),
            req_env.sender_uuid,
            req_env.request_id,
            server_version,
            ts,
            nonce,
            0,
        )
        if encrypt:
            ephemeral, ciphertext = seal_message(
                client_x25519_public, nonce, aad, inner
            )
            payload = wrap_encrypted(
                req_env.sender_credential_version, ephemeral, nonce, ciphertext
            )
        else:
            payload = inner
        envelope = new_envelope(
            msg_type,
            self.server.uuid(),
            req_env.sender_uuid,
            req_env.request_id,
            server_version,
            ts,
            nonce,
            payload,
        )
        envelope.sign(self.server.active_keys()[0])
        return envelope


def _error_response(message: str):
    from sih_shared.protocol import ResponseMessage

    return ResponseMessage(status=RespStatus.ERROR, message=message)


def _info_response(info):
    from sih_shared.protocol import ResponseMessage

    return ResponseMessage(
        status=RespStatus.OK,
        object_uuid=info.object_uuid,
        file_type=info.file_type,
        file_size=info.file_size,
        content_integrity=info.content_integrity,
    )


def _token_identity(token: str, kind: IdentityKind) -> uuid.UUID:
    import hashlib

    prefix = b"proxy" if kind == IdentityKind.PROXY else b"client"
    digest = hashlib.sha256(prefix + token.encode()).hexdigest()
    return uuid.UUID(hex=digest[:32])


_RESP_TYPE: dict[int, int] = {
    ControlType.ENROLL.value: ControlType.ENROLL_RESP.value,
    ControlType.REGISTRY_SYNC_REQ.value: ControlType.REGISTRY_SYNC_RESP.value,
    ControlType.ROTATE_SUBMIT.value: ControlType.ROTATE_SUBMIT_RESP.value,
    ControlType.ROTATE_CHECKPOINT.value: ControlType.ROTATE_CHECKPOINT_RESP.value,
    ControlType.ROTATE_ROLLBACK.value: ControlType.ROTATE_ROLLBACK_RESP.value,
    ControlType.ROTATE_REVOKE.value: ControlType.ROTATE_REVOKE_RESP.value,
}


class Tunnel2Server(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(
        self,
        config: ServerConfig,
        registry: CredentialRegistry,
        authenticator: Authenticator,
        objects: ObjectStore,
        server_identity: ServerIdentity,
        ssl_context: ssl.SSLContext,
        now_seconds: float | None = None,
    ) -> None:
        super().__init__((config.tunnel2_host, config.tunnel2_port), _Handler)
        self.registry = registry
        self.authenticator = authenticator
        self.objects = objects
        self.server_identity = server_identity
        self.ssl_context = ssl_context
        self.audit = authenticator._audit
        self._now_seconds = now_seconds
        self._tick = threading.Thread(target=self._rotation_tick, daemon=True)

    def start_tick(self) -> None:
        self._tick.start()

    def _rotation_tick(self) -> None:
        interval = self.server_identity._config.rotation_tick
        while True:
            time.sleep(interval)
            try:
                self.server_identity.maybe_rotate()
            except Exception:
                log.exception("server identity rotation failed")


class _Handler(socketserver.StreamRequestHandler):
    def handle(self) -> None:  # type: ignore[override]
        server: Tunnel2Server = self.server  # type: ignore[assignment]
        try:
            tls_sock = server.ssl_context.wrap_socket(self.connection, server_side=True)
        except ssl.SSLError as exc:
            log.warning("TLS handshake failed: %s", exc)
            return
        conn = _Connection(
            tls_sock,
            server.server_identity,
            server.registry,
            server.authenticator,
            server.objects,
            server.audit,
            server._now_seconds,
        )
        conn.run()
