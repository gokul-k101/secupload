"""Proxy transport: client-facing TLS endpoint and blind frame relay.

For every client connection the proxy opens one pinned TLS connection to
the server, performs its own pre-relay control burst (rotation check +
registry snapshot refresh), then splices the two sockets frame-by-frame
without inspecting payloads (SR-40: blind relay).
"""

from __future__ import annotations

import logging
import socketserver
import ssl
import threading
import time
from contextlib import suppress
from pathlib import Path

from sih_client.config import ClientConfig
from sih_client.session import ClientSession, ServerKeyState
from sih_shared.framing import (
    CHANNEL_CONTROL,
    FrameError,
    recv_frame,
    send_frame,
)
from sih_shared.models import IdentityKind
from sih_shared.protocol import ProtocolError, parse_envelope
from sih_shared.replay import timestamp_ok
from sih_shared.tls import generate_endpoint_cert, write_pem

from .cache import RegistryCache
from .config import ProxyConfig
from .identity import ProxyIdentity

log = logging.getLogger("sih.proxy.tunnel")


class ProxyError(Exception):
    pass


class _FrameValidator:
    """Client->server frame validation against the synchronized registry.

    The proxy verifies the client's Ed25519 envelope signatures (SRS 26,
    39) without touching the primary ciphertext: an identity present in
    the cached registry must authenticate with the matching credential
    version and a valid signature within the timestamp window, or the
    connection is dropped.  Unknown identities (e.g. first enrollment)
    are forwarded; the server remains authoritative.
    """

    def __init__(self, cache: RegistryCache) -> None:
        self._cache = cache

    def check(self, channel: int, payload: bytes) -> None:
        if channel == CHANNEL_CONTROL:
            # Control traffic (enroll, rotation requests, registry sync) is
            # authenticated server-side against the registry; only data
            # frames carry the client's signed envelope.
            return
        env = parse_envelope(payload)
        entry = self._cache.entry(env.sender_uuid)
        if entry is None:
            return
        if entry.version != env.sender_credential_version:
            raise ProxyError(
                "credential version mismatch for "
                f"{env.sender_uuid} (registry v{entry.version}, "
                f"envelope v{env.sender_credential_version})"
            )
        if not timestamp_ok(env.timestamp, int(time.time())):
            raise ProxyError("client envelope outside timestamp window")
        try:
            env.verify(entry.ed25519_public)
        except ProtocolError as exc:
            raise ProxyError(f"client signature invalid: {exc}") from exc


def _pump(src, dst, validator: _FrameValidator | None = None) -> None:
    """Copy frames from ``src`` to ``dst`` until either side closes."""
    while True:
        try:
            channel, payload = recv_frame(src)
        except (FrameError, ConnectionError, OSError):
            break
        if validator is not None:
            try:
                validator.check(channel, payload)
            except Exception as exc:
                log.warning("proxy frame validation failed: %s", exc)
                break
        try:
            send_frame(dst, channel, payload)
        except (FrameError, ConnectionError, OSError):
            break


def _capture_pump(src, dst, capture: list) -> None:
    """Copy frames, recording (channel, payload) copies for tests."""
    while True:
        try:
            channel, payload = recv_frame(src)
        except (FrameError, ConnectionError, OSError):
            break
        capture.append((channel, payload))
        try:
            send_frame(dst, channel, payload)
        except (FrameError, ConnectionError, OSError):
            break


def _splice(
    a,
    b,
    validator: _FrameValidator | None = None,
    capture: list | None = None,
) -> None:
    """Bidirectional relay; returns when either direction ends."""
    if capture is not None:
        t1 = threading.Thread(
            target=_capture_pump, args=(a, b, capture), daemon=True
        )
    else:
        t1 = threading.Thread(target=_pump, args=(a, b, validator), daemon=True)
    t2 = threading.Thread(target=_pump, args=(b, a), daemon=True)
    t1.start()
    t2.start()
    t1.join()
    t2.join()
    for sock in (a, b):
        with suppress(OSError):
            sock.close()


class ProxyTunnel:
    """One client connection relayed onto one server connection.

    The pre-relay control burst is serialized across connections with
    ``control_lock`` so the shared proxy identity never submits two
    successors concurrently.
    """

    def __init__(
        self,
        config: ProxyConfig,
        identity: ProxyIdentity,
        cache: RegistryCache,
        control_lock: threading.Lock | None = None,
        server_keys: ServerKeyState | None = None,
        now_seconds: float | None = None,
        capture: list | None = None,
    ) -> None:
        self._config = config
        self._identity = identity
        self._cache = cache
        self._control_lock = control_lock or threading.Lock()
        self._now_seconds = now_seconds
        self._capture = capture
        # shared across connections: enrollment populates it on the first
        # connection and later connections reuse the server's key info
        self._server_keys = server_keys or ServerKeyState()

    # ------------------------------------------------------------------ #

    def handle(self, client_sock) -> None:
        server_session: ClientSession | None = None
        try:
            with self._control_lock:
                server_session = self._open_server_connection()
                self._control_burst(server_session)
            validator = _FrameValidator(self._cache)
            _splice(
                server_session._sock,
                client_sock,
                validator=validator,
                capture=self._capture,
            )
        except Exception as exc:
            log.warning("relay ended: %s", exc)
            if server_session is not None:
                server_session.close()
            client_sock.close()

    def _open_server_connection(self) -> ClientSession:
        cfg = ClientConfig(
            proxy_host=self._config.server_host,
            proxy_port=self._config.server_port,
            server_uuid=self._config.server_uuid,
            data_dir=self._config.data_dir,
            enrollment_token=self._config.enrollment_token,
            rotation_duration=self._config.rotation_duration,
            tls_hostname=self._config.tls_hostname,
        )
        session = ClientSession(
            cfg,
            self._identity,
            server_keys=self._server_keys,
            kind=IdentityKind.PROXY,
            now_seconds=self._now_seconds,
        )
        server_cert = Path(self._config.server_cert_file).read_bytes()
        session.connect(server_cert)
        return session

    def _control_burst(self, session: ClientSession) -> None:
        """Proxy-side control traffic before the client's frames flow."""
        if self._identity.should_rotate():
            session.rotate()
            self._identity.checkpoint()
        client_entries = session.sync_registry(IdentityKind.CLIENT)
        proxy_entries = session.sync_registry(IdentityKind.PROXY)
        self._cache.update(client_entries + proxy_entries)


def ensure_proxy_cert(config: ProxyConfig) -> tuple[Path, Path]:
    """Generate the proxy's endpoint certificate on first run."""
    cert_file = config.cert_file or config.default_cert_file()
    key_file = config.key_file or config.default_key_file()
    if not cert_file.exists() or not key_file.exists():
        cert_pem, key_pem = generate_endpoint_cert("sih-proxy")
        write_pem(cert_file, cert_pem)
        write_pem(key_file, key_pem, private=True)
    return cert_file, key_file


class ProxyServer(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(
        self,
        config: ProxyConfig,
        ssl_context: ssl.SSLContext,
        identity: ProxyIdentity,
        cache: RegistryCache,
        control_lock: threading.Lock | None = None,
        now_seconds: float | None = None,
        capture: list | None = None,
    ) -> None:
        super().__init__((config.proxy_host, config.proxy_port), _Handler)
        self.proxy_config = config
        self.ssl_context = ssl_context
        self.proxy_identity = identity
        self.cache = cache
        self.control_lock = control_lock or threading.Lock()
        self.now_seconds = now_seconds
        self.capture = capture
        self.server_keys = ServerKeyState()


class _Handler(socketserver.StreamRequestHandler):
    def handle(self) -> None:  # type: ignore[override]
        server: ProxyServer = self.server  # type: ignore[assignment]
        try:
            tls_sock = server.ssl_context.wrap_socket(
                self.connection, server_side=True
            )
        except ssl.SSLError as exc:
            log.warning("client TLS handshake failed: %s", exc)
            return
        tunnel = ProxyTunnel(
            server.proxy_config,
            server.proxy_identity,
            server.cache,
            server.control_lock,
            server.server_keys,
            server.now_seconds,
            server.capture,
        )
        tunnel.handle(tls_sock)