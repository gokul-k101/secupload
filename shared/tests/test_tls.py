"""TLS tests: TLS 1.3 enforcement and endpoint-certificate pinning (spec 64)."""

from __future__ import annotations

import socket
import ssl
import threading
import uuid

import pytest
from sih_shared.tls import (
    TLS_HOSTNAME,
    build_client_context,
    build_server_context,
    cert_fingerprint,
    generate_endpoint_cert,
    write_pem,
)


class TLSResponder:
    """A tiny TLS server answering connections with the word 'hello'."""

    def __init__(self, certfile, keyfile) -> None:
        self._ctx = build_server_context(certfile, keyfile)
        self._thread: threading.Thread | None = None
        self.port: int | None = None
        self._stop = threading.Event()

    def __enter__(self) -> TLSResponder:
        self._ready = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()
        if not self._ready.wait(timeout=5):
            raise RuntimeError("TLS server failed to start")
        return self

    def __exit__(self, *exc) -> None:
        self._stop.set()
        self._thread.join(timeout=5)

    def _serve(self) -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as lsock:
            lsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            lsock.bind(("127.0.0.1", 0))
            lsock.listen(5)
            self.port = lsock.getsockname()[1]
            self._ready.set()
            lsock.settimeout(1)
            while not self._stop.is_set():
                try:
                    conn, _ = lsock.accept()
                except TimeoutError:
                    continue
                except OSError:
                    break
                self._handle(conn)

    def _handle(self, conn: socket.socket) -> None:
        try:
            with self._ctx.wrap_socket(conn, server_side=True) as tls_conn:
                tls_conn.sendall(b"hello")
                tls_conn.recv(1024)
        except (ssl.SSLError, OSError):
            pass


@pytest.fixture
def endpoint(tmp_path):
    cn = f"sih-endpoint-{uuid.uuid4()}"
    cert_pem, key_pem = generate_endpoint_cert(cn)
    certfile = tmp_path / "endpoint.crt"
    keyfile = tmp_path / "endpoint.key"
    write_pem(certfile, cert_pem)
    write_pem(keyfile, key_pem, private=True)
    return certfile, keyfile, cert_pem


def connect_pinned(port: int, cert_pem: bytes) -> str:
    """Connect with the pinned certificate; return the negotiated TLS version."""
    ctx = build_client_context(cert_pem)
    with socket.create_connection(("127.0.0.1", port), timeout=5) as raw:
        tls_conn = ctx.wrap_socket(raw, server_hostname=TLS_HOSTNAME)
        assert tls_conn.version() == "TLSv1.3"
        assert tls_conn.recv(1024) == b"hello"
        return tls_conn.version()


def test_tls13_enforcement(endpoint) -> None:
    certfile, keyfile, cert_pem = endpoint
    with TLSResponder(certfile, keyfile) as server:
        assert server.port is not None
        assert connect_pinned(server.port, cert_pem) == "TLSv1.3"


def test_pinned_cert_acceptance_and_unknown_rejection(endpoint) -> None:
    certfile, keyfile, cert_pem = endpoint
    with TLSResponder(certfile, keyfile) as server:
        assert server.port is not None
        assert connect_pinned(server.port, cert_pem) == "TLSv1.3"

        other_cert, _ = generate_endpoint_cert("sih-other")
        ctx_bad = build_client_context(other_cert)
        with (
            socket.create_connection(("127.0.0.1", server.port), timeout=5) as raw,
            pytest.raises(ssl.SSLCertVerificationError),
        ):
            ctx_bad.wrap_socket(raw, server_hostname=TLS_HOSTNAME)


def test_incorrect_endpoint_fingerprint_rejection(endpoint) -> None:
    certfile, keyfile, _ = endpoint
    with TLSResponder(certfile, keyfile) as server:
        assert server.port is not None
        # a fingerprint-mismatched pin (any other self-signed cert) fails
        wrong_cert, _ = generate_endpoint_cert("sih-wrong")
        with open(certfile, "rb") as fh:
            pinned_fp = cert_fingerprint(fh.read())
        assert cert_fingerprint(wrong_cert) != pinned_fp
        ctx = build_client_context(wrong_cert)
        with (
            socket.create_connection(("127.0.0.1", server.port), timeout=5) as raw,
            pytest.raises(ssl.SSLCertVerificationError),
        ):
            ctx.wrap_socket(raw, server_hostname=TLS_HOSTNAME)


def test_expired_certificate_rejection(tmp_path) -> None:
    expired_cert, expired_key = generate_endpoint_cert("sih-expired", days=-1)
    exp_certfile = tmp_path / "expired.crt"
    exp_keyfile = tmp_path / "expired.key"
    write_pem(exp_certfile, expired_cert)
    write_pem(exp_keyfile, expired_key, private=True)

    with TLSResponder(exp_certfile, exp_keyfile) as server:
        assert server.port is not None
        ctx = build_client_context(expired_cert)
        with (
            socket.create_connection(("127.0.0.1", server.port), timeout=5) as raw,
            pytest.raises(ssl.SSLCertVerificationError),
        ):
            ctx.wrap_socket(raw, server_hostname=TLS_HOSTNAME)


def test_certificate_fingerprint(endpoint) -> None:
    _, _, cert_pem = endpoint
    fp = cert_fingerprint(cert_pem)
    assert len(fp) == 64
    assert fp == cert_fingerprint(cert_pem)
    other_cert, _ = generate_endpoint_cert("sih-other")
    assert fp != cert_fingerprint(other_cert)
