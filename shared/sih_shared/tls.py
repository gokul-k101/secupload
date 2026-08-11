"""TLS 1.3 transport helpers with explicit endpoint-certificate pinning.

mTLS is NOT used (SR-35).  TLS endpoint certificates are self-signed and
trusted exclusively through configured pins (SR-33, SR-37):

* the Client pins the Proxy endpoint certificate
* the Proxy pins the Server endpoint certificate

Pinning is implemented with standard TLS: the pinned certificate is loaded
as the trust anchor and the connection hostname matches the certificate's
SAN, so any presented certificate other than the pinned one fails
verification.  All contexts are restricted to TLS 1.3 (SR-21/22).
"""

from __future__ import annotations

import hashlib
import socket
import ssl
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

#: Hostname embedded in endpoint certificates; used as the TLS server name
#: so that hostname validation always matches and never depends on UUIDs.
TLS_HOSTNAME = "sih.local"

DEFAULT_CERT_DAYS = 365


def generate_endpoint_cert(
    cn: str,
    days: int = DEFAULT_CERT_DAYS,
) -> tuple[bytes, bytes]:
    """Generate a self-signed endpoint TLS certificate.

    Returns ``(cert_pem, key_pem)``.
    """
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = x509.random_serial_number()
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(now)
        .not_valid_before(_utc_days(-1))
        .not_valid_after(_utc_days(days))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True
        )
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(TLS_HOSTNAME)]), critical=False
        )
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    return cert_pem, key_pem


def _utc_days(days: int):
    import datetime

    return datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=days)


def cert_fingerprint(cert_pem: bytes) -> str:
    """SHA-256 fingerprint of a certificate (for pins and audit logs)."""
    cert = x509.load_pem_x509_certificate(cert_pem)
    return hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()


def _tls13_context(proto: int) -> ssl.SSLContext:
    ctx = ssl.SSLContext(proto)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    ctx.options |= ssl.OP_NO_COMPRESSION
    return ctx


def build_server_context(certfile: str | Path, keyfile: str | Path) -> ssl.SSLContext:
    """Server-side (Tunnel 1 endpoint, Tunnel 2 endpoint) TLS context.

    No client-certificate request: identity authentication happens at the
    application layer with Ed25519 credentials (SR-35).
    """
    ctx = _tls13_context(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(certfile), str(keyfile))
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def build_client_context(pinned_cert_pem: str | bytes) -> ssl.SSLContext:
    """Client-side TLS context that pins exactly one endpoint certificate.

    The pinned certificate is loaded as its own trust anchor; any other
    presented certificate fails verification (SR-37).
    """
    ctx = _tls13_context(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    cadata = (
        pinned_cert_pem.decode("ascii")
        if isinstance(pinned_cert_pem, bytes)
        else pinned_cert_pem
    )
    ctx.load_verify_locations(cadata=cadata)
    return ctx


def wrap_pinned(
    ctx: ssl.SSLContext,
    sock: socket.socket,
    server_hostname: str = TLS_HOSTNAME,
) -> ssl.SSLSocket:
    """Wrap a socket in TLS, verifying the peer against the pinned cert."""
    ssl_sock = ctx.wrap_socket(sock, server_hostname=server_hostname)
    if ssl_sock.version() != "TLSv1.3":
        ssl_sock.close()
        raise ConnectionError(f"peer did not negotiate TLS 1.3: {ssl_sock.version()}")
    return ssl_sock


def write_pem(path: str | Path, data: bytes, private: bool = False) -> None:
    """Atomically write PEM data with restrictive permissions."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_bytes(data)
    mode = 0o600 if private else 0o644
    tmp.chmod(mode)
    tmp.replace(path)
