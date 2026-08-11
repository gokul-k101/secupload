"""Proxy entry point: `uv run python -m sih_proxy`."""

from __future__ import annotations

import argparse
import logging
import sys
import threading

from sih_shared.tls import build_server_context

from .cache import RegistryCache
from .config import ProxyConfig
from .identity import ProxyIdentity
from .tunnel import ProxyServer, ensure_proxy_cert


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="sih_proxy", description="SRS v3.0 dual-tunnel secure proxy"
    )
    parser.add_argument("--listen-host", default=None)
    parser.add_argument("--listen-port", type=int, default=None)
    parser.add_argument("--server-host", default=None)
    parser.add_argument("--server-port", type=int, default=None)
    parser.add_argument("--server-cert", default=None)
    parser.add_argument("--server-uuid", default=None)
    parser.add_argument("--data-dir", default=None)
    parser.add_argument("--cert", default=None)
    parser.add_argument("--key", default=None)
    parser.add_argument(
        "--token", default=None,
        help="proxy enrollment token (fallback: SIH_ENROLLMENT_TOKEN)",
    )
    args = parser.parse_args(argv)

    config = ProxyConfig.from_env()
    if args.listen_host:
        config.proxy_host = args.listen_host
    if args.listen_port:
        config.proxy_port = args.listen_port
    if args.server_host:
        config.server_host = args.server_host
    if args.server_port:
        config.server_port = args.server_port
    if args.server_cert:
        config.server_cert_file = args.server_cert
    if args.server_uuid:
        import uuid

        config.server_uuid = uuid.UUID(args.server_uuid)
    if args.data_dir:
        config.data_dir = args.data_dir
    if args.cert:
        config.cert_file = args.cert
    if args.key:
        config.key_file = args.key
    if args.token:
        config.enrollment_token = args.token
    if not config.enrollment_token:
        parser.error("proxy enrollment token required (--token or SIH_ENROLLMENT_TOKEN)")

    logging.basicConfig(level=logging.INFO)

    cert_file, key_file = ensure_proxy_cert(config)
    ssl_context = build_server_context(cert_file, key_file)
    identity = ProxyIdentity(config)
    identity.ensure_loaded()
    cache = RegistryCache()
    server = ProxyServer(config, ssl_context, identity, cache)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    logging.info(
        "proxy listening on %s:%s -> server %s:%s",
        config.proxy_host,
        config.proxy_port,
        config.server_host,
        config.server_port,
    )
    try:
        thread.join()
    except KeyboardInterrupt:
        server.shutdown()
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())