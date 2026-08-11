"""Length-prefixed framing over TLS sockets.

Frame layout:

    u8  channel  (0 = control, 1 = relayed application traffic)
    u32 length   (big-endian)
    ... payload

A single Tunnel 2 connection multiplexes the control channel and relayed
client traffic; Tunnel 1 connections always use the relay channel.
"""

from __future__ import annotations

import socket
import struct

CHANNEL_CONTROL = 0
CHANNEL_RELAY = 1

_FRAME_HEADER = struct.Struct(">BI")
MAX_FRAME_SIZE = 64 * 1024 * 1024  # 64 MiB safety cap


class FrameError(ConnectionError):
    pass


def send_frame(sock: socket.socket, channel: int, payload: bytes) -> None:
    if len(payload) > MAX_FRAME_SIZE:
        raise FrameError("frame too large")
    try:
        sock.sendall(_FRAME_HEADER.pack(channel, len(payload)) + payload)
    except OSError as exc:
        raise FrameError(f"send failed: {exc}") from exc


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < n:
        try:
            part = sock.recv(n - len(chunks))
        except TimeoutError:
            raise FrameError("recv timed out") from None
        except OSError as exc:
            raise FrameError(f"recv failed: {exc}") from exc
        if not part:
            raise FrameError("connection closed by peer")
        chunks += part
    return bytes(chunks)


def recv_frame(sock: socket.socket) -> tuple[int, bytes]:
    """Return (channel, payload).  Raises FrameError on EOF or errors."""
    header = _recv_exact(sock, _FRAME_HEADER.size)
    channel, length = _FRAME_HEADER.unpack(header)
    if length > MAX_FRAME_SIZE:
        raise FrameError("frame too large")
    payload = _recv_exact(sock, length)
    return channel, payload
