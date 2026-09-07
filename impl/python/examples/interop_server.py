# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""Live N-PAMP interop SERVER (raw TCP).

Listens on an address, accepts one connection, completes the server side of
the 1.5-RTT mutually-authenticated N-PAMP handshake (binding spec/10) via
``npamp.session.Session``, then receives one AEAD-protected application frame
on the Memory channel and echoes it back under the server-to-client key.
Interoperates with this package's own ``interop_client.py`` (Python<->Python),
the Go reference harness ``impl/go/cmd/npamp-interop -role client``
(Go<->Python), or the Rust reference example
``impl/rust/examples/interop_client`` (Rust<->Python).

    pip install -e .[session]     # from impl/python, once
    python examples/interop_server.py 127.0.0.1:47700

Transport: the N-PAMP handshake is transport-agnostic; this example runs it
directly over TCP, UNBUFFERED (see ``interop_client.py``'s module docstring
for why -- a buffered ``makefile`` write left unflushed while the peer blocks
on its own read would stall the whole interop). The Go SDK's TLS 1.3
(ALPN "n-pamp/3") transport binding is layered by ``sdk.Dial``/``sdk.Listen``
and is not exercised here.
"""
from __future__ import annotations

import os
import socket
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat  # noqa: E402

from npamp import session  # noqa: E402

APP_FRAME_TYPE = 0x0120  # application-defined frame type (matches the Go/Rust examples)
DEFAULT_ADDR = "127.0.0.1:47700"


def hex8(b: bytes) -> str:
    """First 8 octets of `b`, hex-encoded -- matches the Go/Rust examples'
    `hex8` truncated-identity log helper."""
    return b[:8].hex()


def _split_addr(addr: str) -> tuple[str, int]:
    host, _, port_s = addr.rpartition(":")
    if not host or not port_s.isdigit():
        raise ValueError(f"address must be host:port, got {addr!r}")
    return host, int(port_s)


def main(argv: "list[str] | None" = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    addr = argv[0] if argv else DEFAULT_ADDR
    host, port = _split_addr(addr)

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        listener.bind((host, port))
    except OSError as exc:
        print(f"interop_server: bind {addr}: {exc}", file=sys.stderr)
        return 1
    listener.listen(1)
    bound = listener.getsockname()
    print(f"interop_server: listening on {bound[0]}:{bound[1]}")

    identity = session.generate_identity()
    pub = identity.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    print(f"interop_server: identity ed25519 = {hex8(pub)}")

    try:
        conn, peer = listener.accept()
    except OSError as exc:
        print(f"interop_server: accept: {exc}", file=sys.stderr)
        return 1
    finally:
        listener.close()
    print(f"interop_server: accepted {peer[0]}:{peer[1]}")

    transport = conn.makefile("rwb", buffering=0)
    try:
        try:
            sess = session.Session.accept(transport, identity)
        except session.SessionError as exc:
            print(f"interop_server: handshake failed: {exc}", file=sys.stderr)
            return 1
        print(
            "interop_server: handshake OK -- authenticated client ed25519 = "
            f"{hex8(sess.peer_identity())}"
        )

        try:
            channel, ftype, pt = sess.recv(transport, 0)
        except session.SessionError as exc:
            print(f"interop_server: recv data frame: {exc}", file=sys.stderr)
            return 1
        print(f"interop_server: recv channel=0x{channel:04x} type=0x{ftype:04x} payload={pt!r}")

        try:
            sess.send(transport, channel, APP_FRAME_TYPE, 0, pt)
        except session.SessionError as exc:
            print(f"interop_server: echo data frame: {exc}", file=sys.stderr)
            return 1
        print("interop_server: echoed payload back; interop OK")
        return 0
    finally:
        transport.close()
        conn.close()


if __name__ == "__main__":
    sys.exit(main())
