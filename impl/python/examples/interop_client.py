# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""Live N-PAMP interop CLIENT (raw TCP).

Connects to an N-PAMP server, completes the client side of the 1.5-RTT
mutually-authenticated handshake (binding spec/10) via
``npamp.session.Session``, sends one AEAD-protected application frame on the
Memory channel, and verifies the server's echo. Interoperates with this
package's own ``interop_server.py`` (Python<->Python), the Go reference
harness ``impl/go/cmd/npamp-interop -role server`` (Go<->Python), or the Rust
reference example ``impl/rust/examples/interop_server`` (Rust<->Python) --
the same live, cross-process, non-shared-codebase unlock as the existing
Go<->Rust harness (``impl/go/cmd/npamp-interop/run-interop.sh``), closing the
Python leg's own deferred cross-process clause (a deferred cross-process interop item).

    pip install -e .[session]     # from impl/python, once
    python examples/interop_client.py 127.0.0.1:47700

Exit code 0 iff the handshake completes AND the server echo byte-matches the
sent payload. Transport: raw TCP -- the handshake is transport-agnostic (see
``npamp/session.py``'s module docstring); the Go SDK's TLS 1.3
(ALPN "n-pamp/3") transport binding is not exercised here.

The socket is wrapped UNBUFFERED (``buffering=0``): ``socket.makefile()``'s
default buffered mode needs an explicit ``flush()`` after every
``Session.send`` write, and a handshake/data frame left sitting in a
Python-side write buffer while the peer blocks on its own read would stall
the whole interop. ``buffering=0`` returns the raw ``SocketIO`` object
directly, so every ``transport.write()`` call reaches the wire immediately --
matching the blocking, unbuffered ``read(n)``/``write(data)`` contract
``npamp.session.Session.dial``/``accept``/``send``/``recv`` document.
"""
from __future__ import annotations

import os
import socket
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat  # noqa: E402

import npamp as n  # noqa: E402  (path bootstrap above)
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

    try:
        sock = socket.create_connection((host, port))
    except OSError as exc:
        print(f"interop_client: connect {addr}: {exc}", file=sys.stderr)
        return 1
    transport = sock.makefile("rwb", buffering=0)
    try:
        print(f"interop_client: connected to {addr}")

        identity = session.generate_identity()
        pub = identity.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        print(f"interop_client: identity ed25519 = {hex8(pub)}")

        try:
            sess = session.Session.dial(transport, identity)
        except session.SessionError as exc:
            print(f"interop_client: handshake failed: {exc}", file=sys.stderr)
            return 1
        print(
            "interop_client: handshake OK -- authenticated server ed25519 = "
            f"{hex8(sess.peer_identity())}"
        )

        payload = b"hello from the python interop client"
        try:
            sess.send(transport, n.CHAN_MEMORY, APP_FRAME_TYPE, 0, payload)
        except session.SessionError as exc:
            print(f"interop_client: send data: {exc}", file=sys.stderr)
            return 1
        print(f"interop_client: sent {len(payload)} octets on the Memory channel")

        try:
            channel, ftype, echo = sess.recv(transport, 0)
        except session.SessionError as exc:
            print(f"interop_client: recv echo: {exc}", file=sys.stderr)
            return 1
        print(
            f"interop_client: recv echo channel=0x{channel:04x} type=0x{ftype:04x} "
            f"payload={echo!r}"
        )

        if echo != payload:
            print("interop_client: FAIL -- echo did not match sent payload", file=sys.stderr)
            return 1
        print("interop_client: PASS -- live N-PAMP handshake + data frame round-trip verified")
        return 0
    finally:
        transport.close()
        sock.close()


if __name__ == "__main__":
    sys.exit(main())
