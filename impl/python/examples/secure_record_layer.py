"""Runnable example: the draft-00 secure record layer, end to end.

Composes the OPEN-protocol primitives this port provides - the HKDF key
schedule, the AES-256-GCM record layer, and the 36-octet frame codec - into one
send -> receive round-trip over an in-memory "wire". Mirrors the Go reference's
Example_secureRecordLayer (impl/go/example_test.go).

The master secret is a fixed demo value; in a live session it is the handshake
output (binding spec/10 section 5). Standard profile only (SHA-256,
AES-256-GCM). Run from impl/python:

    python examples/secure_record_layer.py
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

import npamp as n  # noqa: E402  (path bootstrap above)

DIR_CLIENT_TO_SERVER = 0  # direction octet (draft-00 7.5)


def main():
    # 1. Key schedule: derive a per-(direction, channel, suite) traffic key + IV
    #    from the master secret. In a live session the master secret is the
    #    handshake output; here it is fixed so the example is deterministic.
    master = bytes([0x2B]) * 32
    ts = n.derive_traffic_secret(master, DIR_CLIENT_TO_SERVER, 0, n.AEAD_AES256_GCM, n.CHAN_MEMORY, True)
    key, iv = n.derive_key_iv(ts, True)

    # 2. Sender: seal an application payload into an AEAD-protected frame on the
    #    Memory channel. The AEAD associated data is the 21-octet header prefix,
    #    so the ciphertext is bound to the frame's type/channel/seq/length - a
    #    tampered header makes the open fail.
    app_type = 0x0120  # application frame type (app-defined; this port is wire-only)
    plaintext = b"hello over n-pamp"
    seq = 0
    out = n.Frame(ftype=app_type, channel=n.CHAN_MEMORY, seq=seq, flags=n.FLAG_ENC)
    aad = out.header_prefix(len(plaintext) + 16)  # +16 = AES-256-GCM authentication tag
    out.payload = n.seal_aes256gcm(key, iv, seq, aad, plaintext)
    wire = out.marshal()

    # 3. ... the `wire` bytes travel over any transport (the consumer supplies TCP/TLS) ...

    # 4. Receiver: parse the frame (validates CRC32C/magic/version) and open the
    #    payload under the same key/seq and the reconstructed header-prefix AAD.
    inc = n.Frame.unmarshal(wire)
    raad = inc.header_prefix(len(inc.payload))
    opened = n.open_aes256gcm(key, iv, inc.seq, raad, inc.payload)

    print("channel=%d seq=%d encrypted=%s" % (inc.channel, inc.seq, "true" if inc.flags & n.FLAG_ENC else "false"))
    print("recovered: %s" % opened.decode())
    return 0 if opened == plaintext else 1


if __name__ == "__main__":
    raise SystemExit(main())
