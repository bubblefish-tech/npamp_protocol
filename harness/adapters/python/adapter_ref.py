"""N-PAMP conformance adapter (Python) wired to the OPEN reference implementation.

This is a "testee" for npamp-conform. It reads length-prefixed JSON requests
{op,in} on stdin and writes length-prefixed JSON responses {out|error|skipped}
on stdout. Unlike the stdlib template, every cryptographic / wire primitive here
is performed by calling the reference package at impl/python (`import npamp`),
not by a fresh reimplementation:

  - npamp.crc32c            -> crc32c, header.encode CRC, header.decode CRC check
  - npamp.Frame.header_prefix -> header.encode octet layout
  - npamp.seal_aes256gcm    -> aead.seal  (called with seq=0 so derive_nonce(nonce,0)==nonce)
  - npamp.open_aes256gcm    -> aead.open  (same nonce trick)
  - npamp.hkdf_expand       -> hkdf.expand (standard=True->SHA-256, False->SHA-384)

tlv.decode is a pure wire-format parse not exposed as a standalone function in the
reference package, so it is implemented inline per the spec's TLV rules. profile.check
is absent from the reference package and is returned as {"skipped": ...}.

Windows: binary stdio buffers (text mode would corrupt the byte framing via CRLF
translation) and an explicit flush after every response.
"""
from __future__ import annotations

import json
import os
import struct
import sys

# Wire this adapter to the reference implementation at impl/python.
_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_IMPL_PYTHON = os.path.normpath(
    os.path.join(_THIS_DIR, "..", "..", "..", "impl", "python")
)
if _IMPL_PYTHON not in sys.path:
    sys.path.insert(0, _IMPL_PYTHON)

import npamp  # reference implementation (impl/python/npamp)


def hx(d, k):
    return bytes.fromhex(d.get(k, "") or "")


def handle(req):
    op = req.get("op")
    i = req.get("in", {})

    if op == "header.encode":
        # Reference layout via Frame.header_prefix + reference crc32c.
        f = npamp.Frame(
            ftype=int(i["frameType"]),
            channel=int(i["channel"]),
            seq=int(i["seq"]),
            flags=int(i["flags"]),
            version=int(i["ver"]),
        )
        prefix = f.header_prefix(int(i["payloadLength"]))  # 21 octets, reference layout
        frame = bytearray(npamp.HEADER_SIZE)               # 36, octets 25..36 reserved zero
        frame[0:21] = prefix
        frame[21:25] = npamp.crc32c(prefix).to_bytes(4, "big")  # reference CRC32C
        return {"out": {"frame": bytes(frame).hex()}}

    if op == "header.decode":
        b = hx(i, "frame")
        if len(b) != npamp.HEADER_SIZE:
            return {"error": "malformed header length"}
        if b[0:4] != npamp.MAGIC:
            return {"error": "bad magic"}
        if b[21:25] != npamp.crc32c(b[0:21]).to_bytes(4, "big"):  # reference CRC32C check
            return {"error": "crc32c mismatch"}
        if any(x != 0 for x in b[25:36]):
            return {"error": "reserved octet non-zero"}
        return {"out": {
            "magic": "NPAM",
            "ver": b[4] >> 4,
            "flags": b[4] & 0x0F,
            "frameType": int.from_bytes(b[5:7], "big"),
            "channel": int.from_bytes(b[7:9], "big"),
            "seq": int.from_bytes(b[9:17], "big"),
            "payloadLength": int.from_bytes(b[17:21], "big"),
            "crc32c": b[21:25].hex(),
            "reservedZero": True,
        }}

    if op == "crc32c":
        return {"out": {"crc32c": npamp.crc32c(hx(i, "octets")).to_bytes(4, "big").hex()}}

    if op == "tlv.decode":
        b = hx(i, "tlv")
        if len(b) < 4:
            return {"error": "truncated tlv"}
        typ = int.from_bytes(b[0:2], "big")
        length = int.from_bytes(b[2:4], "big")
        if typ & 0x8000:
            return {"error": "unknown forward-incompatible TLV (high bit set)"}
        if length != len(b) - 4:
            return {"error": "tlv length mismatch"}
        return {"out": {"type": typ, "length": length, "value": b[4:].hex()}}

    if op == "aead.seal":
        if i.get("suite") != "AES-256-GCM":
            return {"skipped": "suite not implemented: %s" % i.get("suite")}
        try:
            # seq=0 => derive_nonce(nonce, 0) == nonce, so the reference sealer uses
            # the exact contract nonce.
            sealed = npamp.seal_aes256gcm(
                hx(i, "key"), hx(i, "nonce"), 0, hx(i, "aad"), hx(i, "pt")
            )
        except Exception as e:  # noqa: BLE001
            return {"error": str(e)}
        return {"out": {"sealed": sealed.hex()}}

    if op == "aead.open":
        if i.get("suite") != "AES-256-GCM":
            return {"skipped": "suite not implemented: %s" % i.get("suite")}
        try:
            pt = npamp.open_aes256gcm(
                hx(i, "key"), hx(i, "nonce"), 0, hx(i, "aad"), hx(i, "sealed")
            )
        except Exception:  # noqa: BLE001
            return {"error": "authentication failed"}
        return {"out": {"pt": pt.hex()}}

    if op == "hkdf.expand":
        hn = i.get("hash")
        if hn == "sha256":
            standard = True
        elif hn == "sha384":
            standard = False
        else:
            return {"skipped": "hash not implemented: %s" % hn}
        okm = npamp.hkdf_expand(hx(i, "prk"), hx(i, "info"), int(i["length"]), standard)
        return {"out": {"okm": okm.hex()}}

    if op == "profile.check":
        return {"skipped": "profile.check not implemented in reference package"}

    return {"skipped": "op not implemented: %s" % op}


def main():
    rd, wr = sys.stdin.buffer, sys.stdout.buffer
    while True:
        lp = rd.read(4)
        if len(lp) < 4:
            return
        n = struct.unpack("<I", lp)[0]
        body = rd.read(n)
        try:
            resp = handle(json.loads(body))
        except Exception as e:  # noqa: BLE001
            resp = {"error": "adapter exception: %s" % e}
        ob = json.dumps(resp).encode()
        wr.write(struct.pack("<I", len(ob)))
        wr.write(ob)
        wr.flush()


if __name__ == "__main__":
    main()
