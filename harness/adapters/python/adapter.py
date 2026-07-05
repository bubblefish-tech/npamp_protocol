"""Reference npamp_00 conformance adapter (Python). A second-language "testee" proving
the runner is language-agnostic. Reads length-prefixed JSON requests {op,in} on stdin,
writes length-prefixed JSON responses {out|error|skipped} on stdout, performing the real
npamp_00 primitive for each op.

Windows note: uses the binary stdio buffers (text mode would corrupt the byte framing via
CRLF translation) and flushes after every response. Requires the `cryptography` package
for AES-256-GCM. Flag --break corrupts crc32c for the runner's mutation check.
"""
import hashlib
import hmac
import json
import struct
import sys

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

BREAK = "--break" in sys.argv[1:]


def _crc32c_table():
    poly = 0x82F63B78  # reflected Castagnoli
    tbl = []
    for i in range(256):
        crc = i
        for _ in range(8):
            crc = (crc >> 1) ^ (poly if (crc & 1) else 0)
        tbl.append(crc & 0xFFFFFFFF)
    return tbl


_TBL = _crc32c_table()


def crc32c(data: bytes) -> int:
    crc = 0xFFFFFFFF
    for b in data:
        crc = (crc >> 8) ^ _TBL[(crc ^ b) & 0xFF]
    return crc ^ 0xFFFFFFFF


def crc32c_hex(data: bytes) -> str:
    return crc32c(data).to_bytes(4, "big").hex()


def hkdf_expand(hashname, prk, info, length):
    h = hashlib.sha256 if hashname == "sha256" else hashlib.sha384
    out, t, i = b"", b"", 1
    while len(out) < length:
        t = hmac.new(prk, t + info + bytes([i]), h).digest()
        out += t
        i += 1
    return out[:length]


def hx(d, k):
    return bytes.fromhex(d.get(k, "") or "")


def handle(req):
    op = req.get("op")
    i = req.get("in", {})
    if op == "header.encode":
        h = bytearray(36)
        h[0:4] = b"NPAM"
        h[4] = ((int(i["ver"]) & 0x0F) << 4) | (int(i["flags"]) & 0x0F)
        h[5:7] = int(i["frameType"]).to_bytes(2, "big")
        h[7:9] = int(i["channel"]).to_bytes(2, "big")
        h[9:17] = int(i["seq"]).to_bytes(8, "big")
        h[17:21] = int(i["payloadLength"]).to_bytes(4, "big")
        h[21:25] = crc32c(bytes(h[0:21])).to_bytes(4, "big")
        return {"out": {"frame": bytes(h).hex()}}
    if op == "header.decode":
        b = hx(i, "frame")
        if len(b) != 36:
            return {"error": "malformed header length"}
        if b[0:4] != b"NPAM":
            return {"error": "bad magic"}
        if b[21:25] != crc32c(b[0:21]).to_bytes(4, "big"):
            return {"error": "crc32c mismatch"}
        if any(x != 0 for x in b[25:36]):
            return {"error": "reserved octet non-zero"}
        return {"out": {
            "magic": "NPAM", "ver": b[4] >> 4, "flags": b[4] & 0x0F,
            "frameType": int.from_bytes(b[5:7], "big"),
            "channel": int.from_bytes(b[7:9], "big"),
            "seq": int.from_bytes(b[9:17], "big"),
            "payloadLength": int.from_bytes(b[17:21], "big"),
            "crc32c": b[21:25].hex(), "reservedZero": True}}
    if op == "crc32c":
        c = "deadbeef" if BREAK else crc32c_hex(hx(i, "octets"))
        return {"out": {"crc32c": c}}
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
            sealed = AESGCM(hx(i, "key")).encrypt(hx(i, "nonce"), hx(i, "pt"), hx(i, "aad"))
        except Exception as e:
            return {"error": str(e)}
        return {"out": {"sealed": sealed.hex()}}
    if op == "aead.open":
        if i.get("suite") != "AES-256-GCM":
            return {"skipped": "suite not implemented: %s" % i.get("suite")}
        try:
            pt = AESGCM(hx(i, "key")).decrypt(hx(i, "nonce"), hx(i, "sealed"), hx(i, "aad"))
        except Exception:
            return {"error": "authentication failed"}
        return {"out": {"pt": pt.hex()}}
    if op == "hkdf.expand":
        hn = i.get("hash")
        if hn not in ("sha256", "sha384"):
            return {"skipped": "hash not implemented: %s" % hn}
        return {"out": {"okm": hkdf_expand(hn, hx(i, "prk"), hx(i, "info"), int(i["length"])).hex()}}
    if op == "profile.check":
        profile, kem = i.get("profile"), i.get("kem")
        if profile == "Sovereign" and kem == "X25519MLKEM768":
            return {"error": "Sovereign MUST NOT accept X25519MLKEM768"}
        if profile == "High" and kem == "X25519MLKEM768":
            return {"error": "High minimum KEM is X25519MLKEM1024"}
        return {"out": {"accepted": True}}
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
