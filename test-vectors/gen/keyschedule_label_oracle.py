#!/usr/bin/env python3
# Independent HKDF-Expand-Label + traffic-key oracle + conformance-vector generator (TRACK C6).
#
# Emits two op-groups the pre-C6 corpus never graded:
#   hkdf.expand_label -- the TLS-1.3-style HKDF-Expand-Label (RFC 8446 §7.1) with the N-PAMP label
#                        prefix "n-pamp " (spec/10 §5, spec/06 §"Key Derivation"). The pre-existing
#                        hkdf.expand op grades only RAW RFC 5869 Expand; it never wraps the label
#                        structure or the "n-pamp " prefix, which is exactly the interop-critical,
#                        N-PAMP-original element (a literal "tls13 " prefix is non-conformant).
#   keys.derive_traffic -- the full §5 traffic-key derivation: traffic_secret =
#                        HKDF-Expand-Label(master,"traffic", dir||epoch||suite||channel, HashLen),
#                        then (key,iv) = (ExpandLabel(ts,"key","",32), ExpandLabel(ts,"iv","",12)).
#                        The per-(direction,epoch,suite,channel) context binding was ungraded as an op.
#
# NON-CIRCULARITY (test-vectors/README.md; 55_conformance_requirements.md §5.2; ADR-0008):
#   ANCHOR-based, like key-schedule-kat.json. The HKDF here is implemented from RFC 5869 §2.2/§2.3
#   over Python's stdlib hmac + hashlib (an independent HMAC-SHA-256/384, RFC 2104) -- NOT
#   impl/go/crypto/hkdf. Before emitting any "n-pamp " vector the oracle PROVES its own mechanism:
#     (1) raw HKDF-Extract/Expand == RFC 5869 Appendix-A.1 TC1 (known PRK/OKM), and
#     (2) HKDF-Expand-Label with prefix "tls13 " == RFC 8448 §3 (known write_key/write_iv/finished_key).
#   Only then does it apply the SAME proven constructor with prefix "n-pamp " to produce the emitted
#   expected bytes. So the expected values trace to RFC 5869 + RFC 8446/8448, never to impl/go. The
#   MUST-reject (length > 255*HashLen) is the RFC 5869 §2.3 bound; the prefix-discriminator vector's
#   bytes are reproducible ONLY with "n-pamp ", so a "tls13 " impl fails it.
#
# Run: python3 test-vectors/gen/keyschedule_label_oracle.py -> hkdf.expand_label/keys.derive_traffic JSON.
import json, sys, hmac, hashlib

# ---------- independent HKDF (RFC 5869) over stdlib hmac/hashlib ----------
HASHES = {"sha256": hashlib.sha256, "sha384": hashlib.sha384}

def hkdf_extract(h, salt, ikm):
    return hmac.new(salt, ikm, h).digest()

def hkdf_expand(h, prk, info, length):
    hlen = h().digest_size
    if length > 255 * hlen:
        raise ValueError("HKDF-Expand: length %d exceeds 255*HashLen=%d" % (length, 255 * hlen))
    t, okm, i = b"", b"", 0
    while len(okm) < length:
        i += 1
        t = hmac.new(prk, t + info + bytes([i]), h).digest()
        okm += t
    return okm[:length]

def expand_label(h, secret, prefix, label, context, length):
    full = (prefix + label).encode("ascii")
    info = length.to_bytes(2, "big") + bytes([len(full)]) + full + bytes([len(context)]) + context
    return hkdf_expand(h, secret, info, length)

def hx(b): return b.hex()
def uh(s): return bytes.fromhex(s)

# ---------- self-proof: mechanism == RFC 5869 TC1 and RFC 8448 (independent of "n-pamp ") ----------
def prove_oracle():
    # RFC 5869 Appendix A.1 Test Case 1 (SHA-256).
    prk = hkdf_extract(hashlib.sha256, uh("000102030405060708090a0b0c"), b"\x0b" * 22)
    assert prk == uh("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"), "RFC5869 PRK"
    okm = hkdf_expand(hashlib.sha256, prk, uh("f0f1f2f3f4f5f6f7f8f9"), 42)
    assert okm == uh("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"), "RFC5869 OKM"
    # RFC 8448 §3 HKDF-Expand-Label with prefix "tls13 " (SHA-256).
    chts = uh("b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21")
    assert expand_label(hashlib.sha256, chts, "tls13 ", "key", b"", 16) == uh("dbfaa693d1762c5b666af5d950258d01"), "RFC8448 key"
    assert expand_label(hashlib.sha256, chts, "tls13 ", "iv", b"", 12) == uh("5bd3c71b836e0b76bb73265f"), "RFC8448 iv"
    assert expand_label(hashlib.sha256, chts, "tls13 ", "finished", b"", 32) == uh("b80ad01015fb2f0bd65ff7d4da5d6bf83f84821d1f87fdc7d3c75b5a7b42d9c4"), "RFC8448 finished"

prove_oracle()  # aborts the generator if the mechanism is wrong; only a proven oracle emits vectors.

NPAMP = "n-pamp "

# ---------- hkdf.expand_label vectors (prefix "n-pamp ") ----------
SECRET32 = bytes(range(32))
SECRET48 = bytes(range(48))
TH_KEM = uh("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")

def el(tcid, req, comment, hashname, secret, label, context, length, result, flags=None):
    h = HASHES[hashname]
    o = {"tcId": tcid, "requirement": req, "comment": comment,
         "in": {"hash": hashname, "secret": hx(secret), "label": label,
                "context": hx(context), "length": length}, "result": result}
    if result == "valid":
        o["expected"] = {"out": hx(expand_label(h, secret, NPAMP, label, context, length))}
    if flags is not None:
        o["flags"] = flags
    return o

expand_label_tests = [
    el(1, "10/5/expand-label-prefix-discriminator", "'key'(32): expected bytes require the 'n-pamp ' prefix; a 'tls13 ' impl fails",
       "sha256", SECRET32, "key", b"", 32, "valid", ["LabelPrefixDiscriminator"]),
    el(2, "10/5/expand-label-iv", "'iv'(12) derivation, empty context",
       "sha256", SECRET32, "iv", b"", 12, "valid"),
    el(3, "10/6.2/expand-label-finished", "'finished'(HashLen) key, empty context",
       "sha256", SECRET32, "finished", b"", 32, "valid"),
    el(4, "10/5/expand-label-with-context", "'c hs' with a 32-octet transcript context (TH_kem)",
       "sha256", SECRET32, "c hs", TH_KEM, 32, "valid"),
    el(5, "10/5/expand-label-sha384", "SHA-384 path (High/Sovereign): 'master'(48), empty context",
       "sha384", SECRET48, "master", b"", 48, "valid"),
    el(6, "10/5/expand-label-length-MUST-reject", "length > 255*HashLen (8161 > 255*32) MUST be rejected (RFC 5869 §2.3)",
       "sha256", SECRET32, "key", b"", 255 * 32 + 1, "invalid", ["MustReject", "HkdfLengthExceeded"]),
]

# ---------- traffic.keyiv vectors (spec/10 §5 context layout) ----------
def traffic_ctx(dir_, epoch, suite, channel):
    return bytes([dir_]) + epoch.to_bytes(8, "big") + suite.to_bytes(2, "big") + channel.to_bytes(2, "big")

def traffic_keyiv(hashname, master, dir_, epoch, suite, channel):
    h = HASHES[hashname]
    ts = expand_label(h, master, NPAMP, "traffic", traffic_ctx(dir_, epoch, suite, channel), h().digest_size)
    key = expand_label(h, ts, NPAMP, "key", b"", 32)
    iv = expand_label(h, ts, NPAMP, "iv", b"", 12)
    return key, iv

def tk(tcid, req, comment, profile, hashname, master, dir_, epoch, suite, channel, flags=None):
    key, iv = traffic_keyiv(hashname, master, dir_, epoch, suite, channel)
    o = {"tcId": tcid, "requirement": req, "comment": comment,
         "in": {"profile": profile, "master": hx(master), "dir": dir_, "epoch": epoch,
                "suite": suite, "channel": channel},
         "expected": {"key": hx(key), "iv": hx(iv)}, "result": "valid"}
    if flags is not None:
        o["flags"] = flags
    return o

MASTER_STD = bytes(range(32))
MASTER_HIGH = bytes(range(48))
SUITE_AESGCM, SUITE_CHACHA = 0x0001, 0x0002
CH_CONTROL, CH_MEMORY, CH_STREAM = 0x0000, 0x0001, 0x000C

traffic_tests = [
    tk(1, "10/5/traffic-c2s-control", "Standard C2S, epoch 0, AES-256-GCM, Control channel",
       "Standard", "sha256", MASTER_STD, 0, 0, SUITE_AESGCM, CH_CONTROL),
    tk(2, "10/5/traffic-dir-discriminator", "same tuple, S2C direction -> different (key,iv) (direction binding)",
       "Standard", "sha256", MASTER_STD, 1, 0, SUITE_AESGCM, CH_CONTROL, ["DirectionDiscriminator"]),
    tk(3, "10/5/traffic-channel-discriminator", "same tuple, Memory channel -> different (key,iv) (channel binding)",
       "Standard", "sha256", MASTER_STD, 0, 0, SUITE_AESGCM, CH_MEMORY, ["ChannelDiscriminator"]),
    tk(4, "10/5/traffic-epoch-suite-binding", "epoch 5 + ChaCha20-Poly1305 + Stream channel (epoch/suite binding)",
       "Standard", "sha256", MASTER_STD, 0, 5, SUITE_CHACHA, CH_STREAM),
    tk(5, "10/5/traffic-sha384-high", "High profile SHA-384 traffic secret -> 32-octet key, 12-octet iv",
       "High", "sha384", MASTER_HIGH, 0, 0, SUITE_AESGCM, CH_CONTROL),
]

groups = [
    {"op": "hkdf.expand_label", "profile": "any", "tests": expand_label_tests},
    {"op": "keys.derive_traffic", "profile": "any", "tests": traffic_tests},
]
json.dump(groups, sys.stdout, indent=2)
sys.stdout.write("\n")
