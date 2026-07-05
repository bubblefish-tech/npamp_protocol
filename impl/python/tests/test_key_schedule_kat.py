"""Standards-derived, NON-CIRCULAR known-answer test for the draft-00 handshake key schedule
(binding spec/10 section 5; ML-KEM-first per ADR-0005; draft-00 7.4 HKDF-Expand-Label + 7.5 traffic
keys). Python mirror of the sibling KATs (transcript/finished/certverify) against the SAME pinned
vector (test-vectors/v1/key-schedule-kat.json). N-PAMP's HKDF-Expand-Label is RFC 8446 7.1 with the
prefix swapped from "tls13 " to "n-pamp " - so RFC 8448 (which uses "tls13 ") validates the
MECHANISM and the prefix is the only N-PAMP-original element.

NON-CIRCULARITY: this file stores NO golden N-PAMP output bytes. It proves an INDEPENDENT in-test
HKDF-Expand-Label oracle against published RFC vectors FIRST, then uses that proven oracle (applied
with the "n-pamp " prefix) to judge the implementation. Three legs:
  1. ANCHOR - raw HKDF-Extract/Expand (impl AND the in-test oracle primitives) reproduce RFC 5869
     Appendix A.1 TC1: Extract(salt,ikm)==prk and Expand(prk,info,L)==okm (trust the primitive).
  2. ORACLE - an INDEPENDENT HKDF-Expand-Label that re-derives the HkdfLabel bytes itself (prefix as
     a PARAMETER, NOT calling the impl's hkdf_expand_label) reproduces RFC 8448 section 3 key/iv/
     finished with the "tls13 " prefix (guards the oracle/mechanism against an external vector).
  3. IMPL   - the key-schedule trunk (hkdf_extract / derive_handshake_secret /
     derive_handshake_traffic_secrets / derive_finished_key) reproduces, byte-for-byte, the proven
     oracle applied with the "n-pamp " prefix to npamp_inputs; and the s2c handshake AEAD key/iv from
     derive_traffic_secret/derive_key_iv match the oracle-computed traffic key/iv.
"""
import os
import json
import hashlib
import hmac
import npamp as n

VEC = os.path.join(os.path.dirname(__file__), "..", "..", "..", "test-vectors", "v1")
KEY_SCHEDULE_KAT_SHA256 = "e108f5cfdf99a378d7b677792448c8046abf3c630fc23fd8ea2ccb3927f2691c"

# Direction byte (binding section 5 / 7.5 traffic context): ServerToClient = 1.
DIR_S2C = 1
# AES-256-GCM = 0x0001 per registries/aead.csv (= the impl's AEAD_AES256_GCM = npamp.AEADAES256GCM in
# the Go reference); 0x0002 is ChaCha20-Poly1305. The 7.5 traffic context binds this AEAD code point,
# so the KAT uses the impl's own n.AEAD_AES256_GCM constant directly (no magic literal) - the same
# symbol the sibling conformance test passes to derive_traffic_secret.


def _load():
    with open(os.path.join(VEC, "key-schedule-kat.json"), "rb") as fh:
        raw = fh.read()
    got = hashlib.sha256(raw).hexdigest()
    assert got == KEY_SCHEDULE_KAT_SHA256, f"key-schedule KAT vector SHA-256 mismatch (swapped vector?): {got}"
    return json.loads(raw)


def _hx(s):
    return bytes.fromhex(s)


# --- Independent in-test oracle primitives (stdlib hmac/hashlib only; no impl key-schedule code) ----

def _extract_oracle(salt, ikm):
    """HKDF-Extract (RFC 5869 2.2) = HMAC-SHA-256(salt, IKM). Standard profile is SHA-256."""
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def _expand_oracle(prk, info, length):
    """HKDF-Expand (RFC 5869 2.3) over SHA-256, independent of the impl."""
    hash_len = 32
    n_blocks = -(-length // hash_len)  # ceil
    t = b""
    out = b""
    for i in range(1, n_blocks + 1):
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        out += t
    return out[:length]


def _expand_label_oracle(secret, prefix, label, context, length):
    """HKDF-Expand-Label (RFC 8446 7.1) re-deriving the HkdfLabel bytes itself with the prefix as a
    PARAMETER. info = uint16(length) || uint8(len(prefix+label)) || prefix+label || uint8(len(context))
    || context. It MUST NOT call the impl's hkdf_expand_label - the two must agree independently.
    Built on _expand_oracle (anchored against RFC 5869 in the ANCHOR leg)."""
    full = (prefix + label).encode()
    info = length.to_bytes(2, "big") + bytes([len(full)]) + full + bytes([len(context)]) + context
    return _expand_oracle(secret, info, length)


def test_key_schedule_kat_rfc5869_anchor():
    """ANCHOR: raw HKDF-Extract/Expand (impl AND oracle) reproduce RFC 5869 Appendix A.1 TC1."""
    k = _load()
    tc = k["rfc5869_tc1"]
    salt, ikm, info, L = _hx(tc["salt"]), _hx(tc["ikm"]), _hx(tc["info"]), tc["L"]

    # Impl raw primitives.
    assert n.hkdf_extract(salt, ikm, True).hex() == tc["prk"], "impl hkdf_extract != RFC 5869 TC1 PRK"
    assert n.hkdf_expand(_hx(tc["prk"]), info, L, True).hex() == tc["okm"], "impl hkdf_expand != RFC 5869 TC1 OKM"

    # Oracle raw primitives (so the oracle's own raw layer is anchored before it judges anything).
    assert _extract_oracle(salt, ikm).hex() == tc["prk"], "oracle extract != RFC 5869 TC1 PRK"
    assert _expand_oracle(_hx(tc["prk"]), info, L).hex() == tc["okm"], "oracle expand != RFC 5869 TC1 OKM"


def test_key_schedule_kat_rfc8448_oracle():
    """ORACLE: the independent HKDF-Expand-Label reproduces RFC 8448 section 3 key/iv/finished
    ("tls13 " prefix), validating the label-byte construction + expand mechanism against an external
    vector. The oracle does NOT call the impl."""
    k = _load()
    v = k["rfc8448_expand_label"]
    secret = _hx(v["client_handshake_traffic_secret"])
    assert _expand_label_oracle(secret, "tls13 ", "key", b"", 16).hex() == v["write_key"], "oracle expandLabel key != RFC 8448"
    assert _expand_label_oracle(secret, "tls13 ", "iv", b"", 12).hex() == v["write_iv"], "oracle expandLabel iv != RFC 8448"
    assert _expand_label_oracle(secret, "tls13 ", "finished", b"", 32).hex() == v["finished_key"], "oracle expandLabel finished != RFC 8448"


def test_key_schedule_kat_impl():
    """IMPL: the key-schedule trunk reproduces the proven oracle applied with the "n-pamp " prefix to
    npamp_inputs; the s2c handshake AEAD key/iv match the oracle-computed traffic key/iv. No golden
    N-PAMP byte is hardcoded - every expectation is computed by the oracle proven in the legs above."""
    k = _load()
    nn = k["npamp_inputs"]
    assert nn["label_prefix"] == "n-pamp ", "vector label_prefix drifted from n-pamp"
    assert n.LABEL_PREFIX == "n-pamp ", "impl LABEL_PREFIX drifted from n-pamp"
    assert n.CHAN_CONTROL == 0x0000, "CHAN_CONTROL drifted from spec (Control channel)"

    mlkem_ss = _hx(nn["ikm_mlkem_ss"])    # ML-KEM shared secret (IKM), concatenated FIRST
    x25519_ss = _hx(nn["ikm_x25519_ss"])  # X25519 shared secret (IKM)
    th_kem = _hx(nn["th_kem"])
    th_ccv = _hx(nn["th_ccv"])
    PFX = "n-pamp "

    # handshake_secret = HKDF-Extract(salt = 32 zero octets, ML-KEM_SS || X25519_SS).
    zeros32 = b"\x00" * 32
    hs_oracle = _extract_oracle(zeros32, mlkem_ss + x25519_ss)
    hs_impl = n.derive_handshake_secret(mlkem_ss, x25519_ss, True)
    assert hs_impl.hex() == hs_oracle.hex(), "handshake_secret: impl != oracle"

    # Ladder: c_hs / s_hs bind TH_kem; master binds TH_ccv.
    c_hs_oracle = _expand_label_oracle(hs_oracle, PFX, "c hs", th_kem, 32)
    s_hs_oracle = _expand_label_oracle(hs_oracle, PFX, "s hs", th_kem, 32)
    master_oracle = _expand_label_oracle(hs_oracle, PFX, "master", th_ccv, 32)
    c_hs_impl, s_hs_impl, master_impl = n.derive_handshake_traffic_secrets(hs_impl, th_kem, th_ccv, True)
    assert c_hs_impl.hex() == c_hs_oracle.hex(), "c_hs: impl != oracle"
    assert s_hs_impl.hex() == s_hs_oracle.hex(), "s_hs: impl != oracle"
    assert master_impl.hex() == master_oracle.hex(), "master: impl != oracle"

    # finished_key(secret) = HKDF-Expand-Label(secret, "finished", "", 32). Client from c_hs, server from s_hs.
    fk_client_oracle = _expand_label_oracle(c_hs_oracle, PFX, "finished", b"", 32)
    fk_server_oracle = _expand_label_oracle(s_hs_oracle, PFX, "finished", b"", 32)
    assert n.derive_finished_key(c_hs_impl, True).hex() == fk_client_oracle.hex(), "finished_key(c_hs): impl != oracle"
    assert n.derive_finished_key(s_hs_impl, True).hex() == fk_server_oracle.hex(), "finished_key(s_hs): impl != oracle"

    # s2c handshake AEAD: traffic_secret from s_hs (dir=ServerToClient, epoch=0, suite=AES-256-GCM,
    # channel=Control), then key/iv. ctx = dir(1) || epoch(8 BE) || suite(2 BE) || channel(2 BE).
    ctx = bytes([DIR_S2C]) + (0).to_bytes(8, "big") + n.AEAD_AES256_GCM.to_bytes(2, "big") + n.CHAN_CONTROL.to_bytes(2, "big")
    traffic_oracle = _expand_label_oracle(s_hs_oracle, PFX, "traffic", ctx, 32)
    key_oracle = _expand_label_oracle(traffic_oracle, PFX, "key", b"", 32)
    iv_oracle = _expand_label_oracle(traffic_oracle, PFX, "iv", b"", 12)

    traffic_impl = n.derive_traffic_secret(s_hs_impl, DIR_S2C, 0, n.AEAD_AES256_GCM, n.CHAN_CONTROL, True)
    key_impl, iv_impl = n.derive_key_iv(traffic_impl, True)
    assert key_impl.hex() == key_oracle.hex(), "s2c handshake key: impl != oracle"
    assert iv_impl.hex() == iv_oracle.hex(), "s2c handshake iv: impl != oracle"


if __name__ == "__main__":
    fails = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"PASS {name}")
            except Exception as e:
                print(f"FAIL {name}: {e}")
                fails += 1
    raise SystemExit(1 if fails else 0)
