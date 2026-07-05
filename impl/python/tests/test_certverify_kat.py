"""Standards-derived, NON-CIRCULAR known-answer test for the draft-00 CertVerify (binding spec/10
section 6.1; RFC 8446 4.4.3 structure; Ed25519 per RFC 8032). The value is
u16(0x0807) | Ed25519(priv, signing_input), signing_input = 64*0x20 | context | 0x00 | TH. Python
mirror of the Go/TS reference tests against the SAME pinned vector (test-vectors/v1/certverify-kat.json).

Three legs: ANCHOR (the src Ed25519 helpers reproduce RFC 8032 TEST1/TEST2 keys + signatures),
ORACLE (rebuild signing_input by hand + sign with an independently-constructed key, no src signing
functions), IMPL (cert_verify_signing_input + sign_cert_verify reproduce the vector; verify_cert_verify
accepts the correct value but rejects a role/context mismatch, a wrong transcript, a wrong scheme, and
a truncated signature).
"""
import os
import json
import hashlib
import npamp as n
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

VEC = os.path.join(os.path.dirname(__file__), "..", "..", "..", "test-vectors", "v1")
CERTVERIFY_KAT_SHA256 = "f56ec6ba250ba8f8c6c84214a16f580a3e476e9b2cfd05720c3352de299fe555"


def _load():
    with open(os.path.join(VEC, "certverify-kat.json"), "rb") as fh:
        raw = fh.read()
    got = hashlib.sha256(raw).hexdigest()
    assert got == CERTVERIFY_KAT_SHA256, f"CertVerify KAT vector SHA-256 mismatch (swapped vector?): {got}"
    return json.loads(raw)


def _hx(s):
    return bytes.fromhex(s)


def _raw_pub(priv):
    return priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


# Oracle signing-input + key, independent of the src signing functions.
def _oracle_priv(seed):
    return ed25519.Ed25519PrivateKey.from_private_bytes(seed)


def _oracle_signing_input(ctx, th):
    return b"\x20" * 64 + ctx.encode() + b"\x00" + th


def test_certverify_kat_rfc8032_anchor():
    k = _load()
    for label, v in (("TEST1", k["rfc8032_ed25519"]["test1"]), ("TEST2", k["rfc8032_ed25519"]["test2"])):
        priv = n.ed25519_private_key_from_seed(_hx(v["seed"]))
        assert _raw_pub(priv).hex() == v["public_key"], f"{label} derived pubkey != RFC 8032"
        assert priv.sign(_hx(v["message"])).hex() == v["signature"], f"{label} signature != RFC 8032"
        # ed25519_public_key_from_raw round-trips for verification (raises on failure).
        n.ed25519_public_key_from_raw(_hx(v["public_key"])).verify(_hx(v["signature"]), _hx(v["message"]))


def test_certverify_kat_oracle():
    k = _load()
    nn, e, c = k["npamp_inputs"], k["expected"], k["contexts"]
    for name, ctx, seed, th, want_si, want_sig in (
        ("server", c["server"], nn["server_seed"], nn["th_sid"], e["signing_input_server"], e["signature_server"]),
        ("client", c["client"], nn["client_seed"], nn["th_cid"], e["signing_input_client"], e["signature_client"]),
    ):
        si = _oracle_signing_input(ctx, _hx(th))
        assert si.hex() == want_si, f"[{name}] oracle signing_input != vector"
        assert _oracle_priv(_hx(seed)).sign(si).hex() == want_sig, f"[{name}] oracle signature != vector"


def test_certverify_kat_impl():
    k = _load()
    nn, e, c = k["npamp_inputs"], k["expected"], k["contexts"]
    assert n.CONTEXT_SERVER_CERTVERIFY == c["server"], "server context constant drifted from spec 6.1"
    assert n.CONTEXT_CLIENT_CERTVERIFY == c["client"], "client context constant drifted from spec 6.1"
    for name, is_server, seed, pub_hex, th, want_si, want_val in (
        ("server", True, nn["server_seed"], nn["server_pub"], nn["th_sid"], e["signing_input_server"], e["certverify_value_server"]),
        ("client", False, nn["client_seed"], nn["client_pub"], nn["th_cid"], e["signing_input_client"], e["certverify_value_client"]),
    ):
        priv = n.ed25519_private_key_from_seed(_hx(seed))
        pub = n.ed25519_public_key_from_raw(_hx(pub_hex))
        thb = _hx(th)

        assert n.cert_verify_signing_input(is_server, thb).hex() == want_si, f"[{name}] cert_verify_signing_input != vector"
        val = n.sign_cert_verify(priv, is_server, thb)
        assert val.hex() == want_val, f"[{name}] sign_cert_verify value != vector"

        assert n.verify_cert_verify(pub, is_server, thb, val), f"[{name}] verify_cert_verify rejected the correct value"
        # Domain separation: the opposite role must FAIL (different context string).
        assert not n.verify_cert_verify(pub, not is_server, thb, val), f"[{name}] accepted a role/context mismatch"
        # Transcript binding: a different transcript hash must FAIL.
        wrong = bytearray(thb)
        wrong[0] ^= 0x01
        assert not n.verify_cert_verify(pub, is_server, bytes(wrong), val), f"[{name}] accepted a wrong transcript hash"
        # Scheme guard: a non-Ed25519 scheme code point must FAIL.
        bad_scheme = bytearray(val)
        bad_scheme[0:2] = (0x0905).to_bytes(2, "big")
        assert not n.verify_cert_verify(pub, is_server, thb, bytes(bad_scheme)), f"[{name}] accepted a non-Ed25519 scheme"
        # Length guard: an Ed25519 signature is exactly 64 octets; a truncated value must FAIL.
        assert not n.verify_cert_verify(pub, is_server, thb, val[:-1]), f"[{name}] accepted a truncated signature"


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
