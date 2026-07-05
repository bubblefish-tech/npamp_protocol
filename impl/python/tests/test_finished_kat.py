"""Standards-derived, NON-CIRCULAR known-answer test for the draft-00 Finished verify_data
(binding spec/10 section 6.2; RFC 8446 4.4.4): verify_data = HMAC(finished_key, transcript_hash)
under the profile hash (SHA-256 at Standard). Python mirror of the Go/TS reference tests against the
SAME pinned vector (test-vectors/v1/finished-kat.json).

Three legs: ANCHOR (HMAC-SHA-256 reproduces RFC 4231 TC1/TC2), ORACLE (independent hmac, no
compute_finished), IMPL (compute_finished + verify_finished accept/reject).
"""
import os
import json
import hashlib
import hmac
import npamp as n

VEC = os.path.join(os.path.dirname(__file__), "..", "..", "..", "test-vectors", "v1")
FINISHED_KAT_SHA256 = "25c21b0bd3b3b6b77862f4a819f81ff5e4ff42e4b1d70af81feeedc5aad73c7f"


def _load():
    with open(os.path.join(VEC, "finished-kat.json"), "rb") as fh:
        raw = fh.read()
    got = hashlib.sha256(raw).hexdigest()
    assert got == FINISHED_KAT_SHA256, f"Finished KAT vector SHA-256 mismatch (swapped vector?): {got}"
    return json.loads(raw)


def _hx(s):
    return bytes.fromhex(s)


def _hmac_oracle(key, data):
    """Standard HMAC-SHA-256, independent of compute_finished."""
    return hmac.new(key, data, hashlib.sha256).digest()


def test_finished_kat_rfc4231_anchor():
    k = _load()
    for label, tc in (("TC1", k["rfc4231_hmac_sha256"]["tc1"]), ("TC2", k["rfc4231_hmac_sha256"]["tc2"])):
        got = _hmac_oracle(_hx(tc["key"]), _hx(tc["data"])).hex()
        assert got == tc["hmac_sha256"], f"HMAC-SHA-256 {label} != RFC 4231\n  got  {got}\n  want {tc['hmac_sha256']}"


def test_finished_kat_oracle():
    k = _load()
    nn, e = k["npamp_inputs"], k["expected"]
    assert _hmac_oracle(_hx(nn["finished_key_server"]), _hx(nn["th_scv"])).hex() == e["verify_data_server"], "oracle server"
    assert _hmac_oracle(_hx(nn["finished_key_client"]), _hx(nn["th_ccv"])).hex() == e["verify_data_client"], "oracle client"


def test_finished_kat_impl():
    k = _load()
    nn, e = k["npamp_inputs"], k["expected"]
    for name, fk, th, want in (
        ("server", nn["finished_key_server"], nn["th_scv"], e["verify_data_server"]),
        ("client", nn["finished_key_client"], nn["th_ccv"], e["verify_data_client"]),
    ):
        fkb, thb, wantb = _hx(fk), _hx(th), _hx(want)
        assert n.compute_finished(fkb, thb, True).hex() == want, f"[{name}] compute_finished mismatch"
        assert n.verify_finished(fkb, thb, wantb, True), f"[{name}] verify_finished rejected the correct verify_data"
        bad = bytearray(wantb)
        bad[0] ^= 0x01
        assert not n.verify_finished(fkb, thb, bytes(bad), True), f"[{name}] verify_finished accepted a tampered verify_data"


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
