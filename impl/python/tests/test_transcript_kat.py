"""Standards-derived, NON-CIRCULAR known-answer test for the draft-00 transcript construction
(binding spec/10 section 3). Python mirror of the Go/TS reference tests against the SAME pinned,
FIPS-180-4-anchored vector (test-vectors/v1/transcript-kat.json).

Three legs: ANCHOR (SHA-256("abc") == FIPS 180-4), ORACLE (in-test manual byte-constructor, no
Transcript), IMPL (the real Transcript). Run directly (PYTHONPATH=impl/python) or via pytest.

Absorption is driven straight from the vector's frame/TLV order; the cut points are encoded as a
(frame index, TLV index) map -> transcript-hash name, which IS the spec section 3 structure:
  - SERVER_HELLO (frame 1) final TLV  -> TH_kem
  - SERVER_AUTH  (frame 2) TLV 0 / 1  -> TH_sId / TH_sCV (TH_sCV excludes the frame's Finished TLV)
  - CLIENT_AUTH  (frame 3) TLV 0 / 1  -> TH_cId / TH_cCV (TH_cCV excludes the frame's Finished TLV)
"""
import os
import json
import hashlib
import npamp as n

VEC = os.path.join(os.path.dirname(__file__), "..", "..", "..", "test-vectors", "v1")
TRANSCRIPT_KAT_SHA256 = "fab6d852497b6ff56405595e9a014d0c45cabc5cde80a60a17444b337d556ee5"

# (frame index, TLV index within that frame) -> transcript-hash point name.
CUT_POINTS = {(1, 4): "th_kem", (2, 0): "th_sid", (2, 1): "th_scv", (3, 0): "th_cid", (3, 1): "th_ccv"}
POINT_ORDER = ("th_kem", "th_sid", "th_scv", "th_cid", "th_ccv")


def _load():
    with open(os.path.join(VEC, "transcript-kat.json"), "rb") as fh:
        raw = fh.read()
    got = hashlib.sha256(raw).hexdigest()
    assert got == TRANSCRIPT_KAT_SHA256, f"transcript KAT vector SHA-256 mismatch (swapped vector?): {got}"
    return json.loads(raw)


def _trim(s):
    return s[2:] if s[:2].lower() == "0x" else s


def _drive(k, add_frame_type, add_tlv, snap):
    """Walk the vector frames/TLVs in order; snapshot at each spec section 3 cut point."""
    points = {}
    for fi, f in enumerate(k["frames"]):
        add_frame_type(int(_trim(f["frame_type"]), 16))
        for ti, tl in enumerate(f["tlvs"]):
            add_tlv(int(_trim(tl["type"]), 16), bytes.fromhex(tl["value"]))
            if (fi, ti) in CUT_POINTS:
                points[CUT_POINTS[(fi, ti)]] = snap()
    return points


def _check(leg, k, points):
    exp = k["expected_transcript_points"]
    assert set(points) == set(POINT_ORDER), f"[{leg}] missing/extra cut points: {sorted(points)}"
    for name in POINT_ORDER:
        assert points[name] == exp[name], f"[{leg}] {name} mismatch\n  got  {points[name]}\n  want {exp[name]}"


def test_transcript_kat_fips180_anchor():
    k = _load()
    fips = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    assert hashlib.sha256(k["fips180_4_sha256_abc"]["input_ascii"].encode()).hexdigest() == fips
    assert k["fips180_4_sha256_abc"]["digest"] == fips


def test_transcript_kat_oracle():
    k = _load()
    buf = bytearray()

    def add_frame_type(v):
        buf.extend(v.to_bytes(2, "big"))

    def add_tlv(t, val):
        buf.extend(t.to_bytes(2, "big") + len(val).to_bytes(2, "big") + val)

    def snap():
        return hashlib.sha256(buf).hexdigest()

    _check("oracle", k, _drive(k, add_frame_type, add_tlv, snap))


def test_transcript_kat_impl():
    k = _load()
    assert (n.FRAME_CLIENT_HELLO, n.FRAME_SERVER_HELLO, n.FRAME_SERVER_AUTH, n.FRAME_CLIENT_AUTH) == (0x0100, 0x0101, 0x0102, 0x0103)
    tr = n.Transcript()

    def snap():
        return tr.hash(True).hex()

    _check("impl", k, _drive(k, tr.add_frame_type, tr.add_tlv, snap))


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
