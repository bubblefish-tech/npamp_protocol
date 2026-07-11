"""Byte-pinned handshake-FLOW known-answer test (issue #60, class golden-interop).

Unlike the standards-anchored primitive KATs (transcript / finished / certverify / key-schedule),
this vector pins the Go reference's SERIALIZED handshake frames so every language impl reproduces
them byte-for-byte. It is the mirror of impl/go/handshakeflow_kat_test.go against the SAME frozen
corpus (test-vectors/v1/handshake-flow-kat.json). The CLIENT_HELLO whole-frame assertion is the one
that catches draft-00-vs-draft-01 wire drift (e.g. a fixed 4-octet ProfileOffer vs the draft-01
one-octet form) as a FAILING TEST rather than a live-handshake break.

Every EXPECTED artifact is rebuilt through THIS impl's REAL code path from the pinned INPUTS:
  - frames: TLV payloads (Type(2)||Length(2)||Value, the exact encoding n.Transcript.add_tlv emits)
    wrapped by the real n.Frame.marshal(); AUTH frames sealed by the real key schedule
    (n.derive_traffic_secret / n.derive_key_iv) + n.seal_aes256gcm with the 21-octet n.Frame
    .header_prefix as AAD.
  - transcript: the real n.Transcript at each spec section 3 cut point.
  - key ladder: n.derive_handshake_secret / n.derive_handshake_traffic_secrets / n.derive_master ...
  - CertVerify / Finished: n.sign_cert_verify / n.verify_cert_verify / n.compute_finished /
    n.verify_finished.
  - mutation guard: a one-octet flip of the server CertVerify signature AND of the client Finished
    MAC must REJECT; the untouched values must still verify.

ML-KEM NOTE (honest scope): the open Python module has NO X25519MLKEM768 encapsulation/decapsulation
(QUICKSTART "KEM operations"; the installed `cryptography` predates ML-KEM). So, exactly as the Go
provenance note records for the captured-once ML-KEM ciphertext, this verifier does NOT decapsulate
the pinned ML-KEM ciphertext in Python. It DOES perform every KEM check Python CAN do through a real
code path: it re-runs the X25519 leg with `cryptography` (client X25519 private + the server X25519
public spliced from the pinned kem_ciphertext tail) and asserts it recovers x25519_shared_secret; it
asserts the ML-KEM-first concatenation mlkem_shared_secret || x25519_shared_secret == combined_secret
(the IKM the key schedule actually consumes); and it asserts the pinned kem_ciphertext front ==
mlkem_ciphertext and kem_ciphertext == server_hello's KEMCiphertext TLV. mlkem_shared_secret is
consumed as a pinned self-validating input, not re-derived.
"""
import os
import json
import hashlib
import npamp as n
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization

VEC = os.path.join(os.path.dirname(__file__), "..", "..", "..", "test-vectors", "v1")

# TLV types the handshake binding uses (spec/10 1.1; registry 9.4). The impl exports a few named TLV
# constants; the handshake-specific ones are pinned here as the wire code points the transcript and
# frames must carry.
TLV_PROFILE_OFFER = 0x0001
TLV_KEM_OFFER = 0x0003
TLV_SIG_OFFER = 0x0005
TLV_AEAD_OFFER = 0x000C
TLV_KEM_SHARE = 0x0007
TLV_PROFILE_SELECT = 0x0002
TLV_KEM_SELECT = 0x0004
TLV_SIG_SELECT = 0x0006
TLV_AEAD_SELECT = 0x000D
TLV_KEM_CIPHERTEXT = 0x0008
TLV_IDENTITY_KEY = 0x0009
TLV_CERT_VERIFY = 0x000A
TLV_FINISHED = 0x000B

PROFILE_STANDARD = 0x01  # draft-00 section 6; the ProfileOffer/ProfileSelect value is ONE octet.

DIR_C2S = 0
DIR_S2C = 1

# ML-KEM-768 ciphertext size (FIPS 203) — the front of the pinned kem_ciphertext; the 32-octet tail
# is the server X25519 public key (spec/10 section 4, ML-KEM-first wire layout).
MLKEM768_CIPHERTEXT_SIZE = 1088


def _load():
    with open(os.path.join(VEC, "handshake-flow-kat.json"), "rb") as fh:
        return json.loads(fh.read())


def _hx(s):
    return bytes.fromhex(s)


def _tlv(type_, value):
    """One TLV in canonical Type(2 BE) || Length(2 BE) || Value form — the identical byte layout
    n.Transcript.add_tlv appends (verified below in test_handshake_flow_kat_tlv_matches_transcript)."""
    return type_.to_bytes(2, "big") + len(value).to_bytes(2, "big") + value


def _u16list(ids):
    return b"".join(i.to_bytes(2, "big") for i in ids)


def _cleartext_frame(ftype, payload):
    """A cleartext handshake frame (Control channel, seq 0) through the impl's real n.Frame.marshal."""
    return n.Frame(ftype=ftype, channel=n.CHAN_CONTROL, seq=0, payload=payload).marshal()


def _seal_auth_frame(ftype, base_secret, direction, plaintext):
    """Seal an AUTH plaintext into a wire frame through the impl's REAL key-schedule + record path:
    traffic_secret -> key/iv from base_secret (dir, epoch 0, AES-256-GCM, Control), then
    n.seal_aes256gcm over the plaintext with the 21-octet header prefix as AAD (payload_len =
    len(plaintext)+16 for the GCM tag), matching impl/go sealAuthKAT."""
    ts = n.derive_traffic_secret(base_secret, direction, 0, n.AEAD_AES256_GCM, n.CHAN_CONTROL, True)
    key, iv = n.derive_key_iv(ts, True)
    f = n.Frame(ftype=ftype, channel=n.CHAN_CONTROL, seq=0, flags=n.FLAG_ENC)
    aad = f.header_prefix(len(plaintext) + 16)
    sealed = n.seal_aes256gcm(key, iv, 0, aad, plaintext)
    f.payload = sealed
    return f.marshal()


def test_handshake_flow_kat_tlv_matches_transcript():
    """Guard: the in-test _tlv encoder produces exactly the bytes n.Transcript.add_tlv absorbs, so the
    frame payloads below are built with the impl's own canonical TLV layout, not a private one."""
    tr = n.Transcript()
    tr.add_tlv(TLV_PROFILE_OFFER, b"\x01")
    tr.add_tlv(TLV_KEM_SHARE, b"\xaa\xbb\xcc")
    manual = _tlv(TLV_PROFILE_OFFER, b"\x01") + _tlv(TLV_KEM_SHARE, b"\xaa\xbb\xcc")
    assert bytes(tr._buf) == manual, "in-test TLV encoder diverged from n.Transcript.add_tlv"


def test_handshake_flow_kat_kem_and_x25519():
    """KEM leg checks Python CAN do: the pinned kem_ciphertext front == mlkem_ciphertext; the X25519
    shared secret re-runs through `cryptography` from client_x25519_private + the server public spliced
    from the ciphertext tail and recovers x25519_shared_secret; and mlkem_ss||x25519_ss (ML-KEM-first)
    == combined_secret (the key schedule IKM). ML-KEM decapsulation is out of scope for this module, so
    mlkem_shared_secret is a pinned self-validating input (see module docstring)."""
    k = _load()
    inp = k["inputs"]
    kem_ct = _hx(k["expected"]["kem"]["kem_ciphertext"])
    mlkem_ct = _hx(inp["mlkem_ciphertext"])
    mlkem_ss = _hx(inp["mlkem_shared_secret"])
    x_ss = _hx(inp["x25519_shared_secret"])
    combined = _hx(inp["combined_secret"])

    assert len(kem_ct) == MLKEM768_CIPHERTEXT_SIZE + 32, "pinned kem_ciphertext is not 1120 octets"
    assert kem_ct[:MLKEM768_CIPHERTEXT_SIZE] == mlkem_ct, "kem_ciphertext front != pinned mlkem_ciphertext"
    server_x_pub = kem_ct[MLKEM768_CIPHERTEXT_SIZE:]

    # Real X25519 through cryptography: recover x25519_shared_secret from the pinned client private and
    # the server public spliced from the ciphertext tail (validates the X25519 half of the pinned CT).
    client_priv = x25519.X25519PrivateKey.from_private_bytes(_hx(inp["client_x25519_private"]))
    got_x_ss = client_priv.exchange(x25519.X25519PublicKey.from_public_bytes(server_x_pub))
    assert got_x_ss == x_ss, "recomputed X25519 shared secret != pinned x25519_shared_secret"

    # ML-KEM-first IKM: mlkem_ss || x25519_ss == combined_secret (the byte the key schedule extracts).
    assert mlkem_ss + x_ss == combined, "mlkem_ss || x25519_ss != combined_secret (IKM drift)"

    # Sanity: the pinned server X25519 private also yields the same X25519 secret (both legs pinned).
    server_priv = x25519.X25519PrivateKey.from_private_bytes(_hx(inp["server_x25519_private"]))
    client_pub_raw = client_priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    got_x_ss2 = server_priv.exchange(x25519.X25519PublicKey.from_public_bytes(client_pub_raw))
    assert got_x_ss2 == x_ss, "server-side X25519 exchange != pinned x25519_shared_secret"


def test_handshake_flow_kat_frames_and_ladder():
    """Rebuild every handshake artifact through the impl's real code path and assert WHOLE-frame /
    byte-exact equality with the frozen vector."""
    k = _load()
    inp, exp = k["inputs"], k["expected"]

    kem_share = _hx(exp["kem"]["kem_share"])
    kem_ct = _hx(exp["kem"]["kem_ciphertext"])
    mlkem_ss = _hx(inp["mlkem_shared_secret"])
    x_ss = _hx(inp["x25519_shared_secret"])

    client_priv = n.ed25519_private_key_from_seed(_hx(inp["client_identity_ed25519_seed"]))
    server_priv = n.ed25519_private_key_from_seed(_hx(inp["server_identity_ed25519_seed"]))
    client_pub = client_priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    server_pub = server_priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    client_pub_key = n.ed25519_public_key_from_raw(client_pub)
    server_pub_key = n.ed25519_public_key_from_raw(server_pub)

    # --- CLIENT_HELLO: TLVs (ProfileOffer ONE octet = draft-01 form) framed by the real record path. ---
    ch_payload = (
        _tlv(TLV_PROFILE_OFFER, bytes([PROFILE_STANDARD]))
        + _tlv(TLV_KEM_OFFER, _u16list([n.KEM_X25519_MLKEM768]))
        + _tlv(TLV_SIG_OFFER, _u16list([n.SIG_ED25519]))
        + _tlv(TLV_AEAD_OFFER, _u16list([n.AEAD_AES256_GCM]))
        + _tlv(TLV_KEM_SHARE, kem_share)
    )
    ch_frame = _cleartext_frame(n.FRAME_CLIENT_HELLO, ch_payload)
    assert ch_frame == _hx(exp["frames"]["client_hello"]), \
        "CLIENT_HELLO frame != expected (the ProfileOffer draft-00-vs-draft-01 wire-drift guard)"

    # --- SERVER_HELLO: ProfileSelect ONE octet; KEM/Sig/AEAD Select two octets; KEMCiphertext pinned. ---
    sh_payload = (
        _tlv(TLV_PROFILE_SELECT, bytes([PROFILE_STANDARD]))
        + _tlv(TLV_KEM_SELECT, n.KEM_X25519_MLKEM768.to_bytes(2, "big"))
        + _tlv(TLV_SIG_SELECT, n.SIG_ED25519.to_bytes(2, "big"))
        + _tlv(TLV_AEAD_SELECT, n.AEAD_AES256_GCM.to_bytes(2, "big"))
        + _tlv(TLV_KEM_CIPHERTEXT, kem_ct)
    )
    sh_frame = _cleartext_frame(n.FRAME_SERVER_HELLO, sh_payload)
    assert sh_frame == _hx(exp["frames"]["server_hello"]), "SERVER_HELLO frame != expected"

    # --- Transcript + key ladder through the real impl. ---
    tr = n.Transcript()
    tr.add_frame_type(n.FRAME_CLIENT_HELLO)
    tr.add_tlv(TLV_PROFILE_OFFER, bytes([PROFILE_STANDARD]))
    tr.add_tlv(TLV_KEM_OFFER, _u16list([n.KEM_X25519_MLKEM768]))
    tr.add_tlv(TLV_SIG_OFFER, _u16list([n.SIG_ED25519]))
    tr.add_tlv(TLV_AEAD_OFFER, _u16list([n.AEAD_AES256_GCM]))
    tr.add_tlv(TLV_KEM_SHARE, kem_share)
    tr.add_frame_type(n.FRAME_SERVER_HELLO)
    tr.add_tlv(TLV_PROFILE_SELECT, bytes([PROFILE_STANDARD]))
    tr.add_tlv(TLV_KEM_SELECT, n.KEM_X25519_MLKEM768.to_bytes(2, "big"))
    tr.add_tlv(TLV_SIG_SELECT, n.SIG_ED25519.to_bytes(2, "big"))
    tr.add_tlv(TLV_AEAD_SELECT, n.AEAD_AES256_GCM.to_bytes(2, "big"))
    tr.add_tlv(TLV_KEM_CIPHERTEXT, kem_ct)
    th_kem = tr.hash(True)
    assert th_kem.hex() == exp["transcript"]["th_kem"], "th_kem != expected"

    # handshake_secret / c_hs / s_hs / master through the real ladder (ML-KEM-first IKM).
    hs = n.derive_handshake_secret(mlkem_ss, x_ss, True)
    assert hs.hex() == exp["secrets"]["handshake_secret"], "handshake_secret != expected"
    # c_hs / s_hs bind th_kem; master binds th_ccv (computed after CLIENT_AUTH's CertVerify below).
    # derive_handshake_traffic_secrets needs th_ccv up front, so compute the ladder in two calls: first
    # c_hs/s_hs from th_kem, and master later from th_ccv (both via the same real function).
    c_hs, s_hs, _ = n.derive_handshake_traffic_secrets(hs, th_kem, th_kem, True)
    assert c_hs.hex() == exp["secrets"]["c_hs_secret"], "c_hs_secret != expected"
    assert s_hs.hex() == exp["secrets"]["s_hs_secret"], "s_hs_secret != expected"

    # --- SERVER_AUTH. ---
    tr.add_frame_type(n.FRAME_SERVER_AUTH)
    tr.add_tlv(TLV_IDENTITY_KEY, server_pub)
    th_sid = tr.hash(True)
    assert th_sid.hex() == exp["transcript"]["th_sid"], "th_sid != expected"
    s_cv = n.sign_cert_verify(server_priv, True, th_sid)
    assert s_cv.hex() == exp["cert_verify"]["server"], "server cert_verify != expected"
    assert n.verify_cert_verify(server_pub_key, True, th_sid, s_cv), "server CertVerify rejected"
    tr.add_tlv(TLV_CERT_VERIFY, s_cv)
    th_scv = tr.hash(True)
    assert th_scv.hex() == exp["transcript"]["th_scv"], "th_scv != expected"
    s_fin_key = n.derive_finished_key(s_hs, True)
    assert s_fin_key.hex() == exp["finished_keys"]["server"], "server finished_key != expected"
    s_fin = n.compute_finished(s_fin_key, th_scv, True)
    assert s_fin.hex() == exp["finished"]["server"], "server finished != expected"
    tr.add_tlv(TLV_FINISHED, s_fin)
    server_auth_plain = (
        _tlv(TLV_IDENTITY_KEY, server_pub) + _tlv(TLV_CERT_VERIFY, s_cv) + _tlv(TLV_FINISHED, s_fin)
    )
    assert server_auth_plain == _hx(exp["auth_plaintext"]["server_auth"]), \
        "SERVER_AUTH plaintext != expected"
    server_auth_frame = _seal_auth_frame(n.FRAME_SERVER_AUTH, s_hs, DIR_S2C, server_auth_plain)
    assert server_auth_frame == _hx(exp["frames"]["server_auth"]), "SERVER_AUTH frame != expected"

    # --- CLIENT_AUTH. ---
    tr.add_frame_type(n.FRAME_CLIENT_AUTH)
    tr.add_tlv(TLV_IDENTITY_KEY, client_pub)
    th_cid = tr.hash(True)
    assert th_cid.hex() == exp["transcript"]["th_cid"], "th_cid != expected"
    c_cv = n.sign_cert_verify(client_priv, False, th_cid)
    assert c_cv.hex() == exp["cert_verify"]["client"], "client cert_verify != expected"
    assert n.verify_cert_verify(client_pub_key, False, th_cid, c_cv), "client CertVerify rejected"
    tr.add_tlv(TLV_CERT_VERIFY, c_cv)
    th_ccv = tr.hash(True)
    assert th_ccv.hex() == exp["transcript"]["th_ccv"], "th_ccv != expected"
    c_fin_key = n.derive_finished_key(c_hs, True)
    assert c_fin_key.hex() == exp["finished_keys"]["client"], "client finished_key != expected"
    c_fin = n.compute_finished(c_fin_key, th_ccv, True)
    assert c_fin.hex() == exp["finished"]["client"], "client finished != expected"
    client_auth_plain = (
        _tlv(TLV_IDENTITY_KEY, client_pub) + _tlv(TLV_CERT_VERIFY, c_cv) + _tlv(TLV_FINISHED, c_fin)
    )
    assert client_auth_plain == _hx(exp["auth_plaintext"]["client_auth"]), \
        "CLIENT_AUTH plaintext != expected"
    client_auth_frame = _seal_auth_frame(n.FRAME_CLIENT_AUTH, c_hs, DIR_C2S, client_auth_plain)
    assert client_auth_frame == _hx(exp["frames"]["client_auth"]), "CLIENT_AUTH frame != expected"

    # --- master_secret binds th_ccv (real ladder, second call). ---
    _, _, master = n.derive_handshake_traffic_secrets(hs, th_kem, th_ccv, True)
    assert master.hex() == exp["secrets"]["master_secret"], "master_secret != expected"

    # --- Traffic secret/key/iv for both handshake directions and both application directions. ---
    def _assert_traffic(name, parent, direction, ts_hex, key_hex, iv_hex):
        ts = n.derive_traffic_secret(parent, direction, 0, n.AEAD_AES256_GCM, n.CHAN_CONTROL, True)
        assert ts.hex() == ts_hex, f"{name}_traffic_secret != expected"
        key, iv = n.derive_key_iv(ts, True)
        assert key.hex() == key_hex, f"{name}_key != expected"
        assert iv.hex() == iv_hex, f"{name}_iv != expected"

    s = exp["secrets"]
    _assert_traffic("c_hs", c_hs, DIR_C2S, s["c_hs_traffic_secret"], s["c_hs_key"], s["c_hs_iv"])
    _assert_traffic("s_hs", s_hs, DIR_S2C, s["s_hs_traffic_secret"], s["s_hs_key"], s["s_hs_iv"])
    _assert_traffic("app_c2s", master, DIR_C2S, s["app_c2s_traffic_secret"], s["app_c2s_key"], s["app_c2s_iv"])
    _assert_traffic("app_s2c", master, DIR_S2C, s["app_s2c_traffic_secret"], s["app_s2c_key"], s["app_s2c_iv"])

    # --- Mutation guard 1: a one-octet flip of the server CertVerify signature must REJECT. ---
    bad_cv = bytearray(s_cv)
    bad_cv[-1] ^= 0x01  # flip the last signature octet
    assert not n.verify_cert_verify(server_pub_key, True, th_sid, bytes(bad_cv)), \
        "mutation guard: a one-octet-flipped server CertVerify signature VERIFIED"

    # --- Mutation guard 2: a one-octet flip of the client Finished MAC must REJECT. ---
    bad_fin = bytearray(c_fin)
    bad_fin[0] ^= 0x01
    assert not n.verify_finished(c_fin_key, th_ccv, bytes(bad_fin), True), \
        "mutation guard: a one-octet-flipped client Finished MAC VERIFIED"

    # --- Sanity: the untouched signature and MAC still verify. ---
    assert n.verify_cert_verify(server_pub_key, True, th_sid, s_cv), "unmutated server CertVerify rejected"
    assert n.verify_finished(c_fin_key, th_ccv, c_fin, True), "unmutated client Finished rejected"


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
