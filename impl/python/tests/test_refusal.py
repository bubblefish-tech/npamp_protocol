"""The open Python module implements the Standard profile only. Every key-schedule, transcript
and Finished primitive refuses a non-Standard profile with NoSuiteForProfile, and still succeeds
at Standard. There is no external authority for a refusal (no RFC or FIPS defines this module's
scope), so these checks are labelled as behaviour checks, not as conformance vectors."""
import pytest
import npamp as n

SECRET = bytes([0x11]) * 32
TH = bytes([0x22]) * 32


def test_standard_control_succeeds():
    assert len(n.hkdf_expand_label(SECRET, "key", b"", 32, True)) == 32
    assert len(n.hkdf_extract(bytes(32), SECRET, True)) == 32
    assert len(n.hkdf_expand(SECRET, b"info", 32, True)) == 32
    assert len(n.derive_traffic_secret(SECRET, 0, 0, n.AEAD_AES256_GCM, n.CHAN_CONTROL, True)) == 32
    key, iv = n.derive_key_iv(SECRET, True)
    assert (len(key), len(iv)) == (32, 12)
    assert len(n.derive_handshake_secret(SECRET, SECRET, True)) == 32
    assert len(n.derive_finished_key(SECRET, True)) == 32
    assert len(n.Transcript().hash(True)) == 32
    mac = n.compute_finished(SECRET, TH, True)
    assert n.verify_finished(SECRET, TH, mac, True)


@pytest.mark.parametrize("call", [
    lambda: n.hkdf_extract(bytes(48), SECRET, False),
    lambda: n.hkdf_expand(SECRET, b"info", 48, False),
    lambda: n.hkdf_expand_label(SECRET, "key", b"", 32, False),
    lambda: n.derive_traffic_secret(SECRET, 0, 0, n.AEAD_AES256_GCM, n.CHAN_CONTROL, False),
    lambda: n.derive_key_iv(SECRET, False),
    lambda: n.derive_handshake_secret(SECRET, SECRET, False),
    lambda: n.derive_handshake_traffic_secrets(SECRET, TH, TH, False),
    lambda: n.derive_finished_key(SECRET, False),
    lambda: n.Transcript().hash(False),
    lambda: n.compute_finished(SECRET, TH, False),
    lambda: n.verify_finished(SECRET, TH, TH, False),
])
def test_non_standard_profile_is_refused(call):
    with pytest.raises(n.NoSuiteForProfile):
        call()
