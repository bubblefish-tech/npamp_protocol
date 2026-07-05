"""Conformance: reproduce the Go-generated vectors + property tests. Run directly or via pytest."""
import npamp as n

HDR = "4e50414d20000100000000000000000000000000000d880c250000000000000000000000"
NONCE = "010203040404040c0c0c0c04"
AEAD = "3fe8b79f95b5697926b3395429c2c2466999c652f9346aeebb30bf"
TK = "79372e2fb7f92d63e3a68099ff72514f310ebf6773deb0fa7ef45d013c652dcc"


def test_vec_header():
    assert n.Frame(ftype=n.FRAME_PING, channel=n.CHAN_CONTROL, seq=0).marshal().hex() == HDR


def test_vec_nonce():
    assert n.derive_nonce(bytes(range(1, 13)), 0x0102030405060708).hex() == NONCE


def test_vec_aead():
    key = bytes(range(32)); iv = bytes(0x10 + i for i in range(12))
    aad = n.Frame(ftype=n.FRAME_PING, channel=n.CHAN_CONTROL).header_prefix(11)
    assert n.seal_aes256gcm(key, iv, 7, aad, b"hello world").hex() == AEAD


def test_vec_traffic_key():
    master = bytes([0x2A]) * 48
    ts = n.derive_traffic_secret(master, 0, 0, n.AEAD_AES256_GCM, n.CHAN_CONTROL, False)
    tk, _ = n.derive_key_iv(ts, False)
    assert tk.hex() == TK


def test_roundtrip():
    f = n.Frame(ftype=0x0100, channel=n.CHAN_MEMORY, seq=42, flags=n.FLAG_ENC, payload=b"payload")
    g = n.Frame.unmarshal(f.marshal())
    assert (g.flags, g.ftype, g.channel, g.seq, g.payload) == (n.FLAG_ENC, 0x0100, n.CHAN_MEMORY, 42, b"payload")


def test_crc_first():
    buf = bytearray(n.Frame(ftype=n.FRAME_PING).marshal()); buf[5] ^= 0xFF
    try:
        n.Frame.unmarshal(bytes(buf)); assert False
    except n.FrameError as e:
        assert "crc" in str(e)


def test_reserved_zero():
    buf = bytearray(n.Frame(ftype=n.FRAME_PING).marshal()); buf[30] = 1
    try:
        n.Frame.unmarshal(bytes(buf)); assert False
    except n.FrameError as e:
        assert "reserved" in str(e)


def test_aead_tamper():
    key = bytes(32); iv = bytes(0x10 + i for i in range(12))
    aad = bytearray(n.Frame(ftype=n.FRAME_PING).header_prefix(5))
    sealed = n.seal_aes256gcm(key, bytes(iv), 7, bytes(aad), b"hello")
    assert n.open_aes256gcm(key, bytes(iv), 7, bytes(aad), sealed) == b"hello"
    aad[5] ^= 1
    try:
        n.open_aes256gcm(key, bytes(iv), 7, bytes(aad), sealed); assert False
    except Exception:
        pass


def test_hkdf_prefix():
    assert n.LABEL_PREFIX == "n-pamp " and n.LABEL_PREFIX != "tls13 "


if __name__ == "__main__":
    fails = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn(); print(f"PASS {name}")
            except Exception as e:
                print(f"FAIL {name}: {e}"); fails += 1
    raise SystemExit(1 if fails else 0)
