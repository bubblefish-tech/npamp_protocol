"""Open reference implementation of the N-PAMP wire format (draft-bubblefish-npamp-00).

OPEN protocol layer only: framing, registries, the AEAD record layer, and the
HKDF-Expand-Label key schedule. No proprietary methods, parameters, or weights.
"""
from __future__ import annotations
import hashlib
import hmac
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.exceptions import InvalidSignature

HEADER_SIZE = 36
PROTOCOL_VERSION = 0x2
MAGIC = b"NPAM"
ALPN = "n-pamp/2"
LABEL_PREFIX = "n-pamp "  # protocol-specific; NOT "tls13 "

FLAG_URG, FLAG_ENC, FLAG_COMP, FLAG_FRAG = 0x01, 0x02, 0x04, 0x08

CHAN_CONTROL, CHAN_MEMORY, CHAN_IMMUNE, CHAN_AUDIT, CHAN_BRIDGE, CHAN_SPATIAL = 0x0000, 0x0001, 0x0005, 0x000B, 0x000D, 0x0013
FRAME_PING, FRAME_PONG, FRAME_CLOSE, FRAME_FLOW_UPDATE, CHANNEL_SPECIFIC_BASE = 0x0001, 0x0002, 0x0003, 0x000A, 0x0100
TLV_PROFILE_OFFER, TLV_KEM_CIPHERTEXT, TLV_ANOMALY_CHARGE = 0x01, 0x08, 0x12
KEM_X25519_MLKEM768, KEM_X25519_MLKEM1024 = 0x11ec, 0x11ed
AEAD_AES256_GCM, AEAD_CHACHA20_POLY1305 = 0x0001, 0x0002
SIG_ED25519, SIG_MLDSA87 = 0x0807, 0x0905


def crc32c(data: bytes) -> int:
    """CRC32C (Castagnoli, reflected) - identical to Go hash/crc32 Castagnoli."""
    poly = 0x82F63B78
    crc = 0xFFFFFFFF
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ poly if (crc & 1) else (crc >> 1)
    return crc ^ 0xFFFFFFFF


class FrameError(Exception):
    pass


class Frame:
    __slots__ = ("version", "flags", "ftype", "channel", "seq", "payload")

    def __init__(self, ftype=0, channel=0, seq=0, flags=0, version=0, payload=b""):
        self.version, self.flags, self.ftype, self.channel, self.seq, self.payload = version, flags, ftype, channel, seq, payload

    def header_prefix(self, payload_len: int) -> bytes:
        ver = self.version or PROTOCOL_VERSION
        out = bytearray(21)
        out[0:4] = MAGIC
        out[4] = (ver << 4) | (self.flags & 0x0F)
        out[5:7] = self.ftype.to_bytes(2, "big")
        out[7:9] = self.channel.to_bytes(2, "big")
        out[9:17] = self.seq.to_bytes(8, "big")
        out[17:21] = payload_len.to_bytes(4, "big")
        return bytes(out)

    def marshal(self) -> bytes:
        prefix = self.header_prefix(len(self.payload))
        out = bytearray(HEADER_SIZE + len(self.payload))
        out[0:21] = prefix
        out[21:25] = crc32c(prefix).to_bytes(4, "big")
        # octets 25..36 reserved, already zero
        out[HEADER_SIZE:] = self.payload
        return bytes(out)

    @staticmethod
    def unmarshal(buf: bytes) -> "Frame":
        if len(buf) < HEADER_SIZE:
            raise FrameError("short header")
        got = int.from_bytes(buf[21:25], "big")
        if got != crc32c(buf[0:21]):
            raise FrameError("bad crc")
        if buf[0:4] != MAGIC:
            raise FrameError("bad magic")
        ver = buf[4] >> 4
        if ver != PROTOCOL_VERSION:
            raise FrameError("bad version")
        if any(buf[i] != 0 for i in range(25, HEADER_SIZE)):
            raise FrameError("reserved nonzero")
        plen = int.from_bytes(buf[17:21], "big")
        if plen != len(buf) - HEADER_SIZE:
            raise FrameError("length mismatch")
        return Frame(
            version=ver, flags=buf[4] & 0x0F,
            ftype=int.from_bytes(buf[5:7], "big"), channel=int.from_bytes(buf[7:9], "big"),
            seq=int.from_bytes(buf[9:17], "big"), payload=bytes(buf[HEADER_SIZE:]),
        )


def derive_nonce(iv: bytes, seq: int) -> bytes:
    """Per-frame AEAD nonce (draft-00 7.5): IV XOR left-zero-padded seq. No channel."""
    n = bytearray(12)
    n[4:12] = seq.to_bytes(8, "big")
    return bytes(a ^ b for a, b in zip(n, iv))


def seal_aes256gcm(key: bytes, iv: bytes, seq: int, aad: bytes, pt: bytes) -> bytes:
    return AESGCM(key).encrypt(derive_nonce(iv, seq), pt, aad)


def open_aes256gcm(key: bytes, iv: bytes, seq: int, aad: bytes, sealed: bytes) -> bytes:
    return AESGCM(key).decrypt(derive_nonce(iv, seq), sealed, aad)


def hkdf_extract(salt: bytes, ikm: bytes, standard: bool) -> bytes:
    """HKDF-Extract (RFC 5869 2.2): PRK = HMAC-Hash(salt, IKM). Standard profile uses SHA-256,
    High/Sovereign uses SHA-384. With a HashLen-zero salt this is the binding's handshake-secret
    extraction step (spec/10 5). Exposed for independent KAT against RFC 5869 TC1."""
    return hmac.new(salt, ikm, hashlib.sha256 if standard else hashlib.sha384).digest()


def hkdf_expand(prk: bytes, info: bytes, length: int, standard: bool) -> bytes:
    """HKDF-Expand only (RFC 5869 2.3). Exposed for independent KAT against RFC 5869 / Wycheproof."""
    algo = hashes.SHA256() if standard else hashes.SHA384()
    return HKDFExpand(algorithm=algo, length=length, info=info).derive(prk)


def hkdf_expand_label(secret: bytes, label: str, context: bytes, length: int, standard: bool) -> bytes:
    full = (LABEL_PREFIX + label).encode()
    info = length.to_bytes(2, "big") + bytes([len(full)]) + full + bytes([len(context)]) + context
    return hkdf_expand(secret, info, length, standard)


def derive_traffic_secret(master: bytes, direction: int, epoch: int, suite: int, channel: int, standard: bool) -> bytes:
    ctx = bytes([direction]) + epoch.to_bytes(8, "big") + suite.to_bytes(2, "big") + channel.to_bytes(2, "big")
    hlen = 32 if standard else 48
    return hkdf_expand_label(master, "traffic", ctx, hlen, standard)


def derive_key_iv(secret: bytes, standard: bool):
    return hkdf_expand_label(secret, "key", b"", 32, standard), hkdf_expand_label(secret, "iv", b"", 12, standard)


def derive_handshake_secret(mlkem_ss: bytes, x25519_ss: bytes, standard: bool) -> bytes:
    """Handshake secret (binding spec/10 5; ADR-0005 ML-KEM-first). The IKM is the ML-KEM shared
    secret concatenated FIRST, then the X25519 shared secret; the handshake secret is HKDF-Extracted
    under a HashLen-zero salt (32 zero octets at Standard/SHA-256, 48 at High/Sovereign/SHA-384)."""
    hlen = 32 if standard else 48
    ikm = mlkem_ss + x25519_ss
    return hkdf_extract(b"\x00" * hlen, ikm, standard)


def derive_handshake_traffic_secrets(handshake_secret: bytes, th_kem: bytes, th_ccv: bytes, standard: bool):
    """The c_hs/s_hs/master ladder off the handshake secret (binding spec/10 5). c_hs and s_hs bind
    the post-KEM transcript hash (th_kem); master binds the post-CertVerify transcript hash (th_ccv).
    Each output is HashLen octets (32 at Standard/SHA-256). Returns (c_hs, s_hs, master)."""
    hlen = 32 if standard else 48
    c_hs = hkdf_expand_label(handshake_secret, "c hs", th_kem, hlen, standard)
    s_hs = hkdf_expand_label(handshake_secret, "s hs", th_kem, hlen, standard)
    master = hkdf_expand_label(handshake_secret, "master", th_ccv, hlen, standard)
    return c_hs, s_hs, master


def derive_finished_key(secret: bytes, standard: bool) -> bytes:
    """Finished key (binding spec/10 6.2 / 5.4): HKDF-Expand-Label(secret, 'finished', '', HashLen).
    The client Finished key derives from c_hs; the server Finished key derives from s_hs."""
    hlen = 32 if standard else 48
    return hkdf_expand_label(secret, "finished", b"", hlen, standard)


# ----------------------------------------------------------------------------
# Handshake binding layer (draft-00 binding spec/10): transcript, Finished, CertVerify.
# ----------------------------------------------------------------------------

# Handshake frame types (spec 1), carried on the control channel.
FRAME_CLIENT_HELLO, FRAME_SERVER_HELLO, FRAME_SERVER_AUTH, FRAME_CLIENT_AUTH = 0x0100, 0x0101, 0x0102, 0x0103

# CertVerify context strings (spec 6.1).
CONTEXT_SERVER_CERTVERIFY = "N-PAMP draft-00, server CertificateVerify"
CONTEXT_CLIENT_CERTVERIFY = "N-PAMP draft-00, client CertificateVerify"


class Transcript:
    """Accumulates the draft-00 handshake transcript (binding spec/10 3) and hashes it at a cut
    point. Per-TLV granularity: add_frame_type appends the 2-octet frame type ONLY (not the rest of
    the 36-octet header - the spec 3/7.1 divergence from RFC 8446); add_tlv appends
    Type(2 BE) | Length(2 BE) | Value. A point = hash over all bytes absorbed so far (SHA-256 at
    Standard, SHA-384 at High/Sovereign)."""
    __slots__ = ("_buf",)

    def __init__(self):
        self._buf = bytearray()

    def add_frame_type(self, ft: int) -> None:
        self._buf += (ft & 0xFFFF).to_bytes(2, "big")

    def add_tlv(self, type_: int, value: bytes) -> None:
        self._buf += (type_ & 0xFFFF).to_bytes(2, "big") + len(value).to_bytes(2, "big") + value

    def hash(self, standard: bool) -> bytes:
        return hashlib.sha256(self._buf).digest() if standard else hashlib.sha384(self._buf).digest()


def compute_finished(finished_key: bytes, transcript_hash: bytes, standard: bool) -> bytes:
    """Finished (binding spec/10 6.2; RFC 8446 4.4.4): HMAC(finished_key, transcript_hash) under
    the profile hash (SHA-256 at Standard, SHA-384 at High/Sovereign)."""
    return hmac.new(finished_key, transcript_hash, hashlib.sha256 if standard else hashlib.sha384).digest()


def verify_finished(finished_key: bytes, transcript_hash: bytes, verify_data: bytes, standard: bool) -> bool:
    """Recompute the Finished MAC and constant-time-compare it to the received verify_data."""
    return hmac.compare_digest(compute_finished(finished_key, transcript_hash, standard), verify_data)


def ed25519_private_key_from_seed(seed: bytes):
    """Build an Ed25519 private key from its raw 32-octet seed (RFC 8032)."""
    return ed25519.Ed25519PrivateKey.from_private_bytes(seed)


def ed25519_public_key_from_raw(raw: bytes):
    """Build an Ed25519 public key from its raw 32-octet encoding (RFC 8032)."""
    return ed25519.Ed25519PublicKey.from_public_bytes(raw)


def cert_verify_signing_input(is_server: bool, transcript_hash: bytes) -> bytes:
    """The 6.1 signing input: 64 octets of 0x20, the role context string, a 0x00 separator, then
    the transcript hash - TLS-1.3-style domain separation (RFC 8446 4.4.3)."""
    ctx = (CONTEXT_SERVER_CERTVERIFY if is_server else CONTEXT_CLIENT_CERTVERIFY).encode()
    return b"\x20" * 64 + ctx + b"\x00" + transcript_hash


def sign_cert_verify(private_key, is_server: bool, transcript_hash: bytes) -> bytes:
    """The CertVerify TLV value: u16(0x0807, Ed25519) | Ed25519(priv, signing_input)."""
    sig = private_key.sign(cert_verify_signing_input(is_server, transcript_hash))
    return SIG_ED25519.to_bytes(2, "big") + sig


def verify_cert_verify(public_key, is_server: bool, transcript_hash: bytes, value: bytes) -> bool:
    """Check a CertVerify TLV value against the signer's public key, role, and transcript hash.
    Rejects a non-Ed25519 scheme, a wrong-length signature, a role/context mismatch, or a wrong
    transcript."""
    if len(value) < 2 or int.from_bytes(value[0:2], "big") != SIG_ED25519:
        return False
    sig = value[2:]
    if len(sig) != 64:  # Ed25519 signatures are exactly 64 octets (RFC 8032 5.1.6)
        return False
    try:
        public_key.verify(sig, cert_verify_signing_input(is_server, transcript_hash))
        return True
    except InvalidSignature:
        return False
