"""A live N-PAMP session: the 1.5-RTT mutually-authenticated handshake (binding
spec/10) plus the AEAD record layer, composed over a caller-injected byte
transport.

This is the port's ecosystem-facing ADOPTION API: everything in the sibling
``npamp`` package (the frame codec, the HKDF key schedule, the handshake
transcript/CertVerify/Finished primitives in ``npamp/__init__.py``) is a
wire-format PRIMITIVE -- real, tested, but not itself a usable client/server.
This module composes those primitives, plus the X25519MLKEM768 hybrid KEM,
into the calls a consuming product actually wants:

  - :func:`Session.dial` / :func:`Session.accept` -- run the client/server
    side of the handshake over any object exposing a blocking ``read(n) ->
    bytes`` and ``write(data) -> int|None`` pair (a socket wrapped in
    ``makefile()``, an ``io.BytesIO``-like duplex, a tunnel inside another
    session -- the handshake is transport-agnostic per binding spec/10),
    returning an authenticated :class:`Session` on success.
  - :meth:`Session.send` / :meth:`Session.recv` -- seal/open one
    application-defined frame under the session's per-direction epoch-0
    traffic key (draft-01 section 7.5).

Scope: Standard profile only (X25519MLKEM768 + Ed25519 + AES-256-GCM +
SHA-256), matching the rest of this port. ``Session`` carries NO application
semantics (the channel/frame-type/payload meaning is the caller's contract)
and no connection MANAGEMENT beyond the handshake and one send/recv pair per
direction: there is no key update, no ratchet, no graceful close, and no
anti-replay window -- a caller that needs those composes them on top, the
same way the Go reference's ``sdk.Conn`` layers them over the wire-only
``impl/go`` package. A caller-managed sequence number keeps this module's job
bounded to authentication + confidentiality/integrity.

This module needs a real X25519MLKEM768 hybrid KEM (encapsulate/decapsulate).
The base ``npamp`` package deliberately carries none (see QUICKSTART.md:
"the installed `cryptography` predates ML-KEM"), so this module imports the
pure-Python FIPS-203 implementation from the ``kyber-py`` package (an
OPTIONAL dependency -- ``pip install npamp[session]`` or ``pip install
kyber-py``). Importing the base ``npamp`` package never pulls this in;
only importing ``npamp.session`` does, so a consumer who wants the strict
wire-format-only library keeps a zero-PQ-dependency install.

ML-KEM-768 correctness note: ``kyber_py.ml_kem.ML_KEM_768`` was verified this
session against the frozen ``handshake-flow-kat.json`` vector -- deterministic
keygen from the pinned 64-octet ``mlkem768_seed_dz`` reproduces the pinned
encapsulation key exactly, and decapsulating the pinned (captured-once)
``mlkem_ciphertext`` under the derived decapsulation key recovers the pinned
``mlkem_shared_secret`` exactly. See ``tests/test_session.py`` and
``RED-EVIDENCE.md`` for the recorded evidence.
"""
from __future__ import annotations

import hmac as _hmac
import os as _os
import queue as _queue

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from kyber_py.ml_kem import ML_KEM_768

import npamp as n

__all__ = [
    "SessionError",
    "Session",
    "generate_identity",
    "Duplex",
    "duplex_pair",
]

# ---------------------------------------------------------------------------
# Handshake TLV code points (binding spec/10 section 1.1). The npamp package
# root exposes only the subset the wire-only primitives need; the full
# handshake set is private to this module, which owns the handshake flow.
# ---------------------------------------------------------------------------
TLV_PROFILE_OFFER = 0x01
TLV_PROFILE_SELECT = 0x02
TLV_KEM_OFFER = 0x03
TLV_KEM_SELECT = 0x04
TLV_SIG_OFFER = 0x05
TLV_SIG_SELECT = 0x06
TLV_KEM_SHARE = 0x07
TLV_KEM_CIPHERTEXT = 0x08
TLV_IDENTITY_KEY = 0x09
TLV_CERT_VERIFY = 0x0A
TLV_FINISHED = 0x0B
TLV_AEAD_OFFER = 0x0C
TLV_AEAD_SELECT = 0x0D

PROFILE_STANDARD = 0x01
STANDARD = True  # SHA-256 profile throughout (Standard, not High/Sovereign)

# Direction octets (draft-01 section 7.5): client-to-server = 0, server-to-client = 1.
DIR_C2S = 0
DIR_S2C = 1

MLKEM768_EK_LEN = 1184
MLKEM768_CT_LEN = 1088
X25519_PUB_LEN = 32
KEM_SHARE_LEN = MLKEM768_EK_LEN + X25519_PUB_LEN  # 1216
KEM_CIPHERTEXT_LEN = MLKEM768_CT_LEN + X25519_PUB_LEN  # 1120
GCM_TAG_LEN = 16
ZERO_X25519_SS = bytes(32)

# Caps a single accepted frame (header + payload), mirroring the Go SDK's
# maxFrameSize guard so a peer cannot force an unbounded allocation with a
# hostile length field.
MAX_FRAME_SIZE = 16 << 20


class SessionError(Exception):
    """A handshake or record-layer failure: a malformed/unexpected frame, a
    rejected CertVerify/Finished, an AEAD-authentication failure, or a
    transport closed mid-exchange. Never raised with an unauthenticated
    plaintext already returned to the caller."""


def _proto(msg: str) -> SessionError:
    return SessionError(f"npamp/session: {msg}")


# ---------------------------------------------------------------------------
# OS entropy -> deterministic keygen seeds (no extra RNG dependency).
# ---------------------------------------------------------------------------
def generate_identity():
    """Generates a fresh Ed25519 long-term identity signing key from OS
    entropy, for use as the ``identity`` argument to :func:`Session.dial` /
    :func:`Session.accept`."""
    return n.ed25519_private_key_from_seed(_os.urandom(32))


# ---------------------------------------------------------------------------
# TLV codec (Type u16 BE || Length u16 BE || Value), identical to the wire
# form ``npamp.Transcript.add_tlv`` absorbs and to the Go reference's TLV
# codec.
# ---------------------------------------------------------------------------
def _tlv(type_: int, value: bytes) -> bytes:
    return type_.to_bytes(2, "big") + len(value).to_bytes(2, "big") + value


def _decode_tlvs(buf: bytes):
    """Parses a concatenation of TLVs into a list of (type, value) pairs.
    Rejects a truncated TLV header or a truncated TLV value."""
    out = []
    off = 0
    n_ = len(buf)
    while off < n_:
        if off + 4 > n_:
            raise _proto("truncated TLV header")
        typ = int.from_bytes(buf[off:off + 2], "big")
        ln = int.from_bytes(buf[off + 2:off + 4], "big")
        off += 4
        if off + ln > n_:
            raise _proto("truncated TLV value")
        out.append((typ, buf[off:off + ln]))
        off += ln
    return out


def _require_tlvs(tlvs, want):
    """Enforces the exact TLV set + order the handshake fixes (binding
    spec/10 section 1), returning just the values in `want` order."""
    if len(tlvs) != len(want):
        raise _proto("handshake TLV count mismatch")
    vals = []
    for i, w in enumerate(want):
        if tlvs[i][0] != w:
            raise _proto("handshake TLV out of order")
        vals.append(tlvs[i][1])
    return vals


def _cleartext_frame(ftype: int, payload: bytes) -> bytes:
    """Marshals a cleartext handshake frame (Control channel, seq 0) through
    the package's real ``Frame.marshal``."""
    return n.Frame(ftype=ftype, channel=n.CHAN_CONTROL, seq=0, payload=payload).marshal()


# ---------------------------------------------------------------------------
# Self-delimiting frame stream I/O over a GENERIC transport: fixed 36-octet
# header, payload length in octets 17..21, no extra length prefix. `transport`
# is any object with a blocking `.read(n) -> bytes` (returning fewer than n
# octets only at end-of-stream) and a `.write(data) -> int|None` -- a
# `socket.makefile('rwb')`, an `io.BytesIO`, a :class:`Duplex` end, or
# anything else that moves bytes reliably and in order.
# ---------------------------------------------------------------------------
def _read_exact(transport, want: int) -> bytes:
    if want == 0:
        return b""
    buf = bytearray()
    while len(buf) < want:
        chunk = transport.read(want - len(buf))
        if not chunk:
            raise _proto("transport closed (short read)")
        buf += chunk
    return bytes(buf)


def _write_all(transport, data: bytes) -> None:
    view = memoryview(data)
    total = len(data)
    written = 0
    while written < total:
        n_written = transport.write(view[written:])
        if n_written is None:
            n_written = total - written  # file-like convention: full write
        if n_written <= 0:
            raise _proto("transport write stalled")
        written += n_written


def _read_frame(transport) -> bytes:
    header = _read_exact(transport, n.HEADER_SIZE)
    if header[0:4] != n.MAGIC:
        raise _proto("bad frame magic")
    plen = int.from_bytes(header[17:21], "big")
    if plen > MAX_FRAME_SIZE - n.HEADER_SIZE:
        raise _proto("frame exceeds max size")
    payload = _read_exact(transport, plen)
    return header + payload


def _write_frame(transport, frame: bytes) -> None:
    _write_all(transport, frame)


# ---------------------------------------------------------------------------
# AEAD sealing of the AUTH frames + application frames (epoch 0), identical
# to the Go SDK's sealFrame / openFrame / sealWith / openWith.
# ---------------------------------------------------------------------------
def _key_iv(base: bytes, direction: int, channel: int):
    """Derives the epoch-0 (key, iv) for a (base secret, direction, channel)."""
    ts = n.derive_traffic_secret(base, direction, 0, n.AEAD_AES256_GCM, channel, STANDARD)
    return n.derive_key_iv(ts, STANDARD)


def _seal_frame(base: bytes, direction: int, channel: int, seq: int, ftype: int, plaintext: bytes) -> bytes:
    """Seals `plaintext` into a marshaled FLAG_ENC frame on `channel` at `seq`."""
    key, iv = _key_iv(base, direction, channel)
    f = n.Frame(ftype=ftype, channel=channel, seq=seq, flags=n.FLAG_ENC)
    aad = f.header_prefix(len(plaintext) + GCM_TAG_LEN)
    f.payload = n.seal_aes256gcm(key, iv, seq, aad, plaintext)
    return f.marshal()


def _open_frame(f: "n.Frame", base: bytes, direction: int) -> bytes:
    """Opens a parsed FLAG_ENC frame under the (base secret, direction)
    epoch-0 key. A tampered ciphertext, a tampered AAD (any header octet), or
    the wrong key/seq makes AES-256-GCM authentication fail, which this maps
    to a named :class:`SessionError` -- it never falls back to returning
    unauthenticated bytes."""
    key, iv = _key_iv(base, direction, f.channel)
    aad = f.header_prefix(len(f.payload))
    try:
        return n.open_aes256gcm(key, iv, f.seq, aad, f.payload)
    except InvalidTag as exc:
        raise _proto("AEAD open failed") from exc


# ---------------------------------------------------------------------------
# X25519MLKEM768 hybrid KEM (ML-KEM-first, ADR-0005). The client generates
# the key pairs and decapsulates; the server encapsulates.
# ---------------------------------------------------------------------------
class _KemClient:
    """Holds the client's ephemeral ML-KEM-768 + X25519 key pairs."""
    __slots__ = ("mlkem_ek", "mlkem_dk", "x25519_priv", "x25519_pub")

    def __init__(self, mlkem_ek: bytes, mlkem_dk: bytes, x25519_priv, x25519_pub: bytes):
        self.mlkem_ek = mlkem_ek
        self.mlkem_dk = mlkem_dk
        self.x25519_priv = x25519_priv
        self.x25519_pub = x25519_pub

    @classmethod
    def from_seed(cls, mlkem_dz_seed: bytes, x25519_priv_bytes: bytes) -> "_KemClient":
        """Derives the client's ephemeral ML-KEM-768 + X25519 key pairs from
        caller-supplied seed material (deterministic -- :meth:`Session.dial`
        supplies fresh OS entropy; the pinned-vector conformance test in
        ``tests/test_session.py`` supplies the vector's fixed seeds so the
        SAME code path is graded byte-for-byte). ``mlkem_dz_seed`` is the
        64-octet FIPS-203 keygen seed d||z (Algorithm 16)."""
        if len(mlkem_dz_seed) != 64:
            raise _proto("ML-KEM keygen seed must be 64 octets (d||z)")
        ek, dk = ML_KEM_768.key_derive(mlkem_dz_seed)
        x_priv = x25519.X25519PrivateKey.from_private_bytes(x25519_priv_bytes)
        x_pub = x_priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        return cls(ek, dk, x_priv, x_pub)

    def kem_share(self) -> bytes:
        """TLV 0x07 value: ML-KEM-768 ek (1184) || X25519 public (32),
        ML-KEM-first."""
        return self.mlkem_ek + self.x25519_pub

    def shared_secrets(self, kem_ct: bytes):
        """Decapsulates the server's KEMCiphertext into (ML-KEM_SS,
        X25519_SS). Rejects a wrong-length ciphertext, a decapsulation
        failure, and an X25519 low-order (all-zero) result."""
        if len(kem_ct) != KEM_CIPHERTEXT_LEN:
            raise _proto(f"KEMCiphertext is not {KEM_CIPHERTEXT_LEN} octets")
        mlkem_ct = kem_ct[:MLKEM768_CT_LEN]
        server_x_pub = kem_ct[MLKEM768_CT_LEN:]
        try:
            mlkem_ss = ML_KEM_768.decaps(self.mlkem_dk, mlkem_ct)
        except ValueError as exc:
            raise _proto(f"ML-KEM decapsulate: {exc}") from exc
        x_ss = self.x25519_priv.exchange(x25519.X25519PublicKey.from_public_bytes(server_x_pub))
        if x_ss == ZERO_X25519_SS:
            raise _proto("X25519 produced an all-zero (low-order) shared secret")
        return mlkem_ss, x_ss


def _encapsulate(kem_share: bytes, mlkem_encap_m: bytes, x25519_priv_bytes: bytes):
    """Server side: parses the client KEMShare, encapsulates against it, and
    returns the TLV 0x08 KEMCiphertext value plus (ML-KEM_SS, X25519_SS).
    ``mlkem_encap_m`` is the ML-KEM encapsulation randomness (32 octets;
    FIPS-203 Algorithm 17's `m`) and ``x25519_priv_bytes`` the server's
    ephemeral X25519 static secret -- both caller-supplied so
    :meth:`Session.accept` can pass fresh OS entropy while a future
    deterministic test can pass fixed values."""
    if len(kem_share) != KEM_SHARE_LEN:
        raise _proto(f"KEMShare is not {KEM_SHARE_LEN} octets")
    ek = kem_share[:MLKEM768_EK_LEN]
    client_x_pub = kem_share[MLKEM768_EK_LEN:]

    try:
        mlkem_ss, ct = ML_KEM_768._encaps_internal(ek, mlkem_encap_m)
    except ValueError as exc:
        raise _proto(f"ML-KEM encapsulate: {exc}") from exc

    server_priv = x25519.X25519PrivateKey.from_private_bytes(x25519_priv_bytes)
    server_pub = server_priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    x_ss = server_priv.exchange(x25519.X25519PublicKey.from_public_bytes(client_x_pub))
    if x_ss == ZERO_X25519_SS:
        raise _proto("X25519 produced an all-zero (low-order) shared secret")

    kem_ct = ct + server_pub
    return kem_ct, mlkem_ss, x_ss


# ---------------------------------------------------------------------------
# Profile/select negotiation guards (Standard profile only).
# ---------------------------------------------------------------------------
def _list_contains_u16(buf: bytes, want: int) -> bool:
    if len(buf) % 2 != 0:
        return False
    return any(int.from_bytes(buf[i:i + 2], "big") == want for i in range(0, len(buf), 2))


def _require_standard_offer(vals) -> None:
    if PROFILE_STANDARD not in vals[0]:
        raise _proto("client did not offer the Standard profile")
    if not _list_contains_u16(vals[1], n.KEM_X25519_MLKEM768):
        raise _proto("client did not offer X25519MLKEM768")
    if not _list_contains_u16(vals[2], n.SIG_ED25519):
        raise _proto("client did not offer Ed25519")
    if not _list_contains_u16(vals[3], n.AEAD_AES256_GCM):
        raise _proto("client did not offer AES-256-GCM")


def _require_standard_select(vals) -> None:
    if vals[0] != bytes([PROFILE_STANDARD]):
        raise _proto("server selected an unsupported profile")
    if vals[1] != n.KEM_X25519_MLKEM768.to_bytes(2, "big"):
        raise _proto("server selected an unsupported KEM")
    if vals[2] != n.SIG_ED25519.to_bytes(2, "big"):
        raise _proto("server selected an unsupported signature")
    if vals[3] != n.AEAD_AES256_GCM.to_bytes(2, "big"):
        raise _proto("server selected an unsupported AEAD")


def _parse_enc_frame(wire: bytes, want_ftype: int) -> "n.Frame":
    try:
        f = n.Frame.unmarshal(wire)
    except n.FrameError as exc:
        raise _proto(f"AUTH frame parse: {exc}") from exc
    if f.ftype != want_ftype:
        raise _proto("unexpected AUTH frame type")
    if not (f.flags & n.FLAG_ENC):
        raise _proto("AUTH frame is not AEAD-encrypted")
    return f


def _encode_auth(identity: bytes, cert_verify: bytes, finished: bytes) -> bytes:
    return _tlv(TLV_IDENTITY_KEY, identity) + _tlv(TLV_CERT_VERIFY, cert_verify) + _tlv(TLV_FINISHED, finished)


def _decode_auth(pt: bytes):
    vals = _require_tlvs(_decode_tlvs(pt), [TLV_IDENTITY_KEY, TLV_CERT_VERIFY, TLV_FINISHED])
    return vals[0], vals[1], vals[2]


def _vk_from(raw: bytes):
    if len(raw) != 32:
        raise _proto("identity key is not 32 octets")
    try:
        return n.ed25519_public_key_from_raw(raw)
    except Exception as exc:  # cryptography raises its own ValueError family
        raise _proto("invalid Ed25519 identity key") from exc


def _to32(b: bytes) -> bytes:
    if len(b) != 32:
        raise _proto("identity key is not 32 octets")
    return bytes(b)


# ---------------------------------------------------------------------------
# The authenticated session.
# ---------------------------------------------------------------------------
class Session:
    """The authenticated result of a completed handshake: the
    application-phase master secret and the peer's proven Ed25519 identity.
    :meth:`send` / :meth:`recv` derive per-(direction, channel) AEAD traffic
    keys from the master secret on demand (draft-01 section 7.5) -- the
    epoch-0 keys a session established this way never rotate (no key update
    / ratchet in this bounded-core API; see the module docstring)."""

    __slots__ = ("_master", "_peer_identity", "_send_dir", "_recv_dir")

    def __init__(self, master: bytes, peer_identity: bytes, send_dir: int, recv_dir: int):
        self._master = master
        self._peer_identity = peer_identity
        self._send_dir = send_dir
        self._recv_dir = recv_dir

    def peer_identity(self) -> bytes:
        """The peer's Ed25519 identity public key, proven during the
        handshake (32 raw octets)."""
        return self._peer_identity

    def master_secret(self) -> bytes:
        """The application-phase master secret (draft-01 section 5). Exposed
        for a caller that wants to derive its own additional traffic secrets
        via :func:`npamp.derive_traffic_secret`; ordinary send/recv callers
        do not need it."""
        return self._master

    @classmethod
    def dial(cls, transport, identity, expected_peer: "bytes | None" = None) -> "Session":
        """Runs the CLIENT side of the 1.5-RTT N-PAMP handshake (binding
        spec/10) over `transport`, authenticating with `identity` (an
        ``ed25519.Ed25519PrivateKey``) and, if `expected_peer` is not
        ``None``, rejecting any server whose proven Ed25519 identity does not
        match -- checked BEFORE CLIENT_AUTH is sent, so the client never
        authenticates to an impostor.

        `transport` is any object with a blocking ``read(n) -> bytes`` /
        ``write(data) -> int|None`` pair: a wrapped socket, an in-memory
        :class:`Duplex` (see :func:`duplex_pair` and ``tests/test_session.py``),
        or a tunnel inside another authenticated session. The handshake
        itself carries no transport-layer confidentiality (that is a
        TLS/QUIC transport binding's job, layered by the caller) -- over an
        untrusted network, pin `expected_peer` or wrap `transport` in one."""
        return _dial_with_ephemeral(transport, identity, expected_peer, _os.urandom(64), _os.urandom(32))

    @classmethod
    def accept(cls, transport, identity, expected_peer: "bytes | None" = None) -> "Session":
        """Runs the SERVER side of the 1.5-RTT N-PAMP handshake over
        `transport` -- the mirror of :meth:`dial`, with the same
        authentication and identity-pinning semantics (checked against the
        client's proven identity)."""
        return _accept_with_ephemeral(transport, identity, expected_peer, _os.urandom(32), _os.urandom(32))

    def send(self, transport, channel: int, ftype: int, seq: int, payload: bytes) -> None:
        """Seals `payload` as one application-defined frame (`channel`,
        `ftype`, `seq`) under this session's send-direction epoch-0 traffic
        key, and writes it to `transport`. The sequence number is
        caller-managed (no internal counter, no replay window in this
        bounded-core API): the caller picks a fresh `seq` per frame on a
        given channel, matching what the peer's `recv` expects."""
        _write_frame(transport, _seal_frame(self._master, self._send_dir, channel, seq, ftype, payload))

    def recv(self, transport, want_seq: int):
        """Reads one application frame from `transport`, checks it carries
        the expected sequence number `want_seq` and is AEAD-protected, and
        opens it under this session's receive-direction epoch-0 traffic key.
        Returns `(channel, frame_type, plaintext)`. A tampered ciphertext, a
        tampered header, an unencrypted frame, or an out-of-sequence frame is
        a named :class:`SessionError` -- never silently accepted."""
        wire = _read_frame(transport)
        try:
            f = n.Frame.unmarshal(wire)
        except n.FrameError as exc:
            raise _proto(f"data frame parse: {exc}") from exc
        if not (f.flags & n.FLAG_ENC):
            raise _proto("data frame is not AEAD-encrypted")
        if f.seq != want_seq:
            raise _proto("out-of-sequence data frame")
        pt = _open_frame(f, self._master, self._recv_dir)
        return f.channel, f.ftype, pt


# ---------------------------------------------------------------------------
# Handshake drivers, parameterized over the ephemeral seed material so a
# pinned-vector conformance test can drive the SAME code path
# :meth:`Session.dial` / :meth:`Session.accept` use, with fixed seeds instead
# of fresh OS entropy.
# ---------------------------------------------------------------------------
def _dial_with_ephemeral(transport, identity, expected_peer, mlkem_dz_seed: bytes, x25519_priv_bytes: bytes) -> Session:
    client_pub = identity.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    kem = _KemClient.from_seed(mlkem_dz_seed, x25519_priv_bytes)
    kem_share = kem.kem_share()

    # --- CLIENT_HELLO (cleartext) ---
    ch = (
        _tlv(TLV_PROFILE_OFFER, bytes([PROFILE_STANDARD]))
        + _tlv(TLV_KEM_OFFER, n.KEM_X25519_MLKEM768.to_bytes(2, "big"))
        + _tlv(TLV_SIG_OFFER, n.SIG_ED25519.to_bytes(2, "big"))
        + _tlv(TLV_AEAD_OFFER, n.AEAD_AES256_GCM.to_bytes(2, "big"))
        + _tlv(TLV_KEM_SHARE, kem_share)
    )
    _write_frame(transport, _cleartext_frame(n.FRAME_CLIENT_HELLO, ch))

    tr = n.Transcript()
    tr.add_frame_type(n.FRAME_CLIENT_HELLO)
    tr.add_tlv(TLV_PROFILE_OFFER, bytes([PROFILE_STANDARD]))
    tr.add_tlv(TLV_KEM_OFFER, n.KEM_X25519_MLKEM768.to_bytes(2, "big"))
    tr.add_tlv(TLV_SIG_OFFER, n.SIG_ED25519.to_bytes(2, "big"))
    tr.add_tlv(TLV_AEAD_OFFER, n.AEAD_AES256_GCM.to_bytes(2, "big"))
    tr.add_tlv(TLV_KEM_SHARE, kem_share)

    # --- SERVER_HELLO (cleartext) ---
    sh_wire = _read_frame(transport)
    try:
        sh = n.Frame.unmarshal(sh_wire)
    except n.FrameError as exc:
        raise _proto(f"SERVER_HELLO parse: {exc}") from exc
    if sh.ftype != n.FRAME_SERVER_HELLO:
        raise _proto("expected SERVER_HELLO")
    sh_vals = _require_tlvs(
        _decode_tlvs(sh.payload),
        [TLV_PROFILE_SELECT, TLV_KEM_SELECT, TLV_SIG_SELECT, TLV_AEAD_SELECT, TLV_KEM_CIPHERTEXT],
    )
    _require_standard_select(sh_vals)
    kem_ct = sh_vals[4]
    tr.add_frame_type(n.FRAME_SERVER_HELLO)
    tr.add_tlv(TLV_PROFILE_SELECT, sh_vals[0])
    tr.add_tlv(TLV_KEM_SELECT, sh_vals[1])
    tr.add_tlv(TLV_SIG_SELECT, sh_vals[2])
    tr.add_tlv(TLV_AEAD_SELECT, sh_vals[3])
    tr.add_tlv(TLV_KEM_CIPHERTEXT, kem_ct)

    # --- key schedule ---
    mlkem_ss, x_ss = kem.shared_secrets(kem_ct)
    hs = n.derive_handshake_secret(mlkem_ss, x_ss, STANDARD)
    th_kem = tr.hash(STANDARD)
    c_hs, s_hs, _ = n.derive_handshake_traffic_secrets(hs, th_kem, th_kem, STANDARD)

    # --- SERVER_AUTH (sealed under s_hs, s2c) ---
    sa_wire = _read_frame(transport)
    sa = _parse_enc_frame(sa_wire, n.FRAME_SERVER_AUTH)
    sa_pt = _open_frame(sa, s_hs, DIR_S2C)
    sid, scv, sfin = _decode_auth(sa_pt)
    tr.add_frame_type(n.FRAME_SERVER_AUTH)
    tr.add_tlv(TLV_IDENTITY_KEY, sid)
    server_vk = _vk_from(sid)
    if not n.verify_cert_verify(server_vk, True, tr.hash(STANDARD), scv):
        raise _proto("server CertVerify rejected")
    tr.add_tlv(TLV_CERT_VERIFY, scv)
    s_fin_key = n.derive_finished_key(s_hs, STANDARD)
    if not n.verify_finished(s_fin_key, tr.hash(STANDARD), sfin, STANDARD):
        raise _proto("server Finished rejected")
    tr.add_tlv(TLV_FINISHED, sfin)
    peer_identity = _to32(sid)
    if expected_peer is not None and not _hmac.compare_digest(peer_identity, expected_peer):
        raise _proto("server identity does not match the pinned key")

    # --- CLIENT_AUTH (sealed under c_hs, c2s) ---
    tr.add_frame_type(n.FRAME_CLIENT_AUTH)
    tr.add_tlv(TLV_IDENTITY_KEY, client_pub)
    c_cv = n.sign_cert_verify(identity, False, tr.hash(STANDARD))
    tr.add_tlv(TLV_CERT_VERIFY, c_cv)
    th_ccv = tr.hash(STANDARD)
    c_fin_key = n.derive_finished_key(c_hs, STANDARD)
    c_fin = n.compute_finished(c_fin_key, th_ccv, STANDARD)
    ca_pt = _encode_auth(client_pub, c_cv, c_fin)
    ca_wire = _seal_frame(c_hs, DIR_C2S, n.CHAN_CONTROL, 0, n.FRAME_CLIENT_AUTH, ca_pt)
    _write_frame(transport, ca_wire)

    _, _, master = n.derive_handshake_traffic_secrets(hs, th_kem, th_ccv, STANDARD)
    return Session(master, peer_identity, DIR_C2S, DIR_S2C)


def _accept_with_ephemeral(transport, identity, expected_peer, mlkem_encap_m: bytes, x25519_priv_bytes: bytes) -> Session:
    server_pub = identity.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    tr = n.Transcript()

    # --- CLIENT_HELLO ---
    ch_wire = _read_frame(transport)
    try:
        ch = n.Frame.unmarshal(ch_wire)
    except n.FrameError as exc:
        raise _proto(f"CLIENT_HELLO parse: {exc}") from exc
    if ch.ftype != n.FRAME_CLIENT_HELLO:
        raise _proto("expected CLIENT_HELLO")
    ch_vals = _require_tlvs(
        _decode_tlvs(ch.payload),
        [TLV_PROFILE_OFFER, TLV_KEM_OFFER, TLV_SIG_OFFER, TLV_AEAD_OFFER, TLV_KEM_SHARE],
    )
    _require_standard_offer(ch_vals)
    kem_share = ch_vals[4]
    tr.add_frame_type(n.FRAME_CLIENT_HELLO)
    tr.add_tlv(TLV_PROFILE_OFFER, ch_vals[0])
    tr.add_tlv(TLV_KEM_OFFER, ch_vals[1])
    tr.add_tlv(TLV_SIG_OFFER, ch_vals[2])
    tr.add_tlv(TLV_AEAD_OFFER, ch_vals[3])
    tr.add_tlv(TLV_KEM_SHARE, kem_share)

    # --- SERVER_HELLO ---
    kem_ct, mlkem_ss, x_ss = _encapsulate(kem_share, mlkem_encap_m, x25519_priv_bytes)
    sh = (
        _tlv(TLV_PROFILE_SELECT, bytes([PROFILE_STANDARD]))
        + _tlv(TLV_KEM_SELECT, n.KEM_X25519_MLKEM768.to_bytes(2, "big"))
        + _tlv(TLV_SIG_SELECT, n.SIG_ED25519.to_bytes(2, "big"))
        + _tlv(TLV_AEAD_SELECT, n.AEAD_AES256_GCM.to_bytes(2, "big"))
        + _tlv(TLV_KEM_CIPHERTEXT, kem_ct)
    )
    _write_frame(transport, _cleartext_frame(n.FRAME_SERVER_HELLO, sh))
    tr.add_frame_type(n.FRAME_SERVER_HELLO)
    tr.add_tlv(TLV_PROFILE_SELECT, bytes([PROFILE_STANDARD]))
    tr.add_tlv(TLV_KEM_SELECT, n.KEM_X25519_MLKEM768.to_bytes(2, "big"))
    tr.add_tlv(TLV_SIG_SELECT, n.SIG_ED25519.to_bytes(2, "big"))
    tr.add_tlv(TLV_AEAD_SELECT, n.AEAD_AES256_GCM.to_bytes(2, "big"))
    tr.add_tlv(TLV_KEM_CIPHERTEXT, kem_ct)

    # --- key schedule ---
    hs = n.derive_handshake_secret(mlkem_ss, x_ss, STANDARD)
    th_kem = tr.hash(STANDARD)
    c_hs, s_hs, _ = n.derive_handshake_traffic_secrets(hs, th_kem, th_kem, STANDARD)

    # --- SERVER_AUTH (sealed under s_hs, s2c) ---
    tr.add_frame_type(n.FRAME_SERVER_AUTH)
    tr.add_tlv(TLV_IDENTITY_KEY, server_pub)
    s_cv = n.sign_cert_verify(identity, True, tr.hash(STANDARD))
    tr.add_tlv(TLV_CERT_VERIFY, s_cv)
    s_fin_key = n.derive_finished_key(s_hs, STANDARD)
    s_fin = n.compute_finished(s_fin_key, tr.hash(STANDARD), STANDARD)
    tr.add_tlv(TLV_FINISHED, s_fin)
    sa_pt = _encode_auth(server_pub, s_cv, s_fin)
    sa_wire = _seal_frame(s_hs, DIR_S2C, n.CHAN_CONTROL, 0, n.FRAME_SERVER_AUTH, sa_pt)
    _write_frame(transport, sa_wire)

    # --- CLIENT_AUTH (sealed under c_hs, c2s) ---
    ca_wire = _read_frame(transport)
    ca = _parse_enc_frame(ca_wire, n.FRAME_CLIENT_AUTH)
    ca_pt = _open_frame(ca, c_hs, DIR_C2S)
    cid, ccv, cfin = _decode_auth(ca_pt)
    tr.add_frame_type(n.FRAME_CLIENT_AUTH)
    tr.add_tlv(TLV_IDENTITY_KEY, cid)
    client_vk = _vk_from(cid)
    if not n.verify_cert_verify(client_vk, False, tr.hash(STANDARD), ccv):
        raise _proto("client CertVerify rejected")
    tr.add_tlv(TLV_CERT_VERIFY, ccv)
    th_ccv = tr.hash(STANDARD)
    c_fin_key = n.derive_finished_key(c_hs, STANDARD)
    if not n.verify_finished(c_fin_key, th_ccv, cfin, STANDARD):
        raise _proto("client Finished rejected")
    peer_identity = _to32(cid)
    if expected_peer is not None and not _hmac.compare_digest(peer_identity, expected_peer):
        raise _proto("client identity does not match the pinned key")

    _, _, master = n.derive_handshake_traffic_secrets(hs, th_kem, th_ccv, STANDARD)
    return Session(master, peer_identity, DIR_S2C, DIR_C2S)


# ---------------------------------------------------------------------------
# An in-memory, thread-safe, full-duplex byte transport: two `Duplex` ends
# connected by a pair of queues. Useful for same-process tests, and for a
# consumer wiring two `Session`s together inside one process without a real
# socket.
# ---------------------------------------------------------------------------
class Duplex:
    """One end of an in-memory full-duplex byte pipe (see
    :func:`duplex_pair`). Implements the blocking ``read(n)``/``write(data)``
    pair :class:`Session` needs from a transport."""
    __slots__ = ("_tx", "_rx", "_pending", "_eof")

    def __init__(self, tx: "_queue.Queue", rx: "_queue.Queue"):
        self._tx = tx
        self._rx = rx
        self._pending = bytearray()
        self._eof = False

    def read(self, want: int) -> bytes:
        if want <= 0:
            return b""
        while len(self._pending) < want and not self._eof:
            chunk = self._rx.get()
            if chunk is None:  # the peer closed its write side
                self._eof = True
                break
            self._pending += chunk
        take = min(want, len(self._pending))
        out = bytes(self._pending[:take])
        del self._pending[:take]
        return out

    def write(self, data: bytes) -> int:
        self._tx.put(bytes(data))
        return len(data)

    def close(self) -> None:
        """Signals end-of-stream to the peer's blocked/future reads."""
        self._tx.put(None)


def duplex_pair():
    """Builds a connected pair of in-memory, full-duplex transports: bytes
    written to one end arrive, in order, on the other end's `read`. No
    network, no filesystem -- the pair lives entirely in process memory,
    backed by two `queue.Queue` instances. Intended for same-process
    client/server wiring (tests, or a caller that wants two `Session`s
    without a real socket); each end is safe to hand to a separate thread."""
    qa: "_queue.Queue" = _queue.Queue()
    qb: "_queue.Queue" = _queue.Queue()
    return Duplex(qa, qb), Duplex(qb, qa)
