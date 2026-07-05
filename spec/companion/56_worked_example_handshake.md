# NPAMP-EX-HANDSHAKE — Worked Example: One Complete Standard-Profile Handshake (companion to draft-bubblefish-npamp-01)

> Status: **DRAFT companion specification (informative).** The key words "MUST",
> "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT",
> "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as
> described in BCP 14 (RFC 2119, RFC 8174) when, and only when, they appear in all
> capitals, as shown here. This document is a **developer-facing worked example**:
> It walks one complete N-PAMP draft-00 association at the **Standard profile** —
> the four handshake flights, the transcript points, the key-schedule stages, both
> authentication flights, and one application frame exchange — with real numbers.
> It defines no new wire behavior and consumes no code points. Requirement words
> that appear here restate the cited sources; on any disagreement the core
> specification (`../../ietf/draft-bubblefish-npamp-latest.md`), the handshake binding
> (`../10_handshake_binding.md`), and the pinned test-vector corpus
> (`../../test-vectors/v1/`) govern.

## 1. Scope and provenance discipline

### 1.1 In scope

A byte-level narrative of one 1.5-RTT mutually-authenticated association at the
Standard profile (profile `0x01`): CLIENT_HELLO → SERVER_HELLO + SERVER_AUTH →
CLIENT_AUTH, followed by one encrypted application request/response. Every number
in this document carries a provenance tag:

| Tag | Meaning |
|---|---|
| **[KAT:kem-wire]** | Pinned in `test-vectors/v1/kem-wire-kat.json` (NIST ACVP / RFC 7748 values). |
| **[KAT:transcript]** | Pinned in `test-vectors/v1/transcript-kat.json`. |
| **[KAT:key-schedule]** | Pinned in `test-vectors/v1/key-schedule-kat.json`. |
| **[KAT:finished]** | Pinned in `test-vectors/v1/finished-kat.json`. |
| **[KAT:certverify]** | Pinned in `test-vectors/v1/certverify-kat.json`. |
| **[CORPUS]** | Pinned in `test-vectors/v1/conformance-corpus.json`. |
| **[INTEROP]** | Reproduced from a recorded live inter-implementation capture (not included in this public set). |
| **[REGISTRY]** | From the draft-00 wire-format and registry references (`../02_frame_format.md`, `../05_profiles.md`, `../06_cryptographic_suites.md`, `../07_tlv_registry.md`, `../04_frame_types.md`). |
| **[DERIVED]** | Computed for this document from pinned inputs by the §12 recipe, using an oracle first proven against the RFC anchors carried inside the pinned KAT files. Informative; NOT a pinned vector. |

**This example is a composite, not a single recorded session.** The pinned corpus
deliberately isolates each construction (transcript, key schedule, Finished,
CertVerify, KEM wire order) into its own standards-anchored KAT, and some KAT
inputs are synthetic fixtures rather than one coherent handshake (§13). This
document stitches those pinned pieces into one narrative and says, at every step,
which piece is real cryptography, which is a fixture, and which is derived.

### 1.2 Not in scope

- **High and Sovereign profiles.** This walk-through is Standard-only
  (`H` = SHA-256, `HashLen` = 32). The profile parameter table of the handshake
  binding governs the other rows; their operational and cryptographic detail is
  out of scope for this public companion set.
- **New wire behavior.** Nothing here adds to, or deviates from, the handshake
  binding. Where the binding and this document could be read differently, the
  binding wins.
- **A new vector source.** The **[DERIVED]** values in §8 and §11 exist so a
  developer can follow the arithmetic end-to-end. Conformance testing MUST use
  the pinned corpus and its anchor-oracle-impl discipline (§8.3), not this
  document.
- **Bridge/companion payload semantics.** What the application payload *means*
  (memory writes, bridge envelopes) belongs to the channel and companion
  specifications; here it is only sealed bytes with observed lengths.

## 2. The frame envelope in one minute

Every N-PAMP frame begins with the fixed 36-octet header of `../02_frame_format.md`
(core draft §4); multi-octet integers are big-endian:

```
octets 0-3   Magic        "NPAM" (4E 50 41 4D)
octet  4     Ver|Flags    high nibble = wire version 0x2; low nibble = flags
octets 5-6   Frame Type   uint16
octets 7-8   Channel ID   uint16
octets 9-16  Sequence     uint64, per-(channel, direction), starts at 0
octets 17-20 Payload Len  uint32
octets 21-24 CRC32C       Castagnoli 0x1EDC6F41 over octets 0-20
octets 25-35 Reserved     11 octets, MUST be zero
```

Flags: `0x01` URG, `0x02` ENC (payload AEAD-sealed), `0x04` COMP, `0x08` FRAG.
TLVs are `Type(2, BE) ‖ Length(2, BE) ‖ Value`. **[REGISTRY]**

The conformance corpus pins a golden header — a PING on the Control channel,
seq 0, empty payload — whose CRC32C is `0d880c25`: **[CORPUS]** (tcId 1/10/20)

```
4e50414d 20 0001 0000 0000000000000000 00000000 0d880c25 00×11
```

Reassembling that header field-by-field and recomputing the Castagnoli CRC over
octets 0–20 reproduces `0d880c25` exactly; the same anchored CRC oracle is used
for every derived header below (§12 recipe, check A5).

## 3. The four flights at a glance

The handshake is four frames on the Control channel (`0x0000`), seq 0, a 1.5-RTT
exchange in which both peers authenticate. There is no separate Finished frame —
the Finished MAC is a TLV inside each AUTH frame. (Binding §1.)

```
client ── CLIENT_HELLO (0x0100), cleartext ─────────────▶ server
client ◀── SERVER_HELLO (0x0101), cleartext ──────────── server
       ◀── SERVER_AUTH  (0x0102), ENCRYPTED ──────────── server
client ── CLIENT_AUTH  (0x0103), ENCRYPTED ─────────────▶ server
```

The 2026-06-23 live capture (48 frames, recomputed-CRC-validated, taken from the
agent's own process) recorded exactly this shape for a real association between
the Go daemon and the TypeScript client: **[INTEROP]**

```
SEND  magic=NPAM ver=0x2 flags=0x0      type=0x0100(CLIENT_HELLO) chan=0x0000 seq=0 payloadLen=1245 total=1281
RECV  magic=NPAM ver=0x2 flags=0x0      type=0x0101(SERVER_HELLO) chan=0x0000 seq=0 payloadLen=1147 total=1183
RECV  magic=NPAM ver=0x2 flags=0x2/ENC  type=0x0102(SERVER_AUTH)  chan=0x0000 seq=0 payloadLen=158  total=194
SEND  magic=NPAM ver=0x2 flags=0x2/ENC  type=0x0103(CLIENT_AUTH)  chan=0x0000 seq=0 payloadLen=158  total=194
SEND  magic=NPAM ver=0x2 flags=0x2/ENC  type=0x0120(APP_REQUEST)  chan=0x0001 seq=0 payloadLen=570  total=606
RECV  magic=NPAM ver=0x2 flags=0x2/ENC  type=0x0121(APP_RESPONSE) chan=0x0001 seq=0 payloadLen=85   total=121
```

Every one of those payload lengths is reconciled byte-for-byte in the sections
below. Two observations from the capture worth fixing in mind now:

- **Cleartext flights carry no AEAD tag.** `total = 36 + payloadLen` throughout,
  and for the HELLO flights the payload length is fully accounted for by TLV
  bytes alone (§4.3, §5.2). The binding marks these flights "cleartext /
  Encryption: none".
- **For ENC frames the recorded payload length is the sealed length** —
  plaintext TLV bytes plus the 16-octet AES-256-GCM tag (§9.4: 142 + 16 = 158).

## 4. Flight 1 — CLIENT_HELLO (`0x0100`, cleartext)

### 4.1 TLVs, in order

| # | TLV | Tag | Value (Standard-profile association) |
|---|-----|-----|--------------------------------------|
| 1 | ProfileOffer | `0x01` | Profiles the client offers; ProfileOffer is variable, one octet per profile (all three offered: 0x01 0x02 0x03). **[REGISTRY]** |
| 2 | KEMOffer | `0x03` | KEM code points offered; `0x11ec` = X25519MLKEM768. **[REGISTRY]** |
| 3 | SigOffer | `0x05` | Signature schemes offered; `0x0807` = Ed25519. **[REGISTRY]** |
| 4 | AEADOffer | `0x0C` | AEAD code points offered; `0x0001` = AES-256-GCM, `0x0002` = ChaCha20-Poly1305. **[REGISTRY]** (tag from binding §1.1) |
| 5 | KEMShare | `0x07` | The hybrid public share, 1216 octets (§4.2). |

The TLV order above is normative in the binding (§1) and is what the transcript
absorbs (§6).

### 4.2 KEMShare: 1216 octets, ML-KEM-first

KEM `0x11ec` (X25519MLKEM768). The wire layout is **ML-KEM-first** (ADR-0005;
binding §4), even though the suite *name* lists X25519 first:

```
KEMShare (TLV 0x07) = ML-KEM-768 encapsulation key ek (1184) ‖ X25519 public key (32) = 1216 octets
```

Real component values, both standards-derived: **[KAT:kem-wire]**

- `ek` — the NIST ACVP (FIPS 203 final, ML-KEM-768 keyGen, tgId 2 / tcId 26)
  encapsulation key generated from seed `d ‖ z` with
  `d = E582B7D75E6C80B05AE392A1FC9F7153B12390FD99930368CC67A768BAEBC8A0`,
  `z = 1CDACB8740C0B87C4A379575F187B367CBFA3B300BF591B109F79816E9CBE8F0`;
  `ek = 28C793778741B80B02B4339F2AA4347255B099F17264E1B8CC0A2C7C2A1A79F7…8247`
  (1184 octets; full value in the KAT file).
- X25519 public key — RFC 7748 §6.1 Alice:
  `8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a` (32 octets).

The KEM-wire KAT exists precisely to pin this concatenation order in every
conforming implementation — a symmetric implementation that got the order
backwards would still interoperate with itself, which is why the order is
anchored to NIST/RFC values rather than to another N-PAMP build.

### 4.3 Byte accounting for the observed payload

The live capture recorded `payloadLen=1245` for CLIENT_HELLO. **[INTEROP]** With
single-entry KEM/Sig/AEAD offer lists and all three profiles offered (ProfileOffer
is variable, one octet per profile) — the composition consistent with the
transcript KAT (§6) — the arithmetic closes exactly:

```
ProfileOffer  4+3  =    7      (three profiles: 0x01 0x02 0x03)
KEMOffer      4+2  =    6      (one KEM:  0x11ec)
SigOffer      4+2  =    6      (one sig:  0x0807)
AEADOffer     4+2  =    6      (one AEAD: 0x0001)
KEMShare      4+1216 = 1220
                       ----
                       1245    = observed payloadLen; total 1281 = 36 + 1245, no tag
```

(The capture pins the lengths and the negotiated algorithms — X25519MLKEM768,
Ed25519, AES-256-GCM — not the offer-list bytes themselves; the composition above
is the reconstruction that closes, marked informative.)

## 5. Flight 2 — SERVER_HELLO (`0x0101`, cleartext)

### 5.1 TLVs, in order

| # | TLV | Tag | Value |
|---|-----|-----|-------|
| 1 | ProfileSelect | `0x02` | 1 octet; `0x01` = Standard. **[REGISTRY]** |
| 2 | KEMSelect | `0x04` | `0x11ec`. |
| 3 | SigSelect | `0x06` | `0x0807`. |
| 4 | AEADSelect | `0x0D` | `0x0001` (AES-256-GCM) in the live association. **[INTEROP]** |
| 5 | KEMCiphertext | `0x08` | 1120 octets (§5.2). |

The server MUST select from the client's offered set (profiles reference,
`../05_profiles.md`). Because offers *and* selections are absorbed into the
transcript that CertVerify signs and Finished MACs (§6, §9), stripping an offer
or forcing a lower selection invalidates the handshake — this is the binding's
downgrade protection (§6.3): transcript binding, not a TLS-style `DOWNGRD`
sentinel.

### 5.2 KEMCiphertext: 1120 octets, ML-KEM-first

The server encapsulates to the client's `ek` and contributes its own X25519
share:

```
KEMCiphertext (TLV 0x08) = ML-KEM-768 ciphertext (1088) ‖ server X25519 public key (32) = 1120 octets
```

Real reference values: the NIST ACVP encapDecap record for the same key
(tgId 2 / tcId 26) pins ciphertext
`c = 04F4A18C69708A17F561778B2AC10D94380ABEA4A20835939C9015D78DAC41A5…16E`
(1088 octets; full value in the KAT file) decapsulating to shared secret
`K = 11B62291B1A9D307C8240D70BE0B45436DB445793173F6E79FCD2B273D7F3B01`; the
X25519 leg uses RFC 7748 §6.1 Bob,
`de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f`, with
published shared secret
`4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742`.
**[KAT:kem-wire]**

At this point both peers hold the 64-octet hybrid secret, ML-KEM-first
(ADR-0005; binding §4):

```
KEM output (IKM) = ML-KEM SS (32) ‖ X25519 SS (32)
                 = 11B62291…7F3B01 ‖ 4a5d9d5b…161742      [KAT:kem-wire]
```

ML-KEM-768 uses implicit rejection: a corrupted ciphertext decapsulates to a
pseudorandom secret that later fails the Finished MAC rather than erroring
here. An all-zero X25519 output is rejected. (Binding §4.)

### 5.3 Byte accounting

Observed `payloadLen=1147`: **[INTEROP]**

```
ProfileSelect 4+1  =    5
KEMSelect     4+2  =    6
SigSelect     4+2  =    6
AEADSelect    4+2  =    6
KEMCiphertext 4+1120 = 1124
                       ----
                       1147   = observed payloadLen; total 1183 = 36 + 1147, no tag
```

## 6. The transcript and its five points

### 6.1 The rule

The transcript is a running byte buffer; a transcript-hash point is `H` (SHA-256
at Standard) over all bytes absorbed so far. Per binding §3 — a deliberate,
documented divergence from RFC 8446 §4.4.1 — each frame contributes:

- **AddFrameType(ft):** the **2-octet big-endian frame type only**. The other 34
  header octets (magic, flags, channel, seq, length, CRC, reserved) and the AEAD
  tag are NOT absorbed.
- **AddTLV(t):** the TLV in canonical `Type(2) ‖ Length(2) ‖ Value` form, one
  call per TLV, in frame order.

Granularity is per-TLV, which is what lets the bundled AUTH frames be hashed at
sub-frame cut points.

### 6.2 The five points, with pinned values

The transcript KAT fixes a complete four-flight TLV sequence and pins the five
points. Its TLV *values* are deterministic fixtures, not live crypto (§13) —
the construction is value-agnostic, so the fixtures isolate exactly what this
KAT is for: byte order, per-TLV granularity, and frame-type-only absorption.
All five values below were re-derived for this document by an independent
constructor and matched the pinned file. **[KAT:transcript]**

| Point | Absorbed through | Pinned value (SHA-256) |
|-------|------------------|------------------------|
| `TH_kem` | `0x0100 ‖ CH-TLVs ‖ 0x0101 ‖ SH-TLVs` | `adf9ee3f12a81a894a93b9040d15fe3e66905011456cd333dfe62bc6e1e4aaf2` |
| `TH_sId` | `… ‖ 0x0102 ‖ ServerIdentityKey` | `e71beafbba82bdb7ab41a5940ba106d90637bf8339dcb4db596fd635bb24c84c` |
| `TH_sCV` | `… ‖ ServerCertVerify` (excludes ServerFinished) | `8763eb95348b9e52c97a722470f7af4aff401faac2c3388210ba6c70e09cd440` |
| `TH_cId` | `… ‖ ServerFinished ‖ 0x0103 ‖ ClientIdentityKey` | `7447a1770de3aa9fee0196a407fdcf5b5012dcb95af22330c965f21426fba386` |
| `TH_cCV` | `… ‖ ClientCertVerify` (excludes ClientFinished) | `09c24d05e6d8082a85d930892b780469a3a7535d97e9c328dabdec2a1bdd0d2d` |

Who consumes which point (binding §3, §5, §6):

- `TH_kem` → contexts of the `c hs` / `s hs` handshake-secret derivations (§8).
- `TH_sId` → what the **server's CertVerify signs** (§9.2).
- `TH_sCV` → what the **server's Finished MACs** (§9.3).
- `TH_cId` → what the **client's CertVerify signs** (§10).
- `TH_cCV` → what the **client's Finished MACs**, and the context of `master` (§8).

Both peers absorb identical decoded on-wire TLV bytes, so the transcripts are
byte-identical on both sides.

## 7. Interlude — what each side knows after the cleartext flights

After SERVER_HELLO, both sides hold: the negotiated parameter set (Standard,
`0x11ec`, `0x0807`, AEAD), the 64-octet hybrid secret (§5.2), and the same
transcript through `TH_kem`. Nothing has been authenticated yet — that is the
job of the two encrypted AUTH flights, which need keys first.

## 8. Key schedule

### 8.1 The construction

A **single** HKDF-Extract followed by sibling HKDF-Expand-Label derivations
(binding §5 — deliberately simpler than RFC 8446 §7.1's three-stage chain; there
is no PSK/0-RTT in this binding). HKDF-Expand-Label is RFC 8446 §7.1 with the
label prefix `"n-pamp "` (trailing space) replacing `"tls13 "`:

```
handshake_secret = HKDF-Extract(salt = 32×0x00, IKM = ML-KEM_SS ‖ X25519_SS)
c_hs_secret      = HKDF-Expand-Label(handshake_secret, "c hs",   TH_kem, 32)
s_hs_secret      = HKDF-Expand-Label(handshake_secret, "s hs",   TH_kem, 32)
master           = HKDF-Expand-Label(handshake_secret, "master", TH_cCV, 32)

traffic_secret   = HKDF-Expand-Label(parent, "traffic", ctx, 32)
                   ctx = dir(1) ‖ epoch(8 BE) ‖ suite(2 BE) ‖ channel(2 BE)
(key, iv)        = (HKDF-Expand-Label(traffic_secret, "key", "", 32),
                    HKDF-Expand-Label(traffic_secret, "iv",  "", 12))
finished_key     = HKDF-Expand-Label(c_hs/s_hs per direction, "finished", "", 32)
```

Handshake-phase traffic keys descend from `c_hs`/`s_hs` (epoch 0, Control
channel `0x0000`); application-phase keys descend from `master`, which is
derived only at the client-auth boundary from `TH_cCV`. Because the parents
differ, identical `(dir, epoch, suite, channel)` tuples yield different keys
across phases. (Binding §5.)

The direction octet is `0` for client→server and `1` for server→client, as
fixed by the reference implementations and exercised by the cross-language KAT
harness (`impl/go/keyschedule.go` `DirClientToServer = 0` /
`DirServerToClient = 1`; `impl/_conformance-harness/kat-handshake-all-langs.sh`).
The binding's prose does not yet enumerate these two octet values — a known
textual gap noted for draft-01.

### 8.2 Worked bytes: one HkdfLabel

For `c_hs` with the key-schedule KAT's inputs, the exact `HkdfLabel` (the
`info` argument to HKDF-Expand) is: **[DERIVED]** (structure per RFC 8446 §7.1,
pinned in the KAT's `rfc8446_7_1` description)

```
0020                       uint16 output length = 32
0b                         label length = 11
6e2d70616d702063206873     "n-pamp c hs" (the 11 UTF-8 octets of prefix + label)
20                         context length = 32
00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff   TH_kem context
```

i.e. `info = 00200b6e2d70616d70206320687320` ‖ `00112233…ddeeff` (47 octets). The
`"traffic"` context for the server→client handshake key on the Control channel
is `01 0000000000000000 0001 0000` — dir `01`, epoch 0, suite `0x0001`
(AES-256-GCM), channel `0x0000`. **[DERIVED]**

### 8.3 The corpus discipline — and this document's worked numbers

The key-schedule KAT stores **inputs and RFC anchors, never N-PAMP output
bytes** (its stated provenance): implementation-produced outputs would be
circular. A conforming implementation proves an independent HKDF-Expand-Label
oracle against RFC 8448 §3 (`"tls13 "` prefix: `write_key dbfaa693…`,
`write_iv 5bd3c71b…`, `finished_key b80ad010…` from
`client_handshake_traffic_secret b3eddb12…`) and RFC 5869 A.1 TC1
(`prk 07770936…`, `okm 3cb25f25…`), then applies the proven oracle with the
`"n-pamp "` prefix to judge itself. **[KAT:key-schedule]**

Its pinned N-PAMP inputs are: **[KAT:key-schedule]**

```
ikm_mlkem_ss  = 11B62291B1A9D307C8240D70BE0B45436DB445793173F6E79FCD2B273D7F3B01   (the NIST K of §5.2)
ikm_x25519_ss = 4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742   (the RFC 7748 SS of §5.2)
th_kem        = 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff   (synthetic fixture)
th_ccv        = ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100   (synthetic fixture)
```

Note the KEM secrets are the *real* standards values, giving continuity with
§5.2; the two transcript-hash inputs are synthetic fixtures and are **not** the
§6.2 transcript-KAT points (the two KATs isolate different constructions; §13).

Applying the §8.1 construction to those pinned inputs — with an oracle that
first reproduced the RFC 5869 and RFC 8448 anchors above — yields, for this
document: **[DERIVED]**

| Stage | Value |
|-------|-------|
| `handshake_secret` | `4e79b07c4e0016e29566e5423a62178025bd2f08125e187b0957d40336e49719` |
| `c_hs_secret` | `2797172e325aed8a4f141dfaaa70ba692b9f31597567a8dfd7a939a9851e9754` |
| `s_hs_secret` | `404ec1a0b2dc7c7106266949299716c2c03bffd24a41870aec99efea4aaad4bd` |
| `master` | `fb55092aadf2e28d3910a4f1be197266f8e92635d876f02ca038b728f9b036ac` |
| `finished_key` (client, from `c_hs`) | `94e8d5c8d82f9594f15590abf6564d475d5531500b78a57e2fdca45f54abb616` |
| `finished_key` (server, from `s_hs`) | `84024b8ac6bdc671a559bfc446d09750df1c1890cbd1acca98eaca7f1554c74a` |
| Hs traffic secret c→s (dir 0, epoch 0, suite `0x0001`, chan `0x0000`) | `3afb8726344c92d734947a69746f81081d313a84d1221e27e6a8adbe00cbdf69` |
| Hs key / iv c→s | `7d9bcfada23691cfa4482af649f277f626f35736e8fa16b51298c729e6bb8bef` / `3cb042dcb89bd5db3483f4aa` |
| Hs traffic secret s→c (dir 1, epoch 0, suite `0x0001`, chan `0x0000`) | `67096bcc8098b5686659bf5cc3ee87ae2a74f1f63ec328722107362d261ac7a1` |
| Hs key / iv s→c | `de2e503ac33421f7cc6f9eb86dfe52749236cbd36b868b202150bbc0a5f32b16` / `fa0d07bfc1358a402a97d0b6` |

These bytes are reproducible from the pinned inputs by anyone following §12.
They MUST NOT be pasted into a conformance suite as golden values — the corpus's
anchor→oracle→impl discipline exists so that each implementation is graded
against the RFCs, not against another N-PAMP build (or this document).

## 9. Flight 3 — SERVER_AUTH (`0x0102`, encrypted)

### 9.1 Sealing

SERVER_AUTH is AEAD-sealed under the **server→client handshake** key/iv:
`Flags = ENC (0x02)`, `Channel = 0x0000`, `Seq = 0`; AAD = the 21-octet frame
header prefix (octets 0–20, the same octets the CRC covers); nonce = `iv XOR
left-zero-padded seq` — with seq 0, the nonce **is** the IV. AES-256-GCM at the
Standard association. On open, exactly three TLVs in this order are required:
IdentityKey, CertVerify, Finished. (Binding §6.4; `../06_cryptographic_suites.md`.)

### 9.2 CertVerify (TLV `0x0A`): sign the transcript

Structure per RFC 8446 §4.4.3 with N-PAMP context strings (binding §6.1):

```
signing_input = 0x20 × 64 ‖ context ‖ 0x00 ‖ transcript_hash
context (server) = "N-PAMP draft-00, server CertificateVerify"
TLV value = SignatureScheme uint16 (Ed25519 = 0x0807) ‖ signature
```

The server signs `TH_sId` — the transcript through its own IdentityKey, before
its own CertVerify. Worked numbers, all pinned: **[KAT:certverify]**

- Server identity keypair = RFC 8032 §7.1 TEST 1: seed
  `9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60`, public key
  `d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a`. At the
  Standard profile the IdentityKey TLV (`0x09`) carries this 32-octet Ed25519
  public key.
- `signing_input` (server) =
  `2020…20` (64 octets) ‖ `4e2d50414d502064726166742d30302c2073657276657220436572746966696361746556657269667900` ("N-PAMP draft-00, server CertificateVerify" + the 0x00 separator) ‖ `e71beafb…24c84c` (`TH_sId`) — 64 + 41 + 1 + 32 = 138 octets, pinned in full in the KAT.
- Ed25519 signature (deterministic, so any conforming signer reproduces it):
  `504cb67cf28d4fc9a8db676465359e6b27a19b1c5d63600923219879d02c963ff41fe1bb681da3f6057285ddf4fed6c86a6db5d60472ac4b04c3b7105c4d6906`
- CertVerify TLV value = `0807` ‖ signature = 66 octets.

A verifier MUST reject a scheme it did not negotiate, and the differing context
string makes a server CertVerify unusable as a client one (role/domain
separation) — the pinned KAT's consuming tests include exactly those rejection
checks.

### 9.3 Finished (TLV `0x0B`): MAC the transcript

Per RFC 8446 §4.4.4, keyed by the sender's handshake traffic secret
(binding §6.2):

```
finished_key = HKDF-Expand-Label(s_hs_secret, "finished", "", 32)
verify_data  = HMAC-SHA256(finished_key, TH_sCV)
```

Worked numbers from the Finished KAT (its `finished_key` values are fixtures —
derivation of a real `finished_key` is the key-schedule KAT's job, §8):
**[KAT:finished]**

```
finished_key (server fixture) = 5f5f…5f (32 octets)
TH_sCV                        = 8763eb95348b9e52c97a722470f7af4aff401faac2c3388210ba6c70e09cd440
verify_data (server)          = 6cae594ab29bb8d968d8800d469c685b4581a8fd49d9a53951ef0964cc4fbd9b
```

`verify_data` is `HashLen` = 32 octets at Standard, which is why the Finished
TLV is variable-length (binding §1.1). Verification MUST be constant-time and
abort on mismatch.

### 9.4 Byte accounting for the observed frame

Observed `payloadLen=158` for SERVER_AUTH: **[INTEROP]**

```
IdentityKey  TLV  4+32 =  36
CertVerify   TLV  4+66 =  70
Finished     TLV  4+32 =  36
                        ----
plaintext TLV bytes      142
+ AES-256-GCM tag         16
                        ----
sealed payload           158   = observed payloadLen; total 194 = 36 + 158
```

## 10. Flight 4 — CLIENT_AUTH (`0x0103`, encrypted)

The mirror image, sealed under the **client→server handshake** key/iv, same
three-TLV layout, same observed 158-octet sealed payload. **[INTEROP]** The
client-side worked numbers: **[KAT:certverify]** / **[KAT:finished]**

- Client identity keypair = RFC 8032 §7.1 TEST 2: seed
  `4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb`, public key
  `3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c`.
- The client signs `TH_cId` (`7447a177…6fba386`) under context
  `"N-PAMP draft-00, client CertificateVerify"`; signature
  `1c20ff13f0eb4b3c4df0f82dc04849ceae558392e1a81f22e167124255ad26dd38982fa3dd7967a03197fd0f5be1c387543567016f1b8cd3189275c6ee550406`;
  CertVerify TLV value = `0807` ‖ signature.
- The client's Finished MACs `TH_cCV` (`09c24d05…dd0d2d`); with the KAT's
  client fixture key `5c5c…5c`,
  `verify_data (client) = 02ebf8c1b7fc428a3bf4465945c69dd2d1382318e856fd7204d0b9db445e2ee3`.

**The client-auth boundary is where `master` exists.** `master` is derived from
`TH_cCV` (§8.1), so the server reaches the keyed/Established state only after
CLIENT_AUTH verifies (binding §1, §5). At this point both peers have mutually
authenticated: each signed its own transcript point, each MAC'd the transcript
through its own CertVerify, and every negotiation byte from the cleartext
flights is bound into both.

## 11. One application frame exchange

With `master` in hand, application-phase traffic keys are derived per
`(dir, epoch, suite, channel)`. The live capture's application exchange ran on
the Memory channel (`0x0001`), frame types `0x0120` APP_REQUEST /
`0x0121` APP_RESPONSE (channel-specific space, ≥ `0x0100`), seq 0 per channel
and direction, both ENC: **[INTEROP]**

```
SEND  flags=0x2/ENC  type=0x0120(APP_REQUEST)  chan=0x0001 seq=0 payloadLen=570 total=606
RECV  flags=0x2/ENC  type=0x0121(APP_RESPONSE) chan=0x0001 seq=0 payloadLen=85  total=121
```

Mechanics of the request frame, exactly as in §9.1 but with application keys:
AAD = its own 21-octet header prefix; nonce = application IV XOR seq (= the IV,
seq being 0); AES-256-GCM tag inside the sealed payload. In a recorded
exchange the payload was an application memory write that persisted to storage and was
independently read back, together with the negative controls (plaintext HTTP rejected,
wrong ALPN rejected, wrong pinned server key rejected). The per-frame evidence is not
duplicated here.

Continuing this document's worked-fixture universe (the §8.3 `master`),
the application-phase derivations for that channel are: **[DERIVED]**

| Quantity (epoch 0, suite `0x0001`, chan `0x0001`) | Value |
|---|---|
| App traffic secret c→s (dir 0) | `38b7a91e3f14dbe5c6ae377be7299e15bfcff9ceb809c2891d06cc48b21b53c9` |
| App key / iv c→s | `c14daaeeb89c891c0bdc3e98924cbc599b4cb7e9a51bf4e4bdd5e98f29bce67a` / `1341e3cae7833c80098b38ab` |
| App traffic secret s→c (dir 1) | `619ec17947a0f52c91098e7a90e53afade410076de6383b4bb93b96d56ed6380` |
| App key / iv s→c | `9f88c338af7e135a0950311113ec5e75ed29e8a2c68b427cf0cd455aad7b0c0d` / `d1074e0715b9a612803c1f1a` |

Note these keys share `(dir, epoch, suite)` shape with §8.3's handshake keys but
differ because the parent differs (`master` vs `c_hs`/`s_hs`) and the channel
differs — the no-shared-(key,nonce)-across-phases property of binding §5, and
the per-channel key isolation of the core suites section, made concrete.

For completeness, the six 36-octet headers of this walk-through's association,
assembled from the capture's recorded fields with the CRC32C recomputed by the
§2-anchored oracle: **[DERIVED]** (fields **[INTEROP]**)

```
CLIENT_HELLO  4e50414d 20 0100 0000 0000000000000000 000004dd ba7b307e 00×11
SERVER_HELLO  4e50414d 20 0101 0000 0000000000000000 0000047b 591f9f31 00×11
SERVER_AUTH   4e50414d 22 0102 0000 0000000000000000 0000009e d60efd56 00×11
CLIENT_AUTH   4e50414d 22 0103 0000 0000000000000000 0000009e b1800057 00×11
APP_REQUEST   4e50414d 22 0120 0001 0000000000000000 0000023a a258e10a 00×11
APP_RESPONSE  4e50414d 22 0121 0001 0000000000000000 00000055 dd4683a3 00×11
```

(`20` = ver 2, flags 0; `22` = ver 2, flags ENC. The capture validated its 48
frames by recomputing CRC32C; these six headers reproduce the recorded field
values with the CRC recomputed the same way.)

## 12. Reproducing every [DERIVED] value

All derived values in this document were produced by a script that refuses to
emit anything until its oracles pass the anchors **pinned inside the corpus
files themselves** — the same three-leg discipline the KATs impose on
implementations:

1. **Anchor the hash:** SHA-256("abc") == `ba7816bf…0015ad` (FIPS 180-4 anchor
   in the transcript KAT).
2. **Anchor HKDF:** RFC 5869 A.1 TC1 Extract/Expand (anchor in the key-schedule
   KAT).
3. **Anchor Expand-Label:** RFC 8448 §3 key/iv/finished with the `"tls13 "`
   prefix (anchor in the key-schedule KAT).
4. **Anchor HMAC:** RFC 4231 TC1/TC2 (anchor in the Finished KAT).
5. **Anchor CRC32C:** corpus `crc32c` tcId 20 and the golden PING header
   (tcId 1/10).
6. Only then: apply HKDF-Expand-Label with prefix `"n-pamp "` to the pinned
   `npamp_inputs` (§8.3), rebuild the transcript per §6.1 and require all five
   pinned `TH_*` points to match, recompute both pinned `verify_data` values,
   rebuild both pinned `signing_input` values (and verify both pinned Ed25519
   signatures against the RFC 8032 public keys), and assemble the §11 headers.

Sketch (any language; stdlib HMAC/SHA-256 suffices for all but the Ed25519
verify):

```
expand_label(secret, label, ctx, L):
    full = "n-pamp " + label
    info = uint16(L) ‖ uint8(len(full)) ‖ full ‖ uint8(len(ctx)) ‖ ctx
    return HKDF-Expand(secret, info, L)          # HKDF per RFC 5869, SHA-256

hs     = HKDF-Extract(salt=32×00, ikm_mlkem_ss ‖ ikm_x25519_ss)
c_hs   = expand_label(hs, "c hs",   th_kem, 32)
s_hs   = expand_label(hs, "s hs",   th_kem, 32)
master = expand_label(hs, "master", th_ccv, 32)
ts     = expand_label(parent, "traffic", dir(1)‖epoch(8)‖suite(2)‖chan(2), 32)
key,iv = expand_label(ts, "key", "", 32), expand_label(ts, "iv", "", 12)
```

The cross-language reference implementations under `impl/` run this same
discipline as executable tests, gated by
`impl/_conformance-harness/kat-handshake-all-langs.sh`; the Go reference is
exercised by its own KATs (binding §8).

## 13. Limitations and honest scope

- **Composite, not a session.** No single recorded association produced all the
  bytes above. The KEM values are NIST/RFC standards vectors; the transcript
  KAT's TLV values are deterministic fixtures ("not crypto-real", per its
  provenance note); the Finished KAT's `finished_key`s are fixtures; the
  key-schedule KAT's `th_kem`/`th_ccv` inputs are synthetic and are **not** the
  transcript KAT's `TH_kem`/`TH_cCV`. Where the pieces do interlock, they
  interlock exactly: the key-schedule IKM halves equal the KEM-wire KAT's NIST
  `K` and RFC 7748 shared secret, and the CertVerify/Finished KATs consume the
  transcript KAT's real pinned points. All of these identities were re-checked
  byte-for-byte in producing this document.
- **Fixture realism.** The transcript-KAT fixtures use realistic TLV lengths
  (KEMShare 1216, KEMCiphertext 1120, IdentityKey 32, CertVerify 66,
  Finished 32); its ProfileOffer fixture is 3 octets (all three profiles under the
  variable-length ProfileOffer), and its AEAD fixture code point (`0x0002`)
  differs from the live association's (`0x0001`). The transcript construction
  is value- and length-agnostic, so neither affects what that KAT pins.
- **What the capture pins vs. what is reconstructed.** The interop capture pins
  header fields and payload lengths of real frames; it does not record cleartext
  offer-list bytes or sealed plaintexts. The §4.3/§5.3/§9.4 decompositions are
  arithmetic reconstructions that close exactly against the registry TLV lengths and
  the variable-length ProfileOffer; the
  §11 header hexes recompute the CRC over recorded fields.
- **ML-KEM decapsulation-value anchoring.** The NIST decaps leg (`c` → `K`)
  requires importing an expanded 2400-octet decapsulation key, which Go's
  public `crypto/mlkem` cannot; the KEM-wire KAT carries the NIST values and
  documents this as its remaining growth item (binding §8). This document
  inherits that limitation.
- **Not covered at all:** High/Sovereign parameter rows; key updates/epochs
  beyond 0; CLOSE and the reserved cross-channel frame types; fragmentation and
  compression flags; TLS-carriage specifics (the capture ran `n-pamp/2` inside
  TLS 1.3 — see `../01_alpn.md`); the reverse-direction application path and
  durability caveats stated in the interop document's own honest-scope section.
- **The `dir` octet values** (`0`/`1`) are grounded in the reference
  implementations and KAT harness, not yet in the binding's prose (§8.1 note).

## 14. Conformance

This document is **informative**. It imposes no requirements beyond those of
the documents it cites, and conformance language reproduced here binds only via
its source. For avoidance of doubt:

1. An implementation conforms to the handshake binding by satisfying
   `../10_handshake_binding.md` and the core specification — never by matching
   this walk-through.
2. Conformance testing MUST use the pinned corpus
   (`../../test-vectors/v1/*.json`) under each KAT's anchor→oracle→impl
   discipline. The **[DERIVED]** values in §8.3 and §11 MUST NOT be used as
   golden conformance vectors; they are reproductions from pinned inputs,
   provided so a developer can check their own arithmetic while reading.
3. If any value in this document is found to disagree with a pinned vector file
   or with the handshake binding, the vector file and the binding are correct
   and this document is in error and MUST be fixed.
