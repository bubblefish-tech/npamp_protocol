# NPAMP-EX-HANDSHAKE — Worked Example: One Complete Standard-Profile Handshake (companion to draft-bubblefish-npamp-01, crypto generation 3 / n-pamp/3)

> Status: **DRAFT companion specification (informative).** The key words "MUST",
> "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT",
> "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as
> described in BCP 14 (RFC 2119, RFC 8174) when, and only when, they appear in all
> capitals, as shown here. This document is a **developer-facing worked example**:
> It walks one complete N-PAMP association at the **Standard profile** and crypto
> generation 3 (`n-pamp/3`; `../01_alpn.md`) — the four handshake flights, the
> transcript points, the key-schedule stages, both authentication flights, and one
> application frame exchange — with real numbers. It defines no new wire behavior
> and consumes no code points. Requirement words that appear here restate the cited
> sources; on any disagreement the core specification (`../../ietf/draft-bubblefish-npamp-latest.md`),
> the handshake binding (`../10_handshake_binding.md`), and the pinned test-vector
> corpus (`../../test-vectors/v1/`) govern.

## 1. Scope and provenance discipline

### 1.1 In scope

A byte-level narrative of one 1.5-RTT mutually-authenticated association at the
Standard profile (profile `0x01`): CLIENT_HELLO → SERVER_HELLO + SERVER_AUTH →
CLIENT_AUTH, followed by one encrypted application request/response. Every number
in this document carries a provenance tag:

| Tag | Meaning |
|---|---|
| **[KAT:handshake-flow]** | Pinned in `test-vectors/v1/handshake-flow-kat.json` (class `golden-interop`, issue #60). **This is the primary byte authority for this document**: the four handshake frames, the AUTH plaintexts, the five transcript points, the full §5/§8 key ladder (including the application-phase secrets), the Finished keys/MACs, and the CertVerify signatures. Produced by the Go reference implementation's real code path and independently re-derived a second time by a non-`npamp.*` inline oracle; both must agree byte-for-byte (F3 non-circularity). Machine-graded by `impl/_conformance-harness/kat-handshake-all-langs.sh` and the per-language `handshake_flow_kat`/`handshakeflow_kat_test.go` tests. |
| **[KAT:kem-wire]** | Pinned in `test-vectors/v1/kem-wire-kat.json` (NIST ACVP / RFC 7748 values). Used only for the §4.2/§5.2 pedagogical demonstration of the ML-KEM-first wire order against externally-anchored standards vectors; its ML-KEM ciphertext is a **different** value from the golden vector's own captured ciphertext (§5.2 note — ML-KEM-768 encapsulation is randomized). |
| **[KAT:transcript]** | Pinned in `test-vectors/v1/transcript-kat.json`. Proves the §6.1/binding §3 per-TLV, frame-type-only absorption construction against synthetic fixture TLVs. Not the source of any transcript value quoted in this document — §6.2 now cites the golden vector directly, independently reconstructed from its own frame bytes. |
| **[KAT:key-schedule]** | Pinned in `test-vectors/v1/key-schedule-kat.json`. Proves an independent HKDF-Expand-Label oracle against RFC 8448 / RFC 5869 anchors on synthetic fixture inputs; §12 reuses the same anchor chain, but the worked numbers in §8.3 now come from the golden vector directly. |
| **[KAT:finished]** | Pinned in `test-vectors/v1/finished-kat.json`. Proves the Finished HMAC construction against a fixture key. Not the source of any Finished value quoted in this document — §9.3/§10 now cite the golden vector directly. |
| **[KAT:certverify]** | Pinned in `test-vectors/v1/certverify-kat.json`. Proves the CertVerify signing-input construction against RFC 8032 test keys. Not the source of any CertVerify value quoted in this document — §9.2/§10 now cite the golden vector directly (a different, vector-specific identity seed, not the RFC 8032 test keys). |
| **[CORPUS]** | Pinned in `test-vectors/v1/conformance-corpus.json`. |
| **[REGISTRY]** | From the wire-format and registry references (`../02_frame_format.md`, `../05_profiles.md`, `../06_cryptographic_suites.md`, `../07_tlv_registry.md`, `../04_frame_types.md`). |
| **[DERIVED]** | Computed for this document from pinned inputs by the §12 recipe. Informative; NOT itself a pinned vector — used only where no vector value exists (the illustrative APP_REQUEST/APP_RESPONSE frame lengths, §11; the structural HkdfLabel/traffic-context sketch, §8.2). |
| **[INTEROP]** | Reproduced, unedited, from a recorded live inter-implementation capture. The full record now lives in §15 (RFC 7942 Implementation Status) rather than being interleaved with the golden-vector narrative. |

**Most of this document is now anchored to one single golden, self-consistent,
byte-pinned association.** In producing this revision, every quoted value in
§3–§11 was independently re-derived — not merely copied — from
`test-vectors/v1/handshake-flow-kat.json`'s own `inputs` and cross-checked against
its `expected` fields: the four frame headers' CRC32C (recomputed and confirmed
against the well-known Castagnoli check value); the CLIENT_HELLO/SERVER_HELLO TLV
byte-accounting (re-parsed field-by-field); all five transcript points (rebuilt
from the raw frame/TLV bytes via the §6.1 construction, not copied from
`expected.transcript`); the full §8 key ladder, including the application-phase
secrets (rebuilt via HKDF-Extract/HKDF-Expand-Label, itself anchored against RFC
5869 §A.1 TC1 before being trusted); both Finished MACs (rebuilt via HMAC-SHA256);
and both CertVerify signatures (independently VERIFIED against the Ed25519 public
keys extracted from the AUTH plaintexts, with those public keys themselves
independently re-derived from the vector's own identity seeds and confirmed to
agree). A handful of pedagogical asides remain sourced from other pinned material
and are marked accordingly: §4.2/§5.2's demonstration of the ML-KEM-first wire
order against NIST ACVP values (**[KAT:kem-wire]**), and the 2026-06-23 live
interop capture, which predates this golden vector and is preserved unedited as a
historical record in §15.

### 1.2 Not in scope

- **High and Sovereign profiles.** This walk-through is Standard-only
  (`H` = SHA-256, `HashLen` = 32). The profile parameter table of the handshake
  binding governs the other rows; their operational and cryptographic detail is
  out of scope for this public companion set.
- **New wire behavior.** Nothing here adds to, or deviates from, the handshake
  binding. Where the binding and this document could be read differently, the
  binding wins.
- **A new vector source.** This document transcribes pinned values; it does not
  mint new ones. §8.3's and §11's key-ladder tables ARE the golden vector's own
  pinned, machine-graded conformance values (§1.1) — but conformance testing MUST
  still use the pinned corpus and its harness directly (§14), never a hand-copied
  prose table. The remaining **[DERIVED]** material (§8.2's structural HkdfLabel
  sketch, §11's illustrative application-frame lengths) exists so a developer can
  follow the arithmetic end-to-end and MUST NOT be used as a conformance vector.
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

Flags: `0x01` (reserved), `0x02` ENC (payload AEAD-sealed), `0x04` COMP, `0x08` (reserved).
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

Below is the byte authority for this document: the golden-interop vector's four
handshake frame headers, independently re-parsed and CRC-recomputed from
`test-vectors/v1/handshake-flow-kat.json` `expected.frames.*` in producing this
document (§12 recipe; CRC32C anchored against the well-known Castagnoli check
value `crc32c(b"123456789") = e3069283`, RFC 3720): **[KAT:handshake-flow]**

```
CLIENT_HELLO  4e50414d 20 0100 0000 0000000000000000 000004db 9cdad796 00×11
SERVER_HELLO  4e50414d 20 0101 0000 0000000000000000 0000047b 591f9f31 00×11
SERVER_AUTH   4e50414d 22 0102 0000 0000000000000000 0000009e d60efd56 00×11
CLIENT_AUTH   4e50414d 22 0103 0000 0000000000000000 0000009e b1800057 00×11
```

(`20` = ver 2, flags 0 (cleartext); `22` = ver 2, flags ENC. `00×11` = the 11
reserved zero octets. Every payloadLen/CRC number in §4, §5, §9, and §10 below is
reconciled against this block, and `scripts/check-companion56-drift.py` re-derives
it mechanically from the pinned vector on every run — see the header of that
script for exactly what it checks.)

```
client ── CLIENT_HELLO (0x0100), cleartext, 1279 total ────────▶ server
client ◀── SERVER_HELLO (0x0101), cleartext, 1183 total ─────── server
       ◀── SERVER_AUTH  (0x0102), ENCRYPTED, 194 total ──────── server
client ── CLIENT_AUTH  (0x0103), ENCRYPTED, 194 total ─────────▶ server
```

A live inter-implementation capture of this same four-flight shape (plus one
application exchange) was recorded on 2026-06-23, roughly seven weeks before this
golden vector existed; its own numbers are preserved unedited in §15 (RFC 7942
Implementation Status). **Do not mix the two:** this section is the pinned
conformance authority for the numbers used throughout §4–§11; §15 is a separate,
historical implementation report.

Two observations from the golden vector worth fixing in mind now:

- **Cleartext flights carry no AEAD tag.** `total = 36 + payloadLen` throughout,
  and for the HELLO flights the payload length is fully accounted for by TLV
  bytes alone (§4.3, §5.3). The binding marks these flights "cleartext /
  Encryption: none".
- **For ENC frames the recorded payload length is the sealed length** —
  plaintext TLV bytes plus the 16-octet AES-256-GCM tag (§9.4: 142 + 16 = 158).

## 4. Flight 1 — CLIENT_HELLO (`0x0100`, cleartext)

`{client}` constructs and sends this as CLIENT_HELLO — §3's byte authority; the
TLVs are below.

### 4.1 TLVs, in order

| # | TLV | Tag | Value (Standard-profile association) |
|---|-----|-----|--------------------------------------|
| 1 | ProfileOffer | `0x01` | Profiles the client offers; ProfileOffer is variable, one octet per profile. The golden vector's CLIENT_HELLO offers a single profile (`0x01` = Standard) — see §4.3's 3-profile pedagogy sidebar for the all-three-profiles alternative preserved in §15. **[REGISTRY]** / **[KAT:handshake-flow]** |
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

This exact `ek` and X25519-public-key concatenation appears verbatim as the
KEMShare TLV inside the golden vector's own CLIENT_HELLO
(`expected.frames.client_hello`, TLV `0x0007`, independently re-parsed in
producing this document, §12): ML-KEM-768 keygen is deterministic from the seed,
so the same `d ‖ z` produces the same `ek` regardless of which pinned file cites
it. **[KAT:handshake-flow]** cross-check.

### 4.3 Byte accounting for the observed payload

The golden vector's CLIENT_HELLO has `payloadLen = 1243` (`0x000004db`), header
CRC32C `9cdad796`: **[KAT:handshake-flow]** (`expected.frames.client_hello`,
independently re-parsed and CRC-recomputed in producing this document, §12)

```
ProfileOffer  4+1  =    5      (one profile: 0x01 = Standard)
KEMOffer      4+2  =    6      (one KEM:  0x11ec)
SigOffer      4+2  =    6      (one sig:  0x0807)
AEADOffer     4+2  =    6      (one AEAD: 0x0001)
KEMShare      4+1216 = 1220
                       ----
                       1243    = observed payloadLen; total 1279 = 36 + 1243, no tag
```

The five TLVs above were re-parsed directly from the pinned frame bytes (type,
length, and value all confirmed field-by-field) and their `4+len` sum equals the
declared `payloadLen` exactly — this is not a reconstruction that merely closes,
it is the same bytes read twice.

> **Sidebar — a 3-profile offer.** A client offering all three profiles
> (`ProfileOffer = 0x01 0x02 0x03`, still one octet per profile) totals `4+3=7`
> instead of `4+1=5` for the ProfileOffer TLV — 1245 octets overall, header CRC32C
> `ba7b307e`. This is not hypothetical: the 2026-06-23 interop capture (§15)
> recorded exactly that 3-profile CLIENT_HELLO, unedited, as `payloadLen=1245`,
> CRC `ba7b307e`. Both associations are spec-legal; the 2-octet difference is
> exactly the two extra ProfileOffer octets, and every other TLV is identical in
> shape between the two. **[INTEROP]**, quoted verbatim from §15 — not
> reconciled with the golden vector's numbers above.

## 5. Flight 2 — SERVER_HELLO (`0x0101`, cleartext)

`{server}` responds with SERVER_HELLO — §3's byte authority; the TLVs are below.

### 5.1 TLVs, in order

| # | TLV | Tag | Value |
|---|-----|-----|-------|
| 1 | ProfileSelect | `0x02` | 1 octet; `0x01` = Standard. **[REGISTRY]** |
| 2 | KEMSelect | `0x04` | `0x11ec`. |
| 3 | SigSelect | `0x06` | `0x0807`. |
| 4 | AEADSelect | `0x0D` | `0x0001` (AES-256-GCM) — the golden vector's negotiated AEAD. **[KAT:handshake-flow]** |
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

**A note on which ciphertext is which.** The NIST ACVP ciphertext quoted above
(`c = 04F4A18C…`) comes from the KEM-wire KAT's externally-anchored encapDecap
record — it demonstrates the wire *order* against a standard, not this
association's own bytes. ML-KEM-768 encapsulation is randomized (FIPS 203 §7.2),
so even with the identical `ek`, a fresh encapsulation produces a *different*
ciphertext and shared secret each time; the golden vector's own KEMCiphertext
(`expected.frames.server_hello`, TLV `0x0008`) is one such capture, pinned as a
**self-validating** input for exactly this reason (its own provenance note:
"`crypto/mlkem` has no seed-injectable encapsulation"). Concretely, the golden
vector's KEMCiphertext begins `99A82001…` and its ML-KEM shared secret is
`4DA9137519E0AED0…` (`inputs.mlkem_shared_secret`) — both different from the
NIST-anchored `c`/`K` above, and it is *this* association's shared secret, not
the NIST one, that feeds §8's key schedule below. Both were independently
re-parsed/re-derived in producing this document. **[KAT:handshake-flow]**

At this point both peers hold the 64-octet hybrid secret, ML-KEM-first
(ADR-0005; binding §4):

```
KEM output (IKM) = ML-KEM SS (32) ‖ X25519 SS (32)
                 = 4da9137519e0aed0…7618b5439 ‖ 4a5d9d5b…161742      [KAT:handshake-flow]
```

ML-KEM-768 uses implicit rejection: a corrupted ciphertext decapsulates to a
pseudorandom secret that later fails the Finished MAC rather than erroring
here. An all-zero X25519 output is rejected. (Binding §4.)

### 5.3 Byte accounting

Golden-vector `payloadLen=1147`: **[KAT:handshake-flow]**

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
documented divergence from RFC 9846 §4.1 — each frame contributes:

- **AddFrameType(ft):** the **2-octet big-endian frame type only**. The other 34
  header octets (magic, flags, channel, seq, length, CRC, reserved) and the AEAD
  tag are NOT absorbed.
- **AddTLV(t):** the TLV in canonical `Type(2) ‖ Length(2) ‖ Value` form, one
  call per TLV, in frame order.

Granularity is per-TLV, which is what lets the bundled AUTH frames be hashed at
sub-frame cut points.

### 6.2 The five points, with pinned values

The golden vector pins all five points for one real, complete association — not
synthetic fixtures. All five values below were independently reconstructed for
this document directly from the vector's own frame/TLV bytes (the §6.1
AddFrameType/AddTLV construction over a running SHA-256 buffer), NOT copied from
`expected.transcript`, and matched it exactly (§12 recipe): **[KAT:handshake-flow]**

| Point | Absorbed through | Pinned value (SHA-256) |
|-------|------------------|------------------------|
| `TH_kem` | `0x0100 ‖ CH-TLVs ‖ 0x0101 ‖ SH-TLVs` | `c77ccd1c799705f923eb29f5d0c06b4fb868f45dd1d21e082c56b37f06c49ca0` |
| `TH_sId` | `… ‖ 0x0102 ‖ ServerIdentityKey` | `a4c2e09c330fd059767bb2f4676068a8fe840b643a1ce6273ab9bc1383b38bef` |
| `TH_sCV` | `… ‖ ServerCertVerify` (excludes ServerFinished) | `49cde54aa21f2eafbd8425d5b6be5974b5fa2c06870be8fece0a18e58d6f0191` |
| `TH_cId` | `… ‖ ServerFinished ‖ 0x0103 ‖ ClientIdentityKey` | `eb1e70887c70e27f15b0c52f892db156729e9a9a91d811c88199aed14574521f` |
| `TH_cCV` | `… ‖ ClientCertVerify` (excludes ClientFinished) | `47e8f09139d8400cc46ff8be94156bd549e0c086f2670c304d08d80ee52ce346` |

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
(binding §5 — deliberately simpler than RFC 9846 §7.1's three-stage chain; there
is no PSK/0-RTT in this binding). HKDF-Expand-Label is RFC 9846 §7.1 with the
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
textual gap in the current handshake binding (`../10_handshake_binding.md`).

### 8.2 Worked bytes: one HkdfLabel

For `c_hs` with this association's real `TH_kem` (§6.2), the exact `HkdfLabel`
(the `info` argument to HKDF-Expand) is: **[KAT:handshake-flow]** (structure per
RFC 9846 §7.1; independently reconstructed and confirmed to reproduce
`c_hs_secret` below, §12)

```
0020                             uint16 output length = 32
0b                               label length = 11
6e2d70616d702063206873           "n-pamp c hs" (the 11 UTF-8 octets of prefix + label)
20                               context length = 32
c77ccd1c799705f923eb29f5d0c06b4fb868f45dd1d21e082c56b37f06c49ca0   TH_kem context
```

i.e. `info = 00200b6e2d70616d70206320687320` ‖ `c77ccd1c…6c49ca0` (47 octets). The
`"traffic"` context for the server→client handshake key on the Control channel
is `01 0000000000000000 0001 0000` — dir `01`, epoch 0, suite `0x0001`
(AES-256-GCM), channel `0x0000`. **[DERIVED]** (structural illustration only; a
concrete worked `traffic_secret` for this exact context is §8.3's `Hs traffic
secret s→c` row)

### 8.3 The corpus discipline — and this document's worked numbers

The key ladder below is no longer a separately-derived illustration: every
value is a **pinned, machine-graded conformance value** from the golden vector
(`test-vectors/v1/handshake-flow-kat.json` `expected.secrets`), graded across
reference implementations by `impl/_conformance-harness/kat-handshake-all-langs.sh`
and the per-language handshake-flow-KAT tests (e.g. `impl/go/handshakeflow_kat_test.go`).
**[KAT:handshake-flow]**

In producing this document every row below was independently re-derived — not
copied — from the vector's own real inputs and the §6.2 transcript points, using
a from-scratch HKDF-Extract / HKDF-Expand-Label built on stdlib HMAC-SHA256,
itself anchored against RFC 5869 §A.1 TC1 before being trusted
(`HKDF-Extract` → `prk = 077709…`, `HKDF-Expand` → `okm = 3cb25f…`, both
reproduced exactly). Every row below matched the pinned value byte-for-byte:

```
ikm_mlkem_ss  = 4da9137519e0aed0e8fc794842dc62fb299c6881ebc228fc35ae5c97618b5439   (real, §5.2)
ikm_x25519_ss = 4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742   (real, §5.2, RFC 7748 §6.1)
th_kem        = c77ccd1c799705f923eb29f5d0c06b4fb868f45dd1d21e082c56b37f06c49ca0   (real, §6.2)
th_ccv        = 47e8f09139d8400cc46ff8be94156bd549e0c086f2670c304d08d80ee52ce346   (real, §6.2)
```

| Stage | Value |
|-------|-------|
| `handshake_secret` | `9d9a234821550d6e0a866bc23f17a589cb748a53c4523f9305215b8483f97bbc` |
| `c_hs_secret` | `aa7b5985f0456a20cdc679d930e907369d121d56185b51952e7ebd478dafb5f8` |
| `s_hs_secret` | `4470f38cadac98f37238190f2de3de678414f30cd43f5afbc479d3f0aafc04d5` |
| `master` | `4e38f85ad9657695a0a6f5ac7be6efdf54b81a5024827d6ca7ed09820a687303` |
| `finished_key` (client, from `c_hs`) | `0cd8d16d9798de00568d11ca7066fda6dcc93a81e9dfb1fd7aa97af1e7c434a6` |
| `finished_key` (server, from `s_hs`) | `cebfd4567c0aea393368d8d2e6912261465f77f9fbaa2eacb66f186b0ed6fbcc` |
| Hs traffic secret c→s (dir 0, epoch 0, suite `0x0001`, chan `0x0000`) | `2f9f0b9d547276cf90bc32abec09d270848cf62f49da210fcf8a99a1268a6d25` |
| Hs key / iv c→s | `867994e68d29034ae2f9472e656724998d5af2a26a1d7f44ae81e6bf96a82f0a` / `a05c6d3ed50ce0eb30c67f0b` |
| Hs traffic secret s→c (dir 1, epoch 0, suite `0x0001`, chan `0x0000`) | `d756a8343863140ecd805d063d3c6f53596ccdb7a7ea6de2d6efdc1e9944069a` |
| Hs key / iv s→c | `0b7b8011e7e73e7ec94af0a07d5194f001ce0c30c86c139a052fe5ed63ca2caf` / `ee2c97bb3df88555fa2fc2a3` |

These bytes ARE golden conformance values — reproducible from the pinned inputs
by anyone following §12, AND directly machine-graded by
`impl/_conformance-harness/kat-handshake-all-langs.sh`. A conforming
implementation MAY use them as regression fixtures; the machine-graded authority
remains the pinned JSON file, never this prose transcription (§14).

## 9. Flight 3 — SERVER_AUTH (`0x0102`, encrypted)

### 9.1 Sealing

`{server}` constructs and seals SERVER_AUTH under the **server→client
handshake** key/iv (§8.3: key `0b7b8011…`, iv `ee2c97bb…`): `Flags = ENC (0x02)`,
`Channel = 0x0000`, `Seq = 0`; AAD = the 21-octet frame header prefix (octets
0–20, the same octets the CRC covers); nonce = `iv XOR left-zero-padded seq` —
with seq 0, the nonce **is** the IV. AES-256-GCM at the Standard association. On
open, exactly three TLVs in this order are required: IdentityKey, CertVerify,
Finished. (Binding §6.4; `../06_cryptographic_suites.md`.)

### 9.2 CertVerify (TLV `0x0A`): sign the transcript

Structure per RFC 9846 §4.5.2 with N-PAMP context strings (binding §6.1):

```
signing_input = 0x20 × 64 ‖ context ‖ 0x00 ‖ transcript_hash
context (server) = "N-PAMP/3, server CertificateVerify"
TLV value = SignatureScheme uint16 (Ed25519 = 0x0807) ‖ signature
```

The server signs `TH_sId` — the transcript through its own IdentityKey, before
its own CertVerify. Worked numbers, all pinned in the golden vector and
independently verified in producing this document: **[KAT:handshake-flow]**

- Server identity: seed `5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e`
  (`inputs.server_identity_ed25519_seed`, 32 octets) — this is **not** an RFC 8032
  published test key, it is this association's own synthetic identity seed.
  Public key `8146640f02493af4fbc54fe33388e75dc2c937ae0b7727cc2b2afb1b75199a3e`:
  (a) extracted directly from the SERVER_AUTH plaintext's IdentityKey TLV
  (`expected.auth_plaintext.server_auth`) and (b) independently re-derived from
  the seed via Ed25519 key generation; both agree. At the Standard profile the
  IdentityKey TLV (`0x09`) carries this 32-octet Ed25519 public key.
- `signing_input` (server) = `2020…20` (64 octets) ‖
  `4e2d50414d502f332c2073657276657220436572746966696361746556657269667900`
  ("N-PAMP/3, server CertificateVerify" + the 0x00 separator, 35 octets) ‖
  `a4c2e09c330fd059767bb2f4676068a8fe840b643a1ce6273ab9bc1383b38bef` (`TH_sId`) —
  64 + 34 + 1 + 32 = 131 octets, reconstructed byte-for-byte in producing this
  document.
- Ed25519 signature:
  `9c276d2e20a2fea83cfb0c3a08c42311e67b218e0c6b6fae669f8299990917ba3f49d7bc470c39615a0c3affd67a0be36399d420ce41d56a0832912db5bfbe06`.
  Independently **verified** against the extracted public key and the
  reconstructed `signing_input` above — this document did not merely copy the
  signature bytes, it confirmed them cryptographically.
- CertVerify TLV value = `0807` ‖ signature = 66 octets
  (`expected.cert_verify.server`).

A verifier MUST reject a scheme it did not negotiate, and the differing context
string makes a server CertVerify unusable as a client one (role/domain
separation) — the pinned KAT's consuming tests include exactly those rejection
checks.

### 9.3 Finished (TLV `0x0B`): MAC the transcript

Per RFC 9846 §4.5.3, keyed by the sender's handshake traffic secret
(binding §6.2):

```
finished_key = HKDF-Expand-Label(s_hs_secret, "finished", "", 32)
verify_data  = HMAC-SHA256(finished_key, TH_sCV)
```

Worked numbers, all pinned in the golden vector (§8.3's `finished_key` (server)
row) and independently re-derived via HMAC-SHA256 in producing this document —
no longer a synthetic fixture key: **[KAT:handshake-flow]**

```
finished_key (server) = cebfd4567c0aea393368d8d2e6912261465f77f9fbaa2eacb66f186b0ed6fbcc
TH_sCV                 = 49cde54aa21f2eafbd8425d5b6be5974b5fa2c06870be8fece0a18e58d6f0191
verify_data (server)   = 82b1c8f42b08d9b0a162e91729a625a4a93b7d0e74a168597d47f4f5d1e11213
```

`verify_data` is `HashLen` = 32 octets at Standard, which is why the Finished
TLV is variable-length (binding §1.1). Verification MUST be constant-time and
abort on mismatch.

### 9.4 Byte accounting, and the complete sealed record

Golden-vector `payloadLen=158` for SERVER_AUTH: **[KAT:handshake-flow]**

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

`{server}` the plaintext before sealing (142 octets,
`expected.auth_plaintext.server_auth`; TLVs re-parsed and cross-checked in §9.2
above against the separately-pinned `cert_verify.server`/`finished.server`
fields — they agree exactly):

```
   00 09 00 20 81 46 64 0f 02 49 3a f4 fb c5 4f e3
   33 88 e7 5d c2 c9 37 ae 0b 77 27 cc 2b 2a fb 1b
   75 19 9a 3e 00 0a 00 42 08 07 9c 27 6d 2e 20 a2
   fe a8 3c fb 0c 3a 08 c4 23 11 e6 7b 21 8e 0c 6b
   6f ae 66 9f 82 99 99 09 17 ba 3f 49 d7 bc 47 0c
   39 61 5a 0c 3a ff d6 7a 0b e3 63 99 d4 20 ce 41
   d5 6a 08 32 91 2d b5 bf be 06 00 0b 00 20 82 b1
   c8 f4 2b 08 d9 b0 a1 62 e9 17 29 a6 25 a4 a9 3b
   7d 0e 74 a1 68 59 7d 47 f4 f5 d1 e1 12 13
```

`{server}` the complete sealed SERVER_AUTH record (194 octets: 36-octet header +
142-octet plaintext + 16-octet AES-256-GCM tag, `expected.frames.server_auth`):

```
   4e 50 41 4d 22 01 02 00 00 00 00 00 00 00 00 00
   00 00 00 00 9e d6 0e fd 56 00 00 00 00 00 00 00
   00 00 00 00 81 e6 c3 09 c8 14 40 2e 94 2a f8 81
   25 1b cf bd 56 dc 46 7f be 5e 4d ec ba e7 77 f7
   9a b4 dc c4 84 b7 05 c2 74 84 c5 aa 69 55 ff f9
   5a 6f 43 91 9d 4f 2d 12 37 fb 83 af 87 75 d9 44
   eb de ed 89 d6 80 a6 6e c4 95 32 f4 b8 1d 42 08
   f2 74 93 5e 8a 8a 15 4c b8 59 a4 72 dd 29 f7 da
   95 c6 67 24 96 5e 79 f6 1c 1a 6c e1 f5 83 dc 9f
   d3 f4 7f 47 d9 7f 15 96 9e 53 84 8a a7 d5 b0 e5
   be d4 04 1f 7c ca 03 bb 0a 22 1f 4a 8c b4 ac dc
   d4 7e 00 a3 94 fe 4d b4 22 22 65 6c c6 6f b5 6c
   7a d2
```

## 10. Flight 4 — CLIENT_AUTH (`0x0103`, encrypted)

`{client}` constructs and seals CLIENT_AUTH under the **client→server
handshake** key/iv (§8.3: key `867994e6…`, iv `a05c6d3e…`), the mirror image of
§9: same three-TLV layout, same observed 158-octet sealed payload, 194-octet
total. **[KAT:handshake-flow]** The client-side worked numbers, all pinned and
independently verified the same way as §9.2/§9.3:

- Client identity: seed
  `c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1`
  (`inputs.client_identity_ed25519_seed`) — again this association's own
  synthetic identity seed, not an RFC 8032 test key. Public key
  `acdcc8494d458f44a7aaac1d6a84ec624daee88436db2ae26e67ba645a106228` — extracted
  from the CLIENT_AUTH plaintext's IdentityKey TLV and independently confirmed
  by re-deriving the public key from the seed.
- The client signs `TH_cId`
  (`eb1e70887c70e27f15b0c52f892db156729e9a9a91d811c88199aed14574521f`) under
  context `"N-PAMP/3, client CertificateVerify"`; `signing_input` (131 octets)
  reconstructed byte-for-byte the same way as §9.2; signature
  `12ccb4f316318b7e6daee91b15e38c6217b5c2cde0c7a5eba8048c6974e40fdd2e768c3881416eecc3d3c3f42975bc0e6ca318a384aaefdf6ab5f2869c16bc04`,
  independently **verified** against the extracted public key; CertVerify TLV
  value = `0807` ‖ signature.
- The client's Finished MACs `TH_cCV`
  (`47e8f09139d8400cc46ff8be94156bd549e0c086f2670c304d08d80ee52ce346`) with
  `finished_key (client) = 0cd8d16d9798de00568d11ca7066fda6dcc93a81e9dfb1fd7aa97af1e7c434a6`
  (§8.3), giving
  `verify_data (client) = 647142ade665ade076975c7fc111853bfd23143c368c5f69cc0d0c9ab1153b78`
  — re-derived via HMAC-SHA256 and matched.

`{client}` the plaintext before sealing (142 octets,
`expected.auth_plaintext.client_auth`):

```
   00 09 00 20 ac dc c8 49 4d 45 8f 44 a7 aa ac 1d
   6a 84 ec 62 4d ae e8 84 36 db 2a e2 6e 67 ba 64
   5a 10 62 28 00 0a 00 42 08 07 12 cc b4 f3 16 31
   8b 7e 6d ae e9 1b 15 e3 8c 62 17 b5 c2 cd e0 c7
   a5 eb a8 04 8c 69 74 e4 0f dd 2e 76 8c 38 81 41
   6e ec c3 d3 c3 f4 29 75 bc 0e 6c a3 18 a3 84 aa
   ef df 6a b5 f2 86 9c 16 bc 04 00 0b 00 20 64 71
   42 ad e6 65 ad e0 76 97 5c 7f c1 11 85 3b fd 23
   14 3c 36 8c 5f 69 cc 0d 0c 9a b1 15 3b 78
```

`{client}` the complete sealed CLIENT_AUTH record (194 octets,
`expected.frames.client_auth`):

```
   4e 50 41 4d 22 01 03 00 00 00 00 00 00 00 00 00
   00 00 00 00 9e b1 80 00 57 00 00 00 00 00 00 00
   00 00 00 00 ea 21 5d 11 30 56 b3 69 c5 f4 84 7d
   72 ae 42 c4 e4 8b 0d 70 56 82 fe 89 12 74 d9 61
   9e ca 43 05 d9 4d f6 12 9b ec 16 39 9f b6 dc 49
   90 26 00 a4 c0 ea e8 f8 d1 3b fd c9 ab f8 20 5c
   b6 f6 83 fa b8 b7 09 84 94 c2 39 57 d8 4a 51 83
   f9 3d c9 22 c9 a3 01 03 0d 3f 0b e5 8a 34 bf c1
   be 20 d3 82 2b a0 cd b4 52 48 1b 96 ad 10 2b a6
   93 f7 ba b9 37 ed 00 b2 66 00 58 d3 e9 f2 8c 89
   17 d3 39 c3 0b e7 2a 11 04 ac ee 94 14 dc b5 72
   75 de ab f8 9b e8 bf 5b f3 84 81 e4 2e bf 50 0c
   9b 0a
```

**The client-auth boundary is where `master` exists.** `master` is derived from
`TH_cCV` (§8.1), so the server reaches the keyed/Established state only after
CLIENT_AUTH verifies (binding §1, §5). At this point both peers have mutually
authenticated: each signed its own transcript point, each MAC'd the transcript
through its own CertVerify, and every negotiation byte from the cleartext
flights is bound into both.

## 11. One application frame exchange

With `master` in hand (§8.3: `4e38f85ad9657695a0a6f5ac7be6efdf54b81a5024827d6ca7ed09820a687303`),
application-phase traffic keys are derived per `(dir, epoch, suite, channel)`,
the same `DeriveTrafficSecret` construction as §8 (binding §5). The golden
vector pins one instance of this derivation — the **Control channel's own**
post-handshake application-phase secret (epoch 0, suite `0x0001`, **channel
`0x0000`**, i.e. the *same* channel the handshake ran on, not a Memory or other
application channel): **[KAT:handshake-flow]**

| Quantity (epoch 0, suite `0x0001`, chan `0x0000`, Control) | Value |
|---|---|
| App traffic secret c→s (dir 0) | `40a59dbad8f24515625c0ccf144305c1af273f493e71b7e7fa43c89cabec3d49` |
| App key / iv c→s | `06f15371f02823934d99f9437ca7d6a260d0548961c7af6345606522617a7271` / `4fc7f89c4fc2b12ef3c6f0a3` |
| App traffic secret s→c (dir 1) | `4d0eecd8cf0a715f67e33e8cb9a15c9199b6a86f08e381116566878eb9de06f2` |
| App key / iv s→c | `f5c55307013339421803a5e013a8b4d1e095afff89a33c5fda7a0c400fceca81` / `d70af612c4b389c71b54ee28` |

Independently re-derived via HKDF-Expand-Label from `master` in producing this
document and matched byte-for-byte (§12). A different application channel (e.g.
the Memory channel, `0x0001`) would use the identical construction with
`channel = 0x0001` substituted — the golden vector does not pin that instance,
because it does not exercise a non-Control channel; the mechanics are identical,
only the `channel` octets in the `traffic` context change (binding §5's
per-channel isolation, made concrete). **Correction from an earlier revision of
this document:** an informative-only illustration previously showed this table
keyed to Memory-channel (`0x0001`) numbers derived from a different, non-pinned
`master`; those numbers are superseded by the pinned values above, which are
keyed to the Control channel.

The live capture's application exchange is unrelated to the golden vector — no
`handshake-flow-kat.json`-class vector exists for application frames (§1.2) — and
ran on the Memory channel (`0x0001`), frame types `0x0120` APP_REQUEST /
`0x0121` APP_RESPONSE (channel-specific space, ≥ `0x0100`), seq 0 per channel
and direction, both ENC; preserved unedited in §15: **[INTEROP]**

```
SEND  flags=0x2/ENC  type=0x0120(APP_REQUEST)  chan=0x0001 seq=0 payloadLen=570 total=606
RECV  flags=0x2/ENC  type=0x0121(APP_RESPONSE) chan=0x0001 seq=0 payloadLen=85  total=121
```

Mechanics of the request frame, exactly as in §9.1 but with application keys:
AAD = its own 21-octet header prefix; nonce = application IV XOR seq (= the IV,
seq being 0); AES-256-GCM tag inside the sealed payload. In the recorded
exchange the payload was an application memory write that persisted to storage and was
independently read back, together with the negative controls (plaintext HTTP rejected,
wrong ALPN rejected, wrong pinned server key rejected). The per-frame evidence is not
duplicated here; see §15 for the capture's own coverage statement.

For completeness, the six 36-octet headers of this walk-through's association:
the four handshake headers are this document's byte authority (§3,
golden-vector-sourced, **[KAT:handshake-flow]**); the two application headers
are unedited fields from the 2026-06-23 capture (§15, **[INTEROP]**), since no
golden vector pins an application frame:

```
CLIENT_HELLO  4e50414d 20 0100 0000 0000000000000000 000004db 9cdad796 00×11
SERVER_HELLO  4e50414d 20 0101 0000 0000000000000000 0000047b 591f9f31 00×11
SERVER_AUTH   4e50414d 22 0102 0000 0000000000000000 0000009e d60efd56 00×11
CLIENT_AUTH   4e50414d 22 0103 0000 0000000000000000 0000009e b1800057 00×11
APP_REQUEST   4e50414d 22 0120 0001 0000000000000000 0000023a a258e10a 00×11
APP_RESPONSE  4e50414d 22 0121 0001 0000000000000000 00000055 dd4683a3 00×11
```

(`20` = ver 2, flags 0; `22` = ver 2, flags ENC. The first four rows repeat §3's
byte authority verbatim; the last two are the capture's own recorded fields,
CRC32C recomputed by the same §12-anchored oracle.)

## 12. Reproducing and independently verifying every value in this document

Every value in this document was produced, and then independently verified, by
a process that refuses to trust anything until its own oracles pass
externally-anchored checks — the same anchor→oracle→impl discipline the KATs
impose on implementations, now run end-to-end against the golden vector rather
than against synthetic fixtures:

1. **Anchor the hash:** SHA-256("abc") == `ba7816bf…0015ad` (FIPS 180-4 anchor,
   inherited from the transcript KAT).
2. **Anchor CRC32C:** the well-known Castagnoli check value
   `crc32c(b"123456789") == e3069283` (ISO 3309 / RFC 3720 test vector),
   confirmed before recomputing any frame's CRC.
3. **Anchor HKDF:** RFC 5869 §A.1 TC1 Extract/Expand
   (`prk = 077709…`, `okm = 3cb25f…`), confirmed before deriving any secret.
4. **Anchor Expand-Label:** RFC 8448 §3 key/iv/finished with the `"tls13 "`
   prefix (anchor inherited from the key-schedule KAT).
5. **Anchor HMAC:** RFC 4231 TC1/TC2 (anchor inherited from the Finished KAT).
6. Only then, against `test-vectors/v1/handshake-flow-kat.json`:
   - re-parse all four frame headers and recompute CRC32C over octets 0–20,
     confirming the embedded CRC (§3);
   - re-parse the CLIENT_HELLO/SERVER_HELLO TLVs and confirm the byte sum
     equals the declared `payloadLen` (§4.3, §5.3);
   - reconstruct all five `TH_*` transcript points directly from the frame/TLV
     bytes via the §6.1 AddFrameType/AddTLV rule over a running SHA-256 buffer,
     and confirm each against `expected.transcript.*` (§6.2) — not merely
     copied;
   - apply HKDF-Extract to the real ML-KEM/X25519 shared secrets and
     HKDF-Expand-Label with prefix `"n-pamp "` to rebuild the entire §8 key
     ladder — `handshake_secret`, `c_hs`/`s_hs`/`master`, both `finished_key`s,
     both handshake-phase traffic secrets/keys/IVs, and both application-phase
     traffic secrets/keys/IVs — and confirm every one against
     `expected.secrets.*` (§8.3, §11);
   - recompute both Finished `verify_data` values via HMAC-SHA256 and confirm
     against `expected.finished.*` (§9.3, §10);
   - extract both IdentityKey public keys from `expected.auth_plaintext.*`,
     independently re-derive each public key from
     `inputs.*_identity_ed25519_seed`, confirm they agree, rebuild both
     `signing_input` values, and independently VERIFY both Ed25519 signatures
     against the extracted public keys (§9.2, §10).

Sketch (any language; stdlib HMAC/SHA-256 suffices for every step except the
Ed25519 keygen/verify):

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
exercised by its own `handshakeflow_kat_test.go` (binding §8). This document's
own verification pass was checked separately, in Python, against the same
pinned JSON: `scripts/check-companion56-drift.py` is a standing repo gate that
mechanically re-derives the four frame headers (payloadLen + CRC32C) on every
run; the full transcript/key-schedule/signature re-derivation above was a
one-time verification pass performed in producing this revision, not (yet) a
standing repo gate — see that script's own docstring for its exact, narrower
scope.

## 13. Limitations and honest scope

- **Single golden association, not synthetic composites.** Unlike an earlier
  revision of this document, §3 through §11's key-schedule and authentication
  material now comes from ONE pinned, self-consistent, real association
  (`test-vectors/v1/handshake-flow-kat.json`), not stitched-together synthetic
  fixtures from separate per-construction KATs. The KEM values, transcript
  points, key ladder, Finished MACs, and CertVerify signatures interlock
  exactly because they are one real handshake, not because they were checked
  for consistency after the fact.
- **What remains pedagogical, not this association's own bytes.** §4.2/§5.2's
  demonstration of the ML-KEM-first wire order quotes the KEM-wire KAT's NIST
  ACVP ciphertext (`c = 04F4A18C…`), which is NOT the golden vector's own
  captured ciphertext (`99A82001…`) — ML-KEM-768 encapsulation is randomized, so
  the two differ even from the identical `ek` (§5.2 note). The 2026-06-23 live
  interop capture (relocated to §15) predates this golden vector by roughly
  seven weeks and is a separate, unedited historical record, not a source for
  any number in §3–§11.
- **The application-phase key table (§11)** pins the Control channel's own
  post-handshake secret (`channel = 0x0000`), because the golden vector does
  not exercise a non-Control channel. It is NOT a Memory-channel example,
  correcting an earlier revision of this document that mislabeled it as one.
- **The application FRAME bytes (§11's APP_REQUEST/APP_RESPONSE)** remain
  illustrative and interop-capture-sourced (`[INTEROP]`/`[DERIVED]`) — no
  golden vector pins an application frame; extending the corpus to cover one is
  tracked as a separate, future growth item, not part of this revision.
- **ML-KEM decapsulation-value anchoring.** The NIST decaps leg (`c` → `K`)
  requires importing an expanded 2400-octet decapsulation key, which Go's
  public `crypto/mlkem` cannot; the KEM-wire KAT carries the NIST values and
  documents this as its remaining growth item (binding §8). This document
  inherits that limitation for its §4.2/§5.2 pedagogical material only — the
  golden vector's own key schedule (§8.3) does not depend on it, since it uses
  the vector's own captured, self-validating shared secret (§5.2 note).
- **Not covered at all:** High/Sovereign parameter rows; key updates/epochs
  beyond 0; the master ratchet (`../10_handshake_binding.md` §9); CLOSE and the
  reserved cross-channel frame types; fragmentation and compression flags;
  TLS-carriage specifics beyond the ALPN identifier — the current normative
  ALPN is `n-pamp/3` (`../01_alpn.md`); the 2026-06-23 capture (§15) predates
  the `n-pamp/3` ALPN bump by roughly seven weeks, and its negotiated ALPN AT
  CAPTURE TIME is not independently re-verifiable from the preserved record —
  it is NOT asserted to be `n-pamp/2` either, since that would be an unverified
  guess, not a correction; the reverse-direction application path and
  durability caveats stated in the interop capture's own honest-scope
  statement (§15).
- **The `dir` octet values** (`0`/`1`) are grounded in the reference
  implementations and KAT harness, not yet in the handshake binding's own
  prose (§8.1 note).

## 14. Conformance

This document is **informative**. It imposes no requirements beyond those of
the documents it cites, and conformance language reproduced here binds only via
its source. For avoidance of doubt:

1. An implementation conforms to the handshake binding by satisfying
   `../10_handshake_binding.md` and the core specification — never by matching
   this walk-through.
2. Conformance testing MUST use the pinned corpus
   (`../../test-vectors/v1/*.json`) and its harness
   (`impl/_conformance-harness/`) directly. §8.3's and §11's key-ladder tables
   ARE transcriptions of real pinned conformance values
   (`handshake-flow-kat.json`, machine-graded), but a hand-copied prose table
   is never the machine-graded artifact — an implementation MUST be graded
   against the JSON file and the harness, not against this document. §11's
   illustrative APP_REQUEST/APP_RESPONSE numbers remain **[DERIVED]**/
   **[INTEROP]** and MUST NOT be used as conformance vectors under any
   circumstance — no vector exists for them.
3. If any value in this document is found to disagree with a pinned vector
   file or with the handshake binding, the vector file and the binding are
   correct and this document is in error and MUST be fixed.
   `scripts/check-companion56-drift.py` mechanically re-checks the four
   handshake frame headers against the pinned vector on every run; it does not
   check every value in this document end-to-end (that was a one-time
   verification pass, §12) — see the script's own docstring for its exact
   scope.

## 15. Implementation Status (RFC 7942 / BCP 205)

> **Note to the RFC Editor:** this section is to be removed before publication,
> per RFC 7942 §1 — it is retained here only for the drafting/review process.

This section records the status of known implementations of the protocol
defined by this specification at the time of posting of this Internet-Draft,
and is based on a proposal described in RFC 7942. The description of
implementations in this section is intended to assist the IETF in its decision
processes in progressing drafts to RFCs. Please note that the listing of any
individual implementation here does not imply endorsement by the IETF.
Furthermore, no effort has been spent to verify the information presented here
that was supplied by IETF contributors. This is not intended as, and must not
be construed to be, a catalog of available implementations or their features.
Readers are advised to note that other implementations may exist. According to
RFC 7942, "this will allow reviewers and working groups to assign due
consideration to documents that have the benefit of running code, which may
serve as evidence of valuable experimentation and feedback that have made the
implemented protocols more mature. It is up to the individual working groups to
use this information as they see fit."

### 15.1 Go reference implementation

- **Organization:** BubbleFish Technologies, Inc.
- **Implementation:** `impl/go` — the N-PAMP Go reference implementation.
- **Description:** the full 1.5-RTT Standard-profile handshake, the §5/§8 key
  schedule, the §6 transcript construction, §9 CertVerify/Finished, and the
  master ratchet (`../10_handshake_binding.md` §9). Source of every
  `[KAT:handshake-flow]`-tagged value in §3–§11 of this document, via
  `test-vectors/v1/handshake-flow-kat.json`.
- **Maturity:** prototype / reference implementation (not a production
  release).
- **Coverage:** all five handshake-layer KATs (KEM-wire, key-schedule,
  transcript, Finished, CertVerify) and the golden-interop handshake-flow KAT
  (binding §8); High/Sovereign PQ-primitive branches are code points only,
  pending reference implementations (ADR-0004).
- **Version compatibility:** `draft-bubblefish-npamp-01`, crypto generation 3
  (`n-pamp/3`).
- **Licensing:** Apache-2.0 (`../../LICENSE`).
- **Contact:** BubbleFish Technologies, Inc. (`../../MAINTAINERS.md`).
- **Date of last update:** 2026-08-14 (this revision).

### 15.2 Live interop capture (2026-06-23) — preserved historical record

The trace below was recorded on 2026-06-23 between the Go daemon and a
TypeScript client: 48 frames, recomputed-CRC-validated, taken from the agent's
own process. It predates `test-vectors/v1/handshake-flow-kat.json` (the golden
vector this document is sourced from throughout §3–§11; §1.1) by roughly seven
weeks. **The numbers below are reproduced verbatim from that capture and are
NOT edited for consistency with the golden vector** — see §4.3's sidebar and
§13 for exactly how the two associations differ and why (both are spec-legal;
the capture offered three profiles, the golden vector offers one).

- **Organization:** BubbleFish Technologies, Inc.
- **Implementation:** the same Go daemon (server) and a TypeScript client
  (`impl/typescript`), interoperating live.
- **Description:** an end-to-end 1.5-RTT handshake followed by one application
  memory write, independently read back, together with negative controls
  (plaintext HTTP rejected, wrong ALPN rejected, wrong pinned server key
  rejected).
- **Maturity:** prototype interop demonstration.
- **Coverage:** the four handshake flights plus one application
  request/response exchange; does not cover High/Sovereign, key updates, or
  the master ratchet.
- **Version compatibility:** captured 2026-06-23. The negotiated ALPN at
  capture time is not independently re-verifiable from the preserved record —
  it predates the `n-pamp/3` ALPN bump and is not asserted to be any specific
  value (§13).
- **Licensing:** Apache-2.0 (`../../LICENSE`).
- **Date:** 2026-06-23.

```
SEND  magic=NPAM ver=0x2 flags=0x0      type=0x0100(CLIENT_HELLO) chan=0x0000 seq=0 payloadLen=1245 total=1281
RECV  magic=NPAM ver=0x2 flags=0x0      type=0x0101(SERVER_HELLO) chan=0x0000 seq=0 payloadLen=1147 total=1183
RECV  magic=NPAM ver=0x2 flags=0x2/ENC  type=0x0102(SERVER_AUTH)  chan=0x0000 seq=0 payloadLen=158  total=194
SEND  magic=NPAM ver=0x2 flags=0x2/ENC  type=0x0103(CLIENT_AUTH)  chan=0x0000 seq=0 payloadLen=158  total=194
SEND  magic=NPAM ver=0x2 flags=0x2/ENC  type=0x0120(APP_REQUEST)  chan=0x0001 seq=0 payloadLen=570  total=606
RECV  magic=NPAM ver=0x2 flags=0x2/ENC  type=0x0121(APP_RESPONSE) chan=0x0001 seq=0 payloadLen=85   total=121
```

The six 36-octet headers recorded by that capture, CRC32C recomputed by the
same oracle §12 anchors (unchanged from the capture; NOT reconciled with the
golden vector — see §4.3):

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
