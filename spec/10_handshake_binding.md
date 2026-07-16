# N-PAMP-01 — Handshake Binding (normative)

> **Authoritative for the N-PAMP 1.5-RTT handshake binding.** The published
> `draft-bubblefish-npamp-latest.md` specifies the handshake *requirements* and the negotiation
> *vocabulary* (TLV tags, KEM/AEAD/Sig/profile code points, frame envelope, AAD/nonce, the
> HKDF-Expand-Label primitive) but does not fix the handshake *wire bytes*. This document
> fixes them. It is grounded in TLS 1.3 {{RFC8446}} where it reuses a construction and marks
> every N-PAMP-original choice. Targeted for ratification into draft-01.
>
> **Provenance legend** — **[STD]** reused from a cited standard (RFC 8446 / draft-ietf-tls-
> ecdhe-mlkem / FIPS 203 / RFC 7748 / RFC 5869), the standard governs · **[D→RFC]** N-PAMP
> applies an RFC pattern with N-PAMP parameters · **[D→N-PAMP]** N-PAMP-original, this document
> is the authority. Reference implementations live under `impl/`. Profiles are
> parameterized, not duplicated (ADR-0003): one wire format, one construction, a parameter row.

## 1. Message flow (1.5-RTT, mutual authentication)

The handshake is **four frames** over the Control channel (`0x0000`), a 1.5-RTT exchange in
which both peers authenticate. There is no separate Finished frame — the Finished MAC is a
TLV inside each AUTH frame. **[D→N-PAMP]** (modeled on RFC 8446 §4 but with N-PAMP framing).

```
client ── CLIENT_HELLO (0x0100), cleartext ─────────────▶ server
client ◀── SERVER_HELLO (0x0101), cleartext ──────────── server
       ◀── SERVER_AUTH  (0x0102), ENCRYPTED ──────────── server   (server flight)
client ── CLIENT_AUTH  (0x0103), ENCRYPTED ─────────────▶ server
```

Each frame is the 36-octet N-PAMP frame (§2 of `02_frame_format.md`) on channel `0x0000`,
seq `0`, frame type as below; AUTH frames set `FlagENC` and are AEAD-sealed (§6.4).

| Frame | Type | Phase | TLVs (in order) | Encryption |
|-------|------|-------|-----------------|------------|
| CLIENT_HELLO | `0x0100` | Cleartext | ProfileOffer `0x01`, KEMOffer `0x03`, SigOffer `0x05`, AEADOffer `0x0C`, KEMShare `0x07` | None |
| SERVER_HELLO | `0x0101` | Cleartext | ProfileSelect `0x02`, KEMSelect `0x04`, SigSelect `0x06`, AEADSelect `0x0D`, KEMCiphertext `0x08` | None |
| SERVER_AUTH | `0x0102` | Encrypted | IdentityKey `0x09`, CertVerify `0x0A`, Finished `0x0B` | negotiated AEAD (handshake key, §6.4) |
| CLIENT_AUTH | `0x0103` | Encrypted | IdentityKey `0x09`, CertVerify `0x0A`, Finished `0x0B` | negotiated AEAD (handshake key, §6.4) |

A server reaches the keyed/Established state only after CLIENT_AUTH (the master secret is
derived at the client-auth boundary, §5). **[D→N-PAMP]**

### 1.1 Frame-type and TLV code points

Handshake frame types occupy the Control channel-specific space (`>= 0x0100`): `0x0100`
CLIENT_HELLO, `0x0101` SERVER_HELLO, `0x0102` SERVER_AUTH, `0x0103` CLIENT_AUTH. **[D→N-PAMP]**
(unassigned in published draft-00; frozen for draft-01).

Handshake TLV tags: `0x09` IdentityKey, `0x0A` CertVerify, `0x0B` Finished, `0x0C` AEADOffer,
`0x0D` AEADSelect. **[D→N-PAMP]**. Negotiation TLV tags `0x01`–`0x08` and the profile / KEM /
Sig / AEAD code points are reused unchanged from the published registries. **[STD/P]**

`0x0B` (Finished) carries a variable `HashLen`-octet MAC (32 @ SHA-256, 48 @ SHA-384), which is
why it is distinct from any fixed-32 reserved tag. **[D→N-PAMP]**

## 2. Cryptographic agility and profiles

One construction serves all three profiles (ADR-0003); a profile selects a parameter row:

| Parameter | Standard | High | Sovereign |
|-----------|----------|------|-----------|
| KEM (min) | X25519MLKEM768 | X25519MLKEM1024 | X25519MLKEM1024 |
| Signature | Ed25519 | Ed25519, ML-DSA-87 | ML-DSA-87 |
| KDF hash `H` | SHA-256 | SHA-384 | SHA-384 |
| `HashLen` | 32 | 48 | 48 |
| Per-frame AEAD diversification | Off | On | On |

`H` and `HashLen` are read from the negotiated profile throughout this document. **[STD/P]**
(`05_profiles.md`). The reference build implements the Standard row and the High/Sovereign
SHA-384 key-schedule branch; the High/Sovereign PQ-primitive implementations (ML-KEM-1024,
ML-DSA-87) are public code points, published as reference implementations become available (ADR-0004).

## 3. Transcript construction

The transcript is a running byte buffer; a transcript-hash point is `H` over all bytes
absorbed so far. The transcript absorbs, in handshake order: **[D→N-PAMP]** (deliberately
diverges from RFC 8446 §4.4.1, which hashes whole handshake messages including their
type+length headers).

- **AddFrameType(ft):** the **2-octet big-endian frame type only**. The remaining 34 octets of
  the N-PAMP frame header (magic, flags, channel, seq, payload-length, CRC, reserved) and the
  AEAD tag are **NOT** absorbed.
- **AddTLV(t):** one TLV in canonical `Type(2) ‖ Length(2) ‖ Value` form.
- A frame contributes `AddFrameType(ft)` then `AddTLV` for each of its TLVs in order.

Granularity is **per-TLV** (finer than RFC 8446's per-message), so the bundled AUTH frame can
be hashed up to sub-frame boundaries. The five transcript points:

| Symbol | Absorbed through | Used by |
|--------|------------------|---------|
| `TH_kem` | `0x0100 ‖ CH-TLVs ‖ 0x0101 ‖ SH-TLVs` | handshake-secret labels (§5) |
| `TH_sId` | `… ‖ 0x0102 ‖ ServerIdentityKey` | Server CertVerify signs this (§6.1) |
| `TH_sCV` | `… ‖ ServerCertVerify` (excludes ServerFinished) | Server Finished MACs this (§6.2) |
| `TH_cId` | `… ‖ ServerFinished ‖ 0x0103 ‖ ClientIdentityKey` | Client CertVerify signs this |
| `TH_cCV` | `… ‖ ClientCertVerify` (excludes ClientFinished) | Client Finished MACs; master derived from this |

Both peers absorb the identical decoded on-wire TLV bytes, so transcripts are byte-identical.

## 4. Hybrid key encapsulation — X25519MLKEM768

KEM `0x11ec` (Standard/High). **ML-KEM-first** in both the shared secret and the wire layout,
per {{I-D.ietf-tls-ecdhe-mlkem}} + NIST SP 800-56C Rev. 2 (the FIPS-approved secret leads the
HKDF input). **The suite name lists X25519 first; the bytes are ML-KEM-first** (ADR-0005). **[STD]**

- **KEMShare (TLV `0x07`):** `ML-KEM-768 encapsulation key (1184) ‖ X25519 public key (32)` =
  **1216** octets. **[STD]** sizes per FIPS 203 / RFC 7748.
- **KEMCiphertext (TLV `0x08`):** `ML-KEM-768 ciphertext (1088) ‖ server X25519 public key (32)`
  = **1120** octets. **[STD]**
- **Shared secret (KEM output, IKM to §5):** `ML-KEM SS (32) ‖ X25519 SS (32)` = **64** octets,
  fed raw to HKDF-Extract (no hybrid-layer KDF — the key schedule's Extract is the combiner,
  a dual-PRF). **[STD]**
- Component KEMs: ML-KEM-768 `Encaps/Decaps` per FIPS 203 (implicit rejection: a corrupt
  ciphertext yields a pseudorandom secret that fails the Finished MAC, not an error). X25519
  per RFC 7748; an all-zero (low-order) X25519 output is rejected. **[STD]**

Sovereign MUST NOT accept X25519MLKEM768 (it requires X25519MLKEM1024, `0x11ed`). **[STD/P]**

## 5. Key schedule (§6 secrets)

A **single** HKDF-Extract followed by sibling HKDF-Expand-Label derivations. **[D→N-PAMP]**
(deliberately simpler than RFC 8446 §7.1's three-stage Early/Handshake/Master Extract chain;
N-PAMP has no PSK/0-RTT in this binding).

HKDF-Expand-Label is RFC 8446 §7.1 with the N-PAMP label prefix `"n-pamp "` (note the trailing
space) replacing `"tls13 "`: **[D→RFC]**

```
HKDF-Expand-Label(Secret, Label, Context, Length) =
    HKDF-Expand(Secret, HkdfLabel, Length)
HkdfLabel = uint16(Length) ‖ opaque label<7..255> = ("n-pamp " ‖ Label) ‖ opaque context<0..255> = Context
```

Extract and the secret tree (`H`/`HashLen` per profile): **[D→N-PAMP]** (IKM order **[STD]**, ADR-0005)

```
handshake_secret = HKDF-Extract(salt = HashLen·0x00, IKM = ML-KEM_SS ‖ X25519_SS)
c_hs_secret      = HKDF-Expand-Label(handshake_secret, "c hs",   TH_kem, HashLen)
s_hs_secret      = HKDF-Expand-Label(handshake_secret, "s hs",   TH_kem, HashLen)
master           = HKDF-Expand-Label(handshake_secret, "master", TH_cCV, HashLen)
```

- The Extract salt is `HashLen` zero octets (RFC 5869 §2.2 default). **[D→RFC]**
- Full labels on the wire: `"n-pamp c hs"`, `"n-pamp s hs"`, `"n-pamp master"`,
  `"n-pamp finished"` (§6.2). `master` is derived only at the client-auth boundary, from
  `TH_cCV`. **[D→N-PAMP]**

Traffic keys (both handshake and application phases): **[D→N-PAMP]**

```
traffic_secret = DeriveTrafficSecret(parent, dir, epoch, suite, channel, H)
               // context = dir(1) ‖ epoch(8 BE) ‖ suite(2 BE) ‖ channel(2 BE), label "traffic"
(key[32], iv[12]) = ( HKDF-Expand-Label(traffic_secret, "key", "", 32),
                      HKDF-Expand-Label(traffic_secret, "iv",  "", 12) )
```

Handshake-phase keys descend from `c_hs_secret`/`s_hs_secret` (epoch 0, Control channel);
application-phase keys descend from `master`. Because the parents differ, an identical
`(dir, epoch, suite, channel)` tuple yields different (key, iv) across phases — no (key,nonce)
is shared across phases. **[D→N-PAMP]**

## 6. Authentication

### 6.1 CertVerify (TLV `0x0A`)

A signature over the transcript, structured per RFC 8446 §4.4.3 with N-PAMP context strings: **[D→RFC]**

```
signing_input = 0x20 × 64  ‖  context  ‖  0x00  ‖  transcript_hash
context (server) = "N-PAMP/2, server CertificateVerify"   // [D→N-PAMP]
context (client) = "N-PAMP/2, client CertificateVerify"
```

The signed `transcript_hash` is `TH_sId` (server) / `TH_cId` (client) — the transcript through
the signer's own IdentityKey, before its own CertVerify. The TLV value is
`SignatureScheme uint16 (Ed25519 = 0x0807) ‖ signature` (the inner signature has no length
prefix; the TLV Length delimits it). A verifier MUST reject a scheme it did not negotiate and
MUST check the role (server vs client) — the differing context string makes a server CertVerify
unusable as a client one. **[D→N-PAMP]** (carriage), **[STD]** Ed25519 = RFC 8032.

### 6.2 Finished (TLV `0x0B`)

Per RFC 8446 §4.4.4, keyed by the sender's handshake traffic secret: **[D→RFC]**

```
finished_key = HKDF-Expand-Label(BaseKey, "finished", "", HashLen)   // BaseKey = c_hs/s_hs per direction
verify_data  = HMAC(finished_key, transcript_hash)                   // HMAC per RFC 2104, hash = H
```

The MAC'd `transcript_hash` is `TH_sCV` (server) / `TH_cCV` (client) — the transcript through
the signer's own CertVerify, excluding its own Finished. `verify_data` length = `HashLen`.
Verification MUST be constant-time and abort on mismatch. **[D→N-PAMP]** (which transcript point
each covers).

### 6.3 Downgrade protection

The negotiated profile and algorithm selections are carried in the cleartext CH/SH and are
absorbed into the transcript that the Finished MAC and CertVerify cover. Stripping a profile
from the offer or forcing a lower selection therefore invalidates the MAC and aborts the
handshake. **[D→N-PAMP]** (N-PAMP uses transcript binding rather than a TLS-style
ServerHello.Random `DOWNGRD` sentinel).

### 6.4 AUTH-frame sealing

SERVER_AUTH/CLIENT_AUTH are sealed with the negotiated AEAD (the primary suite = `AEADSelect[0]`,
the server's selected handshake suite) under the per-direction handshake key/iv
(§5): `Flags = FlagENC`, `Channel = 0x0000`, `Seq = 0`; AAD = the 21-octet frame header prefix;
nonce = `iv XOR seq` (§4 of `06_cryptographic_suites.md`). On open, exactly three TLVs in order
(IdentityKey, CertVerify, Finished) are required. **[negotiated per AEADSelect `0x0D`]** AEAD; **[D→N-PAMP]** the 3-TLV AUTH layout.

## 7. Security considerations (summary of divergences from TLS 1.3)

This binding deliberately diverges from RFC 8446 in three documented ways; each is an
N-PAMP design decision, not a TLS conformance claim, and is in scope for the formal-methods
re-targeting (`formal/`):

1. **Transcript** absorbs only the 2-octet frame type plus per-TLV bytes — not the full frame
   header. The frame header's integrity for encrypted frames is covered by the AEAD AAD (§6.4);
   for cleartext CH/SH the header carries no security-relevant field the transcript needs (the
   channel and frame type are fixed for the handshake and the frame type **is** absorbed).
   Analysis MUST confirm no security-relevant header field is left unbound.
2. **Single-Extract key schedule** (§5) rather than TLS's three-stage derive-secret chain.
   Sound because there is no PSK/0-RTT stage to separate; the master/handshake separation is by
   label and by the transcript context bound into each Expand-Label.
3. **Hybrid KEM ordering** is ML-KEM-first (§4, ADR-0005), satisfying SP 800-56C Rev. 2 and
   matching {{I-D.ietf-tls-ecdhe-mlkem}}.

Confidentiality holds as long as at least one KEM component (X25519 or ML-KEM-768) is unbroken
(the concatenation-into-HKDF-Extract dual-PRF combiner). **[STD]**

**Forward secrecy and key erasure.** Session confidentiality is forward-secure against
compromise of the long-term *identity* keys: every session secret derives from the *ephemeral*
hybrid KEM shares (§4), so an attacker who later obtains a peer's Ed25519 identity key cannot
decrypt previously recorded sessions. To realize this in practice an implementation SHOULD
zeroize each per-channel traffic secret and its derived `(key, iv)` as soon as an epoch is
retired, and MUST zeroize the connection's key-schedule secrets — including `master` (§5) —
when the connection closes. Erasure is best-effort, bounded by the runtime's memory model (a
garbage-collected or paging runtime MAY leave residue in copied or swapped memory, a limitation
an implementation SHOULD document rather than claim stronger guarantees than it can enforce).
LIMITATION (no intra-session forward secrecy against `master` compromise): within a live
connection `master` is retained so that `DeriveTrafficSecret(master, …)` (§5) can derive later
epochs; consequently an attacker who extracts `master` can reproduce every channel's `(key, iv)`
at every epoch of that connection. This is inherent to a single-retained-root schedule and is
acceptable under the identity-key-compromise threat model above, but it means the schedule
provides forward secrecy across *sessions*, not *within* one against `master` compromise.
Bounding that intra-session exposure window requires a master-level ratchet — a one-way
HKDF-Expand-Label chain over `master`, optionally re-seeded by a periodic re-KEM for
post-compromise self-healing — which is an enhancement OUT OF SCOPE for this binding and tracked
separately.

## 8. Conformance notes

The published draft-00 conformance corpus grades only primitives (header/CRC/AEAD/HKDF/TLV/
profile) and carries **no handshake-layer vectors**. To make this binding independently
conformance-testable (not merely self-interop-testable), the following standards-derived,
non-circular vectors are required and are tracked as corpus growth:

- **KEM-wire KAT** — **DELIVERED** (`test-vectors/v1/kem-wire-kat.json`, ADR-0007). ML-KEM-768
  keygen from a NIST seed `d‖z` (NIST ACVP, FIPS 203) and X25519 from RFC 7748 §6.1, asserting
  the ML-KEM-first wire order of KEMShare (`ek ‖ x25519_pub`), the client KEMCiphertext parse
  (X25519 half anchored to RFC 7748's shared secret), and the HKDF-Extract IKM order
  (`ML-KEM_SS ‖ X25519_SS`). This closes the wire-byte-order gap that symmetric self-interop +
  code review could not catch (the original X25519-first defect; ADR-0005). **Documented
  limitation:** the ML-KEM *decapsulation* leg's shared-secret VALUE is not anchored to NIST via
  Go's public `crypto/mlkem`, because that API imports only the 64-byte seed and NIST ACVP
  encapDecap supplies the key as an expanded decapsulation key; the NIST decaps vector (`c`, `K`)
  is carried in the KAT file for implementations that can import an expanded dk, and is the
  remaining growth item for a fully-NIST-anchored ML-KEM shared secret.
- **Key-schedule KAT** — **DELIVERED** (`test-vectors/v1/key-schedule-kat.json`, ADR-0008). Fixed
  KEM secrets + fixed transcript points → the `handshake_secret` ladder (`c hs`/`s hs`/`master`),
  the handshake/application traffic (key, iv), and `finished_key`. Non-circular by EXTERNAL ANCHOR:
  N-PAMP's HKDF-Expand-Label is RFC 8446 §7.1 with the `"n-pamp "` prefix, so the KAT proves an
  independent Expand-Label oracle against **RFC 8448** (TLS 1.3, `"tls13 "` prefix) and **RFC 5869**
  (raw HKDF), then applies that proven oracle with `"n-pamp "` to check the schedule. The file
  carries the RFC anchors + fixed inputs (not implementation-produced output bytes). Now mirrored
  non-circularly across all reference impls — Go as the reference implementation; TypeScript / Python / Java /
  Kotlin / Ruby / PHP / Rust / C# under `impl/` — gated by `impl/_conformance-harness/kat-handshake-all-langs.sh`.
  Each `impl/` language carries the full trunk (HKDF-Extract → `handshake_secret` → `c_hs`/`s_hs`/`master`
  → `finished_key` + the handshake-phase traffic key/iv); the §7.5 traffic context binds the AEAD code
  point the reference vector fixes as its test input — AES-256-GCM `0x0001` (`registries/aead.csv`; `0x0002`
  is ChaCha20-Poly1305) — the KAT fixture, NOT the AUTH-sealing rule (AUTH uses the negotiated AEAD, §6.4). Mutation-proven per
  language (an X25519-first IKM order — violating ML-KEM-first / ADR-0005 — fails the impl leg only).
- **Transcript KAT** — **DELIVERED** (`test-vectors/v1/transcript-kat.json`, ADR-0009). Fixed
  frame/TLV inputs → each `TH_*` point (`TH_kem`/`TH_sId`/`TH_sCV`/`TH_cId`/`TH_cCV`). Non-circular by
  construction: the expected points are produced by an INDEPENDENT per-TLV byte-constructor
  (frame-type as 2-octet BE; each TLV as `Type(2)‖Length(2)‖Value`) + SHA-256, with the SHA-256
  primitive itself anchored to **FIPS 180-4** (`SHA-256("abc")`); the consuming test re-derives every
  point via its own manual oracle AND via the implementation's `Transcript`, which must agree. This
  pins the §3/§7.1 divergence from RFC 8446 §4.4.1 (only the 2-octet frame type is absorbed, at
  per-TLV granularity): a header-creep or per-message regression fails the impl leg only.
  Delivered + mutation-proven, and now mirrored non-circularly across all reference impls — Go as the
  reference implementation; TypeScript / Python / Java / Kotlin / Ruby / PHP / Rust / C# under `impl/` — gated by
  `impl/_conformance-harness/kat-handshake-all-langs.sh`.
- **Finished KAT** — **DELIVERED** (`test-vectors/v1/finished-kat.json`, ADR-0010). `verify_data` =
  HMAC-SHA256(`finished_key`, `transcript_hash`) (§6.2 / RFC 8446 §4.4.4). Non-circular: the expected
  `verify_data` are produced with an independent `crypto/hmac`, with the HMAC-SHA-256 primitive
  anchored to **RFC 4231** TC1/TC2; the `finished_key` is a fixture (its derivation is anchored by the
  key-schedule KAT) and the `transcript_hash` inputs are the Transcript KAT's `TH_sCV`/`TH_cCV` (the
  points §6.2 covers). The consuming test runs anchor/oracle/impl legs + a `VerifyFinished`
  accept/reject check; mutation-proven (a key-independent hash fails the impl leg only). Mirrored
  non-circularly across all reference impls (gated by `kat-handshake-all-langs.sh`).
- **CertVerify KAT** — **DELIVERED** (`test-vectors/v1/certverify-kat.json`, ADR-0011). CertVerify
  value = `u16(0x0807) ‖ Ed25519(priv, signing_input)`, `signing_input = 0x20×64 ‖ context ‖ 0x00 ‖
  transcript_hash` (§6.1 / RFC 8446 §4.4.3). Non-circular: the expected signatures are produced with
  an independent `crypto/ed25519`, with the Ed25519 primitive anchored to **RFC 8032** §7.1 TEST 1/2
  (published public keys + signatures); the `transcript_hash` inputs are the Transcript KAT's
  `TH_sId`/`TH_cId` (the points each role signs); Ed25519 is deterministic so any conforming signer
  reproduces them. The consuming test runs anchor/oracle/impl legs and checks `VerifyCertVerify`
  accepts the correct value but REJECTS a role/context mismatch (domain separation) and a wrong
  transcript (binding); mutation-proven (a corrupted signing-input separator fails the impl leg
  only). Mirrored non-circularly across all reference impls (gated by `kat-handshake-all-langs.sh`).

**All five handshake-layer KATs (KEM-wire, key-schedule, transcript, Finished, CertVerify) now have
standards-derived, non-circular KATs** — the original draft-00 binding is graded against the
standards (NIST FIPS 203 / RFC 7748 / 8446 / 8448 / 5869 / 4231 / 8032 / FIPS 180-4), not merely
self-interop-tested. The key-schedule / transcript / Finished / CertVerify KATs are now mirrored
non-circularly across all reference impls (gated by `impl/_conformance-harness/kat-handshake-all-langs.sh`;
Go is covered by its own KATs) — each `impl/` language carries the full handshake key
schedule (HKDF-Extract → `handshake_secret` → `c_hs`/`s_hs`/`master` ladder → `finished_key` +
handshake-phase traffic key/iv, binding the AEAD code point the vector fixes as its test input — AES-256-GCM `0x0001`, the KAT fixture, not the AUTH-sealing rule; AUTH uses the negotiated AEAD per §6.4). Only the KEM-wire KAT
remains on the Go reference — broadening it across the `impl/` languages is follow-on work: the ML-KEM
KEM-wire layout needs a per-language ML-KEM dependency that is not generally available.

## 9. Master ratchet — Hybrid Tree Ratchet (normative)

The key schedule of §5 retains a single connection `master` for the connection lifetime, so
`DeriveTrafficSecret(master, …)` can reproduce every channel's `(key, iv)` at every epoch. That is
forward-secure across *sessions* (the master derives from the ephemeral hybrid KEM of §4) but NOT
*within* a session: a `master` compromise discloses all past and future epochs of the live
connection (the §7 LIMITATION). The **master ratchet** — a two-tier **Hybrid Tree Ratchet (HTR)**
— closes that intra-session gap. It advances the connection root over time so that a `master`
compromise is bounded on both sides, and it does so entirely above generation 0, so the §5
schedule, the §3 transcript, and all five §8 handshake KATs are **unchanged**. **[D→N-PAMP]**

The ratchet is **per-direction**. Each endpoint keeps two roots and two generation counters:

```
master_send   root for the direction this endpoint SENDS    (== the peer's master_recv)
master_recv   root for the direction this endpoint RECEIVES  (== the peer's master_send)
gen_send      generation index of master_send, starts 0
gen_recv      generation index of master_recv, starts 0
```

At handshake completion both roots are seeded from the §5 `master` (the `TH_cCV`-bound value) at
generation 0; i.e. `master_send_0 = master_recv_0 = master`. **Generation 0 is byte-identical to the
§5 schedule**: because the ratcheted root enters `DeriveTrafficSecret` unchanged (the leaf context
tuple of §5 is not modified — see §9.4), a connection that never ratchets derives exactly the keys
it derives today, and the §8 key-schedule/traffic KATs still pass. **[D→N-PAMP]**

Because every ratchet step is deterministic in its inputs, both peers compute the same
`master_{G}` for the same direction and generation; the leaf `dir` octet (unchanged, §5) keeps the
two directions' traffic keys separated exactly as today.

### 9.1 Tier 1 — symmetric forward step (forward secrecy)

For a direction at generation `G`, the Tier-1 step advances the root by one HKDF-Expand-Label
(the §5 primitive), then zeroizes the retired root in place: **[D→RFC]** (RFC 8446 §7.1
Expand-Label with the `"n-pamp "` prefix)

```
master_{G+1} = HKDF-Expand-Label(master_G, "master ratchet", gen(8 BE, value G+1), HashLen)
```

- The context is the **new** generation index `G+1` as an 8-octet big-endian integer.
- The full label on the wire is `"n-pamp master ratchet"` (`"n-pamp " ‖ "master ratchet"`).
- HKDF-Expand is one-way, so `master_G` and every earlier generation are unrecoverable from
  `master_{G+1}`. This provides **forward secrecy, not self-healing**: the chain is deterministic,
  so an attacker who holds `master_G` can compute every *future* Tier-1 root. Post-compromise
  self-healing is Tier 2 (§9.2). **[D→N-PAMP]**

An implementation MUST zeroize `master_G` in place after deriving `master_{G+1}` (best-effort per
the §7 memory-model caveat), and MUST drop every cached per-channel key of that direction so each
channel re-derives off the new root at leaf epoch 0. Tier 1 injects nothing on the wire beyond the
boundary marker (§9.3) and so needs no transcript point.

### 9.2 Tier 2 — asymmetric re-KEM step (forward secrecy + post-compromise security)

The Tier-2 step mixes fresh entropy from a new ephemeral `X25519MLKEM768` exchange — the **same**
construction, TLVs, and 64-octet combined secret as the handshake KEM (§4), with no new primitive —
through an Extract-then-Expand step that mirrors the §5 `handshake_secret`→`master` shape: **[STD]**
(KEM per §4), **[D→RFC]** (RFC 5869 §2.2 Extract; RFC 8446 §7.1 Expand-Label)

```
new_ss       = ML-KEM_SS ‖ X25519_SS                                          // 64 octets, exactly as §4
rekem_secret = HKDF-Extract(salt = master_G, IKM = new_ss)                    // dual-PRF combiner
master_{G+1} = HKDF-Expand-Label(rekem_secret, "master ratchet rekem", TH_rekem_G, HashLen)
```

- The full label on the wire is `"n-pamp master ratchet rekem"`.
- The **old root sits in the salt position and the fresh secret in the IKM position** (RFC 5869
  §2.2 / the Signal root-KDF placement), unlike the §5 handshake Extract whose salt is `HashLen`
  zero octets. Consequently `master_{G+1}` is uniform even if `master_G` is fully known to the
  attacker: without `new_ss` the attacker cannot compute `master_{G+1}`, and the direction
  **self-heals** — genuine **post-quantum** post-compromise security, since the re-KEM is the same
  hybrid KEM as the handshake. **[D→N-PAMP]**
- Confidentiality of `master_{G+1}` extends the §7 dual-PRF claim one level: it holds if EITHER the
  chained old root OR one fresh KEM component (X25519 or ML-KEM-768) is unbroken. **[STD]**

`TH_rekem_G` (§9.5) binds the exact REKEM/REKEM_ACK exchange bytes into the new root, defeating
splicing and reflection the same way `master` is bound to `TH_cCV` (§3, §5). An implementation MUST
zeroize `master_G`, `rekem_secret`, `new_ss`, and the ephemeral KEM private keys after the step,
and MUST drop every cached per-channel key of the affected direction (leaf epoch resets to 0). A
Tier-1-only deployment provides forward secrecy but NOT self-healing and MUST NOT be reported as
providing post-compromise security. **[D→N-PAMP]**

### 9.3 Control frame types and TLV (extends §1.1)

The four ratchet control frames are **Control channel-specific** frame types in the space `>=
0x0100` (grouped with the §1.1 handshake frames, which occupy `0x0100`–`0x0103`). They are
interpreted ONLY on the Control channel (`0x0000`); the same numeric values carry unrelated
per-channel meanings in other channels' frame-type namespaces (`04_frame_types.md`), so a receiver
MUST dispatch ratchet handling only for a frame of these types arriving on channel `0x0000`. Each
is sealed under the **current** generation's Control-channel key (like KEY_UPDATE). **[D→N-PAMP]**

| Type | Name | Direction | Role |
|------|------|-----------|------|
| `0x0104` | MASTER_RATCHET | sender→peer | Tier-1 **boundary**: last frame at `gen_send`; carries `TLVRatchetGeneration = gen_send+1` |
| `0x0105` | MASTER_RATCHET_ACK | peer→sender | Tier-1 confirmation (informational, like KEY_UPDATE_ACK) |
| `0x0106` | REKEM | initiator→responder | Tier-2 **request** (not a boundary); carries `KEMShare 0x07` ‖ `TLVRatchetGeneration` |
| `0x0107` | REKEM_ACK | responder→initiator | Tier-2 **boundary** for the responder's send direction; carries `KEMCiphertext 0x08` ‖ `TLVRatchetGeneration` |

TLV code points: **[D→N-PAMP]**

| TLV | Status | Value |
|-----|--------|-------|
| `TLVRatchetGeneration 0x19` | **NEW** (next free after `0x18`) | 8-octet big-endian generation, mirroring `TLVKeyUpdateMarker 0x17` |
| `TLVKEMShare 0x07` | reused (§4) | ML-KEM-768 ek (1184) ‖ X25519 pub (32) = **1216** octets |
| `TLVKEMCiphertext 0x08` | reused (§4) | ML-KEM-768 ct (1088) ‖ server X25519 pub (32) = **1120** octets |

REKEM carries exactly `KEMShare` then `TLVRatchetGeneration`; REKEM_ACK carries exactly
`KEMCiphertext` then `TLVRatchetGeneration`; MASTER_RATCHET and MASTER_RATCHET_ACK carry exactly a
single `TLVRatchetGeneration`. A receiver MUST reject any other TLV layout, and MUST reject a
`KEMShare`/`KEMCiphertext` of the wrong length (§4 sizes) and a `TLVRatchetGeneration` that is not
8 octets. **[D→N-PAMP]**

### 9.4 Leaf derivation is unchanged (parity)

Application traffic secrets keep hanging off the ratcheted root, MLS-epoch-style. The §5
`DeriveTrafficSecret` and its context tuple are **byte-for-byte unchanged**: **[D→N-PAMP]**

```
traffic_secret = DeriveTrafficSecret(master_G, dir, epoch, suite, channel, H)
               // context = dir(1) ‖ epoch(8 BE) ‖ suite(2 BE) ‖ channel(2 BE), label "traffic"  — UNCHANGED from §5
```

The generation `G` enters ONLY through the parent root `master_G`, **never** the leaf context.
This is the load-bearing parity point: generation 0 reproduces the §5 keys exactly, so no §8 KAT,
no AEAD AAD, and no data-frame header changes. Per-channel isolation remains the §5 spatial
domain-separation (the `channel` octet), not root-independence: within one generation a root
compromise still falls all channels of that direction — HTR bounds exposure over *time*, not the
blast radius inside a generation. **[D→N-PAMP]**

### 9.5 Re-KEM transcript point `TH_rekem_G`

`TH_rekem_G` is a per-generation transcript-hash point computed with the §3 construction (the
2-octet big-endian frame type via `AddFrameType`; each TLV in canonical `Type(2) ‖ Length(2) ‖
Value` via `AddTLV`), absorbing the REKEM exchange in wire order: **[D→N-PAMP]**

```
TH_rekem_G = H( AddFrameType(0x0106) ‖ AddTLV(KEMShare) ‖ AddTLV(RatchetGeneration)
              ‖ AddFrameType(0x0107) ‖ AddTLV(KEMCiphertext) ‖ AddTLV(RatchetGeneration) )
```

Both peers assemble it identically from the decoded on-wire bytes they exchanged, so a spliced or
reflected REKEM/REKEM_ACK yields a divergent root and the next frame fails to open (fails closed).
Tier 1 requires no transcript point (§9.1). **[D→N-PAMP]**

### 9.6 On-wire choreography

Every boundary marker is sealed under the OLD (current-generation) key and is the **last frame at
that generation** on its direction — exactly the KEY_UPDATE discipline. Directions ratchet
independently; each direction's send root has a single writer, so there is no concurrent-initiation
tie-break. **[D→N-PAMP]**

**Tier 1** (per direction; one boundary frame + informational ACK). Because the root is
deterministic, each side computes `master_{G+1}` locally on processing the boundary — no agreement
round trip:

```
sender ── MASTER_RATCHET{gen=G+1}  (sealed under gen-G Control key, last gen-G send frame) ──▶ peer
        sender then advances master_send→G+1, wipes master_G, drops cached send keys
        peer opens under gen-G, MUST verify the marker == gen_recv+1, advances master_recv→G+1,
             wipes its master_G, drops cached recv keys
peer   ── MASTER_RATCHET_ACK{gen=G+1}  (informational, off the receive path) ──▶ sender
```

**Tier 2** (heals ONE direction — the stream the initiator RECEIVES — two frames, 1 RTT). Full
bidirectional PCS is two such exchanges, one initiated by each side:

```
initiator ── REKEM{KEMShare, gen}  (sealed under gen-G; initiator does NOT switch yet) ──▶ responder
          responder Encapsulate → (KEMCiphertext, new_ss); compute TH_rekem
responder ── REKEM_ACK{KEMCiphertext, gen}  (sealed under gen-G, BOUNDARY: last gen-G send frame) ──▶ initiator
          responder advances its master_send via Extract-then-Expand (§9.2), drops cached send keys,
                    wipes new_ss + ephemerals
          initiator opens REKEM_ACK under gen-G, Decapsulate → new_ss, advances master_recv identically,
                    wipes new_ss + ephemerals
```

A receiver MUST verify the announced generation equals its own `gen_recv+1` (and, for the
initiator, the pending REKEM's target) before advancing; a mismatch (generation skew) MUST fail
closed without advancing, leaving the direction at generation `G`. ML-KEM implicit rejection of a
corrupt ciphertext (§4) yields a pseudorandom `new_ss`, diverging the two roots so the next frame
fails to open — the fail-closed analogue of a failed Finished MAC. A low-order/all-zero X25519
output MUST be rejected (§4). **[D→N-PAMP]**

Steady-state per-frame cost is unchanged (the generation rides in the parent root, not the wire
context). Both tiers are per-connection/per-direction, not per-channel, so cost does not scale with
the channel count: Tier 1 is one small control frame (a 36-octet header + the 8-octet
`TLVRatchetGeneration`) plus an informational ACK; Tier 2 is one hybrid-KEM round trip reusing the
§4 TLVs (`REKEM` 1216 + `REKEM_ACK` 1120 ≈ 2.3 KiB), amortized over the re-KEM cadence, with no
identity re-authentication (the peers are already authenticated). **[D→N-PAMP]**

### 9.7 Conformance

The master ratchet is graded by two standards-derived, **non-circular** KATs that extend the §8
key-schedule KAT (ADR-0008) discipline and reuse its EXACT external anchor — no new anchor family:
N-PAMP's HKDF-Expand-Label is RFC 8446 §7.1 with the `"n-pamp "` prefix and its HKDF-Extract is
RFC 5869 §2.2, so the KATs first re-prove an independent Expand-Label/Extract oracle against **RFC
8448** (TLS 1.3) and **RFC 5869** (raw HKDF), then apply that proven oracle with the `"n-pamp "`
prefix to compute the expected roots. The expected values are NOT produced by the implementation
under test. **[D→N-PAMP]**

- **Tier-1 symmetric-step KAT** — fixed `master_G` + fixed target generation → `master_{G+1}` via
  `HKDF-Expand-Label(master_G, "master ratchet", gen(8 BE), HashLen)` (§9.1); a chained
  multi-generation check confirms one-wayness. Mutation-proven: a wrong generation context fails
  the implementation leg only.
- **Tier-2 re-KEM-step KAT** — fixed `master_G` + fixed `new_ss` + fixed `TH_rekem` →
  `master_{G+1}` via `HKDF-Expand-Label(HKDF-Extract(salt = master_G, IKM = new_ss), "master
  ratchet rekem", TH_rekem, HashLen)` (§9.2). The KAT pins the salt/IKM placement (a swapped
  salt/IKM yields a different root), that a different `new_ss` self-heals to a divergent root, and
  that a spliced `TH_rekem` diverges. Mutation-proven per the same discipline.

The Go reference implementation carries both KATs (`RatchetMasterTier1` / `RatchetMasterTier2`,
graded in `impl/go`), consistent with the shipped SDK (`impl/go/sdk/ratchet.go`). Mirroring the two
ratchet KATs across the remaining `impl/` reference languages (via
`impl/_conformance-harness/kat-handshake-all-langs.sh`, as for the §8 handshake KATs) is tracked
corpus growth. **[D→N-PAMP]**
