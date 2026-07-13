# NPAMP-CONFORM — Conformance Requirements (companion to draft-bubblefish-npamp-01)

> Status: **DRAFT companion specification.** The key words "MUST", "MUST NOT",
> "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY",
> and "OPTIONAL" in this document are to be interpreted as described in BCP 14
> (RFC 2119, RFC 8174) when, and only when, they appear in all capitals, as shown
> here. This document defines the **conformance classes** for N-PAMP draft-01, the
> requirements an implementation MUST satisfy to claim each class, the evidence a
> claim MUST carry, and — explicitly — what the current conformance corpus does
> and does not verify. It builds on the N-PAMP core specification
> (draft-bubblefish-npamp-01, the "core specification"), the handshake binding
> (`../10_handshake_binding.md`), and the companion set indexed in
> `00_companion_index.md`. It introduces no change to the wire format and consumes
> no code points; its normative content is confined to conformance-claim
> requirements.

## 1. Scope

### 1.1 In scope

This document specifies:

- Three conformance classes for N-PAMP draft-01 — wire-primitives conformance
  (Class W, §3), handshake conformance (Class H, §4), and bridge/companion
  conformance (Class B, §5) — and the requirements of each;
- The conformance oracle set: the pinned vector corpus, its JSON Schemas, the
  handshake known-answer-test (KAT) files, and the grading tools that consume
  them (§6);
- The verified coverage of the current corpus, stated from the corpus itself
  (§7), and the coverage the corpus does NOT provide (§8); and
- The required content of a conformance claim, including what a claimant MUST
  NOT assert (§9).

### 1.2 Not in scope

The following are explicitly NOT defined by this document:

- **High- and Sovereign-profile conformance.** The public conformance corpus and
  the public KAT set exercise the Standard-profile parameter row (see §4, §8.4).
  The High and Sovereign profile names, code points, and public invariants
  (core specification §6, §7) are referenced where the corpus tests them; their
  operational and cryptographic internals are outside this public set, and no
  class defined here certifies them.
- **Certification, branding, or logo programs.** This document defines technical
  conformance claims only; it establishes no certifying authority.
- **Interoperability testing.** Interop between two live implementations is
  complementary evidence, not a conformance class: two
  implementations that share a defect can interoperate perfectly. Conformance
  here is graded against standards-derived vectors that no N-PAMP
  implementation produced (§6.1).
- **Performance, capacity, or robustness-under-load requirements.**
- Any change to the core wire format, the handshake binding, or any companion
  specification. Where this document restates a requirement of those documents,
  the source document is authoritative.

## 2. Conformance classes and targets

### 2.1 Targets

Conformance target:
: The unit a claim is made about — an implementation of the core wire format, of
  the handshake binding, or of one or more bridge/companion documents.

Oracle:
: A vector, KAT, or grading tool whose expected values derive from published
  standards or from the specification text, and NOT from any N-PAMP
  implementation under test (the Wycheproof model; `../../test-vectors/README.md`).

### 2.2 The three classes

| Class | Name | Normative source | Machine-gradable today |
|---|---|---|---|
| **W** | Wire-primitives conformance | Core specification §4 (wire format), §7 (cryptographic suites), §6 (profile invariants) | Yes — the 255-vector corpus (§6.1, §7) |
| **H** | Handshake conformance (Standard profile) | Handshake binding `../10_handshake_binding.md`; core specification §3, §7 | Yes — the five handshake KATs (§6.3) |
| **B** | Bridge and companion conformance | NPAMP-BRIDGE §9 and the numbered §Conformance clause of each claimed companion document | **No** — no bridge vectors exist in the corpus (§5.2, §8.2) |

The classes are cumulative where stated: Class H presupposes the Class W
primitives it builds on (CRC, TLV, AEAD, HKDF), and Class B presupposes a
core-conformant wire implementation (companion index, "Conformance posture").
A claimant MAY claim Class W alone.

### 2.3 What "conformance" is not

Passing a conformance class demonstrates that the tested operations reproduce
the standards-anchored expected values and reject the inputs the specification
says MUST be rejected. It does not demonstrate the runtime behaviors that no
static vector can exercise (replay windows, key-update bounds, zeroization,
path validation — §8.5), and it is not a security evaluation.

## 3. Class W — wire-primitives conformance

### 3.1 Requirements

An implementation claiming Class W MUST implement, and MUST pass every corpus
vector for, each of the following operations (operation names per the adapter
contract, `../../harness/INSTRUCTIONS.md`):

1. **`header.encode` / `header.decode`** — the fixed 36-octet frame header
   (core specification §4.2): magic "NPAM", Ver/Flags octet, big-endian Frame
   Type, Channel ID, 64-bit Sequence Number, Payload Length, CRC32C, and the
   11 reserved zero octets. The decoder MUST reject a header whose reserved
   octets are non-zero and MUST reject a header whose CRC32C does not verify
   (core specification §4.2; corpus flags `ReservedNonZero`, `BadCRC`).
2. **`crc32c`** — CRC32C with the Castagnoli polynomial 0x1EDC6F41 computed over
   header octets 0-20 (core specification §4.2).
3. **`tlv.decode`** — the Type(16) / Length(16) / Value TLV encoding (core
   specification §4.4). A TLV whose unknown Type has the high bit (0x8000) set
   MUST be rejected as forward-incompatible (corpus flag `UnknownCriticalTLV`).
4. **`aead.seal` / `aead.open`** — AEAD seal and open for AES-256-GCM (code
   point 0x0001, core specification §7.2), graded against Project-Wycheproof-
   derived vectors. Open MUST fail on a tampered authentication tag (corpus
   flag `AeadTagMismatch`); tag verification MUST precede any payload
   processing (core specification §10.3).
5. **`hkdf.expand`** — HKDF-Expand per RFC 5869 for SHA-256 and SHA-384,
   graded against Project-Wycheproof-derived vectors (core specification §7.4
   uses HKDF for all key derivation).
6. **`profile.check`** — the public profile KEM-acceptance invariants (core
   specification §6): Standard accepts X25519MLKEM768; High and Sovereign
   accept X25519MLKEM1024; Sovereign MUST NOT accept X25519MLKEM768. These are
   checks of the public profile-invariants table, not of High/Sovereign
   internals.

### 3.2 Grading rule

For every corpus test case of the operations above: a `valid` case passes when
the implementation's output equals `expected`; an `invalid` case passes when
the implementation rejects the input (`invalid` cases carry no `expected`
value — they assert a MUST-reject). A Class W claim requires **zero Fail and
zero Unimplemented** across all eight operation groups; the harness's
`Unimplemented` verdict (§6.2) is admissible for a run but not for a Class W
claim, because every Class W operation is REQUIRED.

### 3.3 Delta from the core specification

The core specification (§7.2) permits a Standard-profile endpoint to support
**at least one** of AES-256-GCM and ChaCha20-Poly1305. The corpus's AEAD
vectors are exclusively AES-256-GCM (§7), so Class W as gradable today
requires AES-256-GCM. An implementation that supports only ChaCha20-Poly1305
may be core-conformant yet cannot currently be graded by this corpus; this is
recorded as a coverage gap (§8.3), not as non-conformance.

## 4. Class H — handshake conformance (Standard profile)

### 4.1 Normative source and profile scope

Class H is defined against the handshake binding
(`../10_handshake_binding.md`), which fixes the 1.5-RTT handshake wire bytes
for draft-00 and is targeted for ratification into draft-01. All five KATs
exercise the **Standard** parameter row (SHA-256, HashLen 32, Ed25519,
X25519MLKEM768); no public KAT exists for any other row (§8.4). The published
draft-00 conformance corpus itself carries **no handshake-layer vectors**
(handshake binding §8); Class H is graded by the standalone KAT files below.

### 4.2 The five handshake KATs

All five are standards-derived and non-circular: no expected value was
produced by an N-PAMP implementation. Each carries its own `provenance` and
`coverage` statement, which is authoritative for that file.

| KAT file (`../../test-vectors/v1/`) | Binding clause | External anchors | Pins |
|---|---|---|---|
| `transcript-kat.json` | §3 | FIPS 180-4 (SHA-256 "abc") | Per-TLV transcript construction (2-octet frame type + `Type‖Length‖Value`), all five transcript points TH_kem / TH_sId / TH_sCV / TH_cId / TH_cCV |
| `key-schedule-kat.json` | §5 | RFC 8448 §3, RFC 5869 A.1 TC1 | HKDF-Expand-Label mechanism with the `"n-pamp "` prefix; the handshake_secret ladder (`c hs` / `s hs` / `master`), traffic key/iv, finished_key derivation; ML-KEM-first IKM order |
| `finished-kat.json` | §6.2 | RFC 4231 §4.2/§4.3 TC1/TC2 | verify_data = HMAC-SHA-256(finished_key, transcript_hash) for both roles, over TH_sCV / TH_cCV |
| `certverify-kat.json` | §6.1 | RFC 8032 §7.1 TEST 1/TEST 2 | CertVerify value = u16(0x0807) ‖ Ed25519 signature over `0x20×64 ‖ context ‖ 0x00 ‖ transcript_hash`, role-separated context strings, over TH_sId / TH_cId |
| `kem-wire-kat.json` | §4 | NIST ACVP (FIPS 203 final), RFC 7748 §6.1 | ML-KEM-first wire order of KEMShare (1216 octets) and KEMCiphertext (1120 octets); combined secret = ML-KEM_SS ‖ X25519_SS as raw HKDF-Extract IKM |

### 4.3 Requirements

An implementation claiming Class H MUST:

1. **Run each KAT with the three-leg discipline** the KAT files and the gate
   define (`../../impl/_conformance-harness/README.md`): an **anchor** leg that
   first reproduces the published RFC/FIPS values carried in the file (so the
   test's own primitives are proven before its expectations are trusted), an
   **oracle** leg that reconstructs the expected values independently of the
   implementation under test, and an **impl** leg that checks the
   implementation against them. A KAT run that omits the anchor leg has not
   run that KAT.
2. **Reproduce every expected value** in `transcript-kat.json`,
   `key-schedule-kat.json`, `finished-kat.json`, and `certverify-kat.json`,
   byte for byte.
3. **Exercise the negative checks**, not only the positive ones: Finished
   verification MUST accept the correct `verify_data` and reject a corrupted
   one, in constant time (binding §6.2); CertVerify verification MUST accept
   the correct value and MUST reject both a role/context mismatch and a
   wrong-transcript input (binding §6.1).
4. **Satisfy the KEM-wire assertions** of `kem-wire-kat.json`: ML-KEM-768
   encapsulation-key derivation from the NIST seed, the RFC 7748 X25519 vector,
   and the ML-KEM-first assembly of KEMShare, KEMCiphertext, and the combined
   secret. The NIST decapsulation anchor (`mlkem768_decaps_reference`) requires
   importing an expanded decapsulation key; an implementation whose ML-KEM API
   accepts only a 64-octet seed MUST record that leg as not-executable with
   that reason (as the KAT's own `coverage` section does) — it MUST NOT be
   silently skipped and MUST NOT be reported as passed.
5. **Verify vector integrity before trusting a vector**: each consuming test
   SHOULD pin the SHA-256 of the KAT file it reads and fail loudly on a swapped
   vector, as the reference gate does; at minimum the claimant MUST verify the
   files against `../../MANIFEST.sha256` (via `../../scripts/verify-pins.ps1`)
   before the run.

### 4.4 Reference gate

`../../impl/_conformance-harness/kat-handshake-all-langs.sh` is the reference
Class H gate for the in-tree reference implementations. Its accounting
convention is normative for claims that cite it: a language is PASS only on
exit 0 **and** its positive pass token; an absent toolchain is a tracked SKIP;
an ALL-PASS banner counts only what actually ran. A Class H claim that cites a
gate run MUST reproduce this ran/skipped accounting rather than reporting a
bare pass.

## 5. Class B — bridge and companion conformance

### 5.1 Requirements

Class B conformance is defined **per companion document** by that document's
own numbered §Conformance clause. A Class B claim MUST:

1. Enumerate exactly which companion documents are claimed (for example:
   NPAMP-BRIDGE + NPAMP-CC-JSONRPC + `60_map_mcp.md`);
2. Satisfy NPAMP-BRIDGE §9 whenever any carriage class or mapping is claimed —
   every carriage class inherits the bridge contract
   (`00_companion_index.md`, "Conformance posture");
3. Satisfy the §Conformance clause of each claimed carriage class and mapping
   in full — partial satisfaction of a clause is non-conformance to that
   document, not partial conformance; and
4. Rest on a core-conformant wire implementation (Class W), since bridge
   frames are ordinary N-PAMP frames on channel 0x000D.

### 5.2 Verification status — honest statement

**No machine-gradable bridge vectors exist today.** The corpus schema reserves
the operations `bridge.envelope.encode`, `bridge.envelope.decode`, and
`bridge.correlate` (`../../test-vectors/schemas/conformance-corpus.schema.json`),
but the corpus carries zero test cases for them (§7). The recorded-exchange
suites that companion documents describe (for example NPAMP-CC-JSONRPC §10's
four-exchange suite) are SHOULD-level test guidance, not a published corpus.

A Class B claim is therefore a **specification-audit claim**: the claimant
attests, clause by clause, that its implementation satisfies each numbered
conformance item of each claimed document. A Class B claim MUST be labeled
"specification-audited" and MUST NOT be represented as corpus-verified.
Populating the reserved bridge operations with vectors is tracked corpus
growth (§8.2).

## 6. The conformance oracle set

### 6.1 The corpus and its pins

The canonical corpus is `../../test-vectors/v1/conformance-corpus.json` —
`algorithm` "npamp_00", `schemaVersion` "1.0.0", `specRevision`
"draft-bubblefish-npamp-01", 255 test cases in 8 test groups. Its SHA-256
(`807a2d8cd8064734f4d53cb5d2c01d0b3635d354440b697b30c3bd300f1a073e`) is pinned
in `../../PIN.json` and `../../MANIFEST.sha256`; `../../scripts/verify-pins.ps1`
recomputes and compares every pinned hash and exits non-zero on drift. The
grading runner embeds a byte-identical copy
(`../../harness/runner/corpus/conformance-corpus.json`). Every vector file has
a draft-2020-12 JSON Schema in `../../test-vectors/schemas/`;
`../../scripts/validate-schemas.py` validates each vector structurally,
complementing the byte pin.

The corpus is non-circular by construction: wire cases derive from the
specification's golden vectors, cryptographic cases from the Project
Wycheproof corpora, and the CRC cases from the published Castagnoli
polynomial — none from the implementation being graded
(`../../test-vectors/README.md`).

Each test case carries: `tcId`, a `requirement` string naming the spec clause
it checks (printed on failure), an `in` object, a `result` of `valid` /
`invalid` / `acceptable`, `expected` (present exactly when `result` is
`valid`), and optional `flags`. The current corpus contains no `acceptable`
cases; every case is a MUST.

### 6.2 The grading harness

`npamp-conform` (`../../harness/CONFORMANCE-README.md`,
`../../harness/INSTRUCTIONS.md`) is the reference grader. Two usage tiers:

- **Tier A — vectors only.** `npamp-conform vectors` emits the corpus; the
  claimant's own harness applies the grading rule of §3.2.
- **Tier B — black-box adapter.** The claimant writes an adapter speaking
  length-prefixed JSON over stdin/stdout; the runner drives it and owns all
  grading. Reference adapters in multiple languages exist under
  `../../harness/adapters/`; the harness instructions document the Go and
  Python adapters as known-good references run against this corpus.

Verdict taxonomy (normative for claims that cite a run): **Pass** (output
matched `expected`, or a MUST-reject was correctly rejected), **Fail** (wrong
output, missing rejection, or adapter error/crash — fails the run),
**Unimplemented** (the adapter returned `skipped`; does not fail the run, but
see §3.2 for what a Class W claim admits), **Non-Strict** (SHOULD-level
deviation, graded only under a future strict mode). The runner exits non-zero
if and only if at least one Fail occurred.

### 6.3 The handshake KAT set

The five KAT files of §4.2, plus the reference gate of §4.4. These are
in-tree, SHA-256-pinned via `../../MANIFEST.sha256`, and consumed by the
handshake gate — they are not part of the `npamp-conform` corpus and are not
exercised by a Tier A/Tier B run (§8.1).

## 7. Corpus coverage — what is verified

The composition below is stated from the corpus file itself (all groups carry
`profile: "any"`):

| Operation | Cases | Valid | Invalid | The MUST-reject cases assert |
|---|---|---|---|---|
| `header.decode` | 5 | 1 | 4 | Reserved octet non-zero; CRC32C mismatch; bad frame magic; unsupported wire version |
| `header.encode` | 1 | 1 | 0 | — |
| `crc32c` | 1 | 1 | 0 | — |
| `tlv.decode` | 2 | 1 | 1 | Unknown TLV type with high bit 0x8000 set |
| `aead.seal` | 39 | 39 | 0 | — (AES-256-GCM, Wycheproof-derived) |
| `aead.open` | 40 | 39 | 1 | Tampered GCM authentication tag |
| `hkdf.expand` | 163 | 163 | 0 | — (83 SHA-256, 80 SHA-384, Wycheproof-derived) |
| `profile.check` | 4 | 3 | 1 | Sovereign MUST NOT accept X25519MLKEM768 |
| **Total** | **255** | **248** | **7** | |

Seven of the 255 cases are negative (MUST-reject) cases. They cover six
distinct rejection rules of the core specification: reserved-octet-non-zero,
CRC mismatch, bad frame magic, unsupported wire version, forward-incompatible
TLV, AEAD tag mismatch — plus the Sovereign KEM-refusal invariant.

## 8. Coverage gaps — what the current corpus does NOT cover

This section is normative in one respect: a conformance claim MUST NOT assert
verification of anything listed here on the basis of the current corpus.

### 8.1 Operations reserved but unpopulated

The corpus schema enumerates 17 operations; the corpus populates 8. The
following 9 carry **zero vectors** today:

- `tlv.encode` (TLV serialization is exercised only indirectly, via decode);
- `nonce.derive` (the per-frame nonce = IV XOR left-padded sequence number,
  core specification §7.5);
- `hkdf.expand_label` (the `"n-pamp "`-prefixed HKDF-Expand-Label — covered by
  the key-schedule KAT (§4.2) but not by any corpus vector, so a Tier A/B run
  never grades it);
- `keys.derive_traffic` (the per-(direction, epoch, suite, channel) traffic
  derivation, core specification §7.5 — same status: KAT-covered, corpus-absent);
- `frame.seal` / `frame.open` (whole-frame protection: header-prefix AAD
  construction plus AEAD, end to end);
- `bridge.envelope.encode` / `bridge.envelope.decode` / `bridge.correlate`
  (the NPAMP-BRIDGE surface; see §5.2).

### 8.2 Handshake and bridge layers absent from the corpus proper

A clean `npamp-conform` run demonstrates Class W only. The handshake layer is
graded exclusively by the separate KAT set (§4; handshake binding §8), and the
bridge/companion layer has no oracle at all (§5.2). Neither is touched by a
Tier A or Tier B run.

### 8.3 Algorithm coverage limits

- **ChaCha20-Poly1305 (AEAD code point 0x0002):** zero vectors; all 79 AEAD
  cases are AES-256-GCM (§3.3).
- **Signature primitives:** the corpus has no signature operation at all.
  Ed25519 is anchored only inside the CertVerify KAT (Class H). ML-DSA-87
  (code point 0x0905, a public code point of core specification §7.3) has no
  public vector in this set.
- **KEM primitives:** the corpus has no KEM operation. ML-KEM-768 keygen and
  X25519 are anchored only inside the KEM-wire KAT (Class H), with the
  documented ML-KEM decapsulation-anchor limitation (§4.3 item 4). No public
  vector exercises X25519MLKEM1024.

### 8.4 Profile coverage limits

Every KAT in the `test-vectors/v1` corpus is Standard-profile (SHA-256, HashLen
32, Ed25519, X25519MLKEM768); each corpus KAT's own `not_covered_here` list says
so explicitly. The corpus touches the High and Sovereign profiles only at the
public KEM-acceptance invariants (`profile.check`, 4 cases). Separately, the
cross-language reference-implementation vectors (`impl/*/*-vectors`) pin one
SHA-384 key-schedule value (`traffic_key_sha384`) that exercises the High/Sovereign
KDF row (SHA-384) but no High-only PQ primitive (ML-KEM-1024, ML-DSA-87). Beyond
that KDF-row value and the KEM-acceptance table, nothing in this public set
verifies High- or Sovereign-profile operation — including per-frame AEAD
diversification and downgrade-refusal behavior — and no class defined here may
be claimed for those profiles.

### 8.5 Runtime behaviors not verifiable by static vectors

The core specification imposes runtime MUSTs that no known-answer vector can
exercise. They are REQUIRED for a conforming endpoint but UNVERIFIED by this
oracle set; a claim MUST carry them as self-attested (§9):

- replay-window enforcement per (channel, direction), and the 0-RTT
  restrictions (core specification §10.4);
- Key updates within profile bounds, and zeroization of prior-epoch secrets
  (§10.5);
- Path validation via PATH_CHALLENGE / PATH_RESPONSE before accepting an
  address change (§10.6);
- Authenticated CLOSE: AEAD verification before honoring a close, forged
  CLOSE dropped (§4.7, §10.7);
- Dropping frames on channels the peer did not advertise (§5), ignoring GREASE
  channel IDs 0xF000-0xFFFE, and never emitting channel 0xFFFF (§8.3);
- Cryptographically secure randomness for every security-relevant field
  (§7.6), and constant-time comparison of authentication values (§10.3);
- transcript-bound downgrade protection observed end-to-end in a live
  handshake (§10.2) — the KATs pin the derivations, not the abort behavior.

### 8.6 Corpus-depth limits within covered operations

Coverage inside the populated groups is uneven and a claim inherits that
unevenness: `header.encode`, `crc32c`, and `tlv.decode` rest on one golden
vector each per positive rule (single-vector groups), while the AEAD and HKDF
groups carry the full Wycheproof-derived breadth. The negative surface is five
cases (§7); many MUST-reject rules of the core specification (for example:
Frame type 0x0000, malformed TLV lengths, truncated headers) have no negative
vector yet.

## 9. Conformance claims

### 9.1 Required content

A conformance claim for any class MUST state, at minimum:

1. The class or classes claimed (W; H; B with the enumerated document list),
   and for every class the profile scope, which for this oracle set is
   **Standard** (§8.4);
2. The spec revision claimed against (draft-bubblefish-npamp-01) and, for
   Class H, the handshake-binding document as its normative source;
3. The corpus `schemaVersion` and the SHA-256 of the corpus consumed, matching
   `../../PIN.json` (and, for Class H, a pin verification of the KAT files,
   §4.3 item 5);
4. The evidence path — Tier A or Tier B `npamp-conform` run for Class W, the
   KAT gate or an equivalent three-leg run for Class H, the clause-by-clause
   audit for Class B — with the verdict tallies (Pass / Fail / Unimplemented /
   Non-Strict) and ran/skipped accounting where a gate is cited (§4.4);
5. Every operation reported Unimplemented, by name; and
6. The self-attested items of §8.5, listed as self-attested.

### 9.2 Prohibited claims

A claimant MUST NOT:

1. Claim "N-PAMP conformant" unqualified — a claim names its class(es), its
   profile scope, and its corpus/KAT pins, or it is not a claim under this
   document;
2. Claim any class for the High or Sovereign profile on the basis of this
   public oracle set (§8.4);
3. Represent a Class B claim as machine-verified (§5.2);
4. Represent a Class W pass as covering the handshake or bridge layers (§8.2),
   or represent KAT-covered derivations (`hkdf.expand_label`,
   `keys.derive_traffic`) as corpus-covered (§8.1);
5. Report a skipped or not-executable leg as passed — including the KEM-wire
   decapsulation anchor (§4.3 item 4) and any gate SKIP (§4.4); or
6. Claim conformance from an interop session alone (§1.2).

### 9.3 Claim persistence

A claim SHOULD be reproducible: the RECOMMENDED form is a machine-readable
report (for example the runner's JUnit output) stored alongside the corpus
hash and tool versions used, such that a third party can re-run the same
evidence path against the same pinned bytes and obtain the same verdicts.

## 10. Conformance

An implementation conforms to NPAMP-CONFORM if and only if every conformance
claim it publishes for N-PAMP draft-01:

1. Names one or more of the classes defined here and satisfies that class's
   requirements in full — §3.1-§3.2 for Class W, §4.3 for Class H, §5.1 for
   Class B;
2. Carries the required claim content of §9.1, including verbatim verdict
   tallies and the named Unimplemented operations;
3. Asserts nothing prohibited by §9.2, and in particular asserts no coverage
   that §8 states this oracle set does not provide; and
4. Was produced against pin-verified vector bytes (§6.1, §4.3 item 5).

A future revision of the corpus that populates the reserved operations of
§8.1, adds ChaCha20-Poly1305 vectors, adds handshake vectors to the corpus
proper, or widens the negative surface (§8.6) supersedes the coverage
statements of §7-§8 for claims made against that revision; claims MUST cite
the corpus hash they were graded against so that coverage statements resolve
unambiguously.
