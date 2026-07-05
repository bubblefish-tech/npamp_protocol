# NPAMP-CC-DOC — Carriage of Capability and Schema Documents (companion to draft-bubblefish-npamp-01)

> Status: **DRAFT companion specification.** The key words MUST, MUST NOT, REQUIRED,
> SHALL, SHALL NOT, SHOULD, SHOULD NOT, RECOMMENDED, MAY, and OPTIONAL in this document
> are to be interpreted as described in BCP 14 (RFC 2119, RFC 8174) when, and only when,
> they appear in all capitals, as shown here. This document defines a **carriage class**
> for capability and schema documents — agent cards, tool catalogs, schemas, and other
> self-describing advertisement documents — and their detached proofs, over N-PAMP. It
> builds on **NPAMP-BRIDGE** and consumes only code points the core specification
> reserves; it introduces no change to the core wire format and redefines nothing in
> NPAMP-BRIDGE.

## 1. Scope

A capability or schema document is a self-contained artifact that one agent publishes so
that another agent can discover, verify, and consume it without a prior bespoke exchange.
Examples in the families this class serves are agent capability cards, tool and function
catalogs, and machine-readable schemas. Such a document is frequently accompanied by one
or more **detached proofs** — a detached signature, a key-binding object, a transparency
receipt, or a content digest — that an independent verifier checks against the document's
exact octets.

This document specifies how to carry such a document **and** its detached proofs over
N-PAMP as a single correlated unit, such that:

1. The document is delivered octet-for-octet, so that a digest or signature computed by
   the producer over the document's exact bytes verifies bit-identically at the consumer
   (§4, §5);

2. Each detached proof is bound to the exact document octets it covers, and to the digest
   algorithm and digest value it was computed over, so that a verifier can pair proof to
   document without guessing (§6);

3. The document and all of its proofs share one correlation, so a consumer assembles the
   complete advertised artifact from a multiplexed, concurrent frame stream (§7).

This class inherits the NPAMP-BRIDGE contract in full: transparent payload carriage,
the BridgeEnvelope TLV, correlation, the structured-error model, one-way notifications,
and streaming. NPAMP-CC-DOC adds only the document-binding metadata and the
digest-stability rules that detached-proof verification requires.

### 1.1 Relationship to the core specification and to NPAMP-BRIDGE

NPAMP-CC-DOC carriage rides the Bridge channel `0x000D` by default. Where a deployment
advertises documents as part of agent, tool, and service discovery, it MAY instead, or in
addition, carry NPAMP-CC-DOC frames on the Discovery channel `0x0010`, whose core-specified
purpose is "Agent, tool, and service discovery and capability advertisement." The two
channels share the NPAMP-BRIDGE frame-type namespace and the rules of this document
unchanged; §3 states the one constraint on channel choice. Selecting a channel does not
alter any rule in this document.

This document does not define, alter, or re-reserve any field of the core wire format. It
does not define new cryptographic primitives: signature and digest algorithms are named by
identifier and carried, not performed, by the carriage layer (§6.4).

### 1.2 Non-scope

This document does NOT:

* Define the internal grammar of any document format (agent-card schema, catalog schema,
  or any schema language); it carries documents of declared content types opaquely with
  respect to their internal structure;
* Define a signature, digest, or canonicalization algorithm; it carries identifiers for
  algorithms defined elsewhere and the proof objects those algorithms produce;
* Verify a proof on behalf of an endpoint; it delivers the document and proof with the
  integrity guarantees a verifier needs and assigns the verification act to the consumer
  (§6.5);
* Define runtime advertisement or lookup semantics (which peer offers which document);
  that is the subject of a separate discovery companion and is out of scope here;
* Canonicalize, normalize, transcode, or re-serialize a carried document or proof under
  any circumstance (§4 is the controlling prohibition).

## 2. Terminology

For the purposes of this document:

Document:
: A capability or schema artifact carried as the foreign message of an NPAMP-CC-DOC
  frame, delivered octet-for-octet.

Detached proof:
: An object — a detached signature, a key-binding statement, a transparency-log receipt,
  or a standalone content digest — computed over the exact octets of a specific document
  and carried as the foreign message of a separate, correlated NPAMP-CC-DOC frame.

Document set:
: One document together with zero or more detached proofs over it, sharing a single
  `correlation_id` and forming the unit a consumer assembles and verifies.

Producer:
: The peer that originates a document set.

Consumer:
: The peer that receives and assembles a document set and that performs proof
  verification.

Digest stability:
: The property that the octet sequence a producer hashed to compute a proof is the exact
  octet sequence a consumer recovers from the wire, so that the recomputed digest equals
  the digest the proof attests (§5).

## 3. Channel and carriage class

NPAMP-CC-DOC is a carriage class under NPAMP-BRIDGE. Its frames are NPAMP-BRIDGE frames on
the Bridge channel `0x000D` or, per §1.1, on the Discovery channel `0x0010`. Within an
exchange (one document set under one `correlation_id`), every frame MUST be carried on the
same channel; a document and its detached proofs MUST NOT be split across the Bridge and
Discovery channels. A consumer MUST treat frames bearing the same `correlation_id` on two
different channels as unrelated correlations and MUST NOT assemble them into one document
set.

All NPAMP-CC-DOC frames are NPAMP-BRIDGE frames; this document defines no new core
frame type and no new Bridge-channel frame type. The frame types used are those of
NPAMP-BRIDGE §2 (`BRIDGE_REQUEST 0x0100`, `BRIDGE_RESPONSE 0x0101`, `BRIDGE_ERROR 0x0102`,
`BRIDGE_NOTIFY 0x0103`, `BRIDGE_STREAM_DATA 0x0104`, `BRIDGE_STREAM_END 0x0105`), with the
usage constraints of §7.

## 4. The transparency rule for documents and proofs

NPAMP-BRIDGE §1 requires that a bridge carry the foreign message octet-for-octet and never
re-serialize, summarize, or substitute its own envelope for it. NPAMP-CC-DOC strengthens
that rule for this class, because detached-proof verification depends on it absolutely:

> **Octet preservation.** A document carried by NPAMP-CC-DOC is the foreign message of its
> frame and MUST be delivered byte-identical to the octets the producer signed or hashed.
> An implementation MUST NOT canonicalize, re-indent, re-encode, re-order, transcode,
> compress at the document layer, pretty-print, minify, normalize Unicode, alter line
> endings, strip or add a byte-order mark, or otherwise change a single octet of a carried
> document or a carried detached proof. The same prohibition applies to every intermediary
> on the path.

A receiver MUST recover the document octets and the proof octets exactly as the producer
emitted them. If any layer of an implementation cannot guarantee octet preservation for a
document set — for example because a transport stage would re-serialize a parsed object —
that implementation MUST NOT carry that document set as NPAMP-CC-DOC and MUST instead fail
with `DigestUnstable` (§8). Reporting an undelivered or altered document as delivered is
prohibited by NPAMP-BRIDGE §6 and remains prohibited here.

The N-PAMP `COMP` frame flag (core specification, frame flags) compresses the AEAD-sealed
payload on the wire and is reversed before the payload is parsed; it is transport
compression and does not alter the recovered document octets. Document-layer compression —
compression that changes the octets a verifier hashes — is the prohibited operation above.

## 5. Digest stability

Detached-proof verification requires that the consumer hash exactly the octets the producer
hashed. NPAMP-CC-DOC guarantees this by carrying the document as an opaque octet string and
forbidding every transformation of it (§4). The digest input is therefore the carried
document's octets, delimited solely by the N-PAMP Payload Length of the document frame (and,
for a fragmented document, by the reassembly rule of §7.4) — never by any framing this
class adds.

The following rules make digest stability verifiable:

1. A producer MUST compute each detached proof's digest over the exact octets it places on
   the wire as the document foreign message, after any document-format-internal
   canonicalization the document's own format defines and before N-PAMP carriage. Any
   canonicalization is the responsibility of the document format and its proof scheme and
   happens **outside** and **before** NPAMP-CC-DOC; the carriage layer treats the
   already-canonical octets as opaque.

2. A consumer MUST recompute the digest over the recovered document octets, using the
   digest algorithm named in the document-binding metadata (§6), and MUST compare it
   against the digest value named there before treating any detached proof as applicable
   to the document.

3. A consumer MUST reject a document set whose recomputed digest does not equal the
   asserted digest, with error `DigestMismatch` (§8), and MUST NOT present the document as
   verified.

4. The digest comparison MUST be constant-time, consistent with the core specification's
   requirement that equality comparisons of authentication values be constant-time.

## 6. Document-binding metadata

A document set carries, alongside the foreign-message octets and the NPAMP-BRIDGE
BridgeEnvelope, a **DocumentBinding** descriptor that names the document, states the
digest algorithm and digest value the proofs were computed over, identifies each detached
proof and the algorithm that produced it, and states how many proofs complete the set.
This metadata is carried *around* the foreign message, never inside it; the document and
proof octets are untouched (§4).

### 6.1 Placement

The DocumentBinding descriptor is carried as an extension TLV in the NPAMP-BRIDGE frame
payload, positioned after the BridgeEnvelope TLV (Type `0x0010`) and after the SafetyLabel
TLV (Type `0x0013`) when present, and before the foreign message, using the core
specification's extension-TLV encoding (Type `u16`, Length `u16`, Value). The TLV type for
DocumentBinding is **`0xTBD-DOCBIND`** (see the IANA/code-point note in §10 and the OPEN
QUESTION in §11): the core specification has not yet reserved a free companion TLV code
point of variable length for this class, so this document specifies the descriptor's layout
and defers the concrete tag to a core-specification reservation. An implementation MUST NOT
occupy a TLV tag that the core specification has not reserved for this use.

Every NPAMP-CC-DOC frame that carries a document part or a detached-proof part — that is,
every frame whose foreign message is document octets or proof octets, including each
`BRIDGE_STREAM_DATA` and `BRIDGE_STREAM_END` part of a streamed document or proof — MUST
carry a DocumentBinding TLV. A `BRIDGE_REQUEST` that only solicits a document set carries no
document or proof part and MUST NOT carry a DocumentBinding TLV (§7.1). A receiver MUST
reject (BRIDGE_ERROR, `BindingMalformed`, §8) any document or proof part whose
DocumentBinding TLV is absent, truncated, or internally inconsistent.

### 6.2 DocumentBinding value layout

Multi-octet integers are big-endian, consistent with the core wire format.

| Field | Size | Meaning |
|---|---|---|
| `part_kind` | u8 | `0x01` document; `0x02` detached proof. Other values reserved; a receiver MUST reject an unknown `part_kind` with `BindingMalformed`. |
| `doc_id_len` | u8 | Length of `doc_id` (1–255). MUST be non-zero. |
| `doc_id` | Var | Opaque document identifier, stable across all parts of one document set; ties proofs to their document independently of `correlation_id`. |
| `doc_content_type_len` | u8 | Length of `doc_content_type` (0–255). |
| `doc_content_type` | Var | UTF-8 media type of the document part (for example a schema or card media type). Present (non-zero length) when `part_kind = 0x01`; MAY be zero-length for a proof part. |
| `digest_alg` | u16 | Identifier of the digest algorithm over which proofs are computed (§6.4). |
| `digest_len` | u8 | Length of `digest` in octets (0–255); MUST match the output length of `digest_alg`. |
| `digest` | Var | The digest value of the document octets, as asserted by the producer (§5). |
| `proof_count` | u8 | Total number of detached-proof parts in this document set (0–255). Identical in every part of the set. |
| `proof_index` | u8 | For `part_kind = 0x02`, the 0-based index of this proof part among the `proof_count` proofs; MUST be `0x00` and ignored when `part_kind = 0x01`. |
| `proof_alg` | u16 | For `part_kind = 0x02`, the identifier of the proof/signature algorithm (§6.4); MUST be `0x0000` when `part_kind = 0x01`. |

A receiver MUST reject with `BindingMalformed` any descriptor in which: a length field
exceeds the remaining TLV value; `digest_len` disagrees with the output length of
`digest_alg`; `proof_index >= proof_count`; or `proof_count`, `doc_id`, `digest_alg`, or
`digest` differ between two parts that share a `correlation_id` and `doc_id`.

### 6.3 Binding a proof to its document

A consumer MUST consider a detached proof to apply to a document if and only if all of the
following hold:

1. The proof part and the document part share the same `correlation_id` (NPAMP-BRIDGE §5);
2. The proof part and the document part carry an identical `doc_id`;
3. The proof part and the document part carry an identical `digest_alg`, `digest_len`, and
   `digest`; and
4. The recomputed digest of the recovered document octets equals that `digest` (§5).

A proof that fails any of these MUST NOT be treated as a valid proof of the document, and
the consumer MUST report `ProofUnbound` (§8) for that proof. A consumer MUST NOT silently
discard an unbound proof and present the document as if it carried fewer proofs than the
producer asserted.

### 6.4 Algorithm identifiers

`digest_alg` and `proof_alg` are identifiers, not algorithm implementations. To avoid
defining a parallel cryptographic registry, an NPAMP-CC-DOC `proof_alg` value, where the
proof is a signature, SHOULD name a signature whose code point the core specification
already assigns (for example the core signature code points for Ed25519 and ML-DSA-87), so
that document-set proofs and N-PAMP identity proofs draw from one set of algorithm
identifiers. A `proof_alg` value that names a proof scheme not expressible as a core
signature code point (for example a transparency-log receipt or a key-binding object) is
permitted; such values, and all `digest_alg` values, are assigned by the protocol registry
companion and are out of scope here. A consumer that does not recognize a `digest_alg` MUST
reject the set with `BindingMalformed`; a consumer that does not recognize a `proof_alg`
MUST report `ProofUnsupported` (§8) for that proof and MUST NOT treat the document as having
no proofs if other, recognized proofs are absent.

### 6.5 Verification is the consumer's act

NPAMP-CC-DOC delivers a document and its proofs with octet preservation (§4) and digest
stability (§5) so that verification is possible; it does not itself decide trust. A consumer
MUST perform digest recomputation (§5) and SHOULD perform proof verification appropriate to
each `proof_alg` before relying on a document. A producer MUST NOT represent the carriage
layer's delivery of a proof as a verification of that proof.

## 7. Carriage patterns

A document set is carried as one document part and zero or more detached-proof parts, all
sharing one `correlation_id`. NPAMP-CC-DOC reuses NPAMP-BRIDGE frame types unchanged; the
`message_kind` of the BridgeEnvelope MUST agree with the frame type as required by
NPAMP-BRIDGE §4.

### 7.1 Pull: a consumer requests a document

A consumer MAY request a document set with a `BRIDGE_REQUEST` (`0x0100`) whose `method`
names the requested document or document family (for example a card or catalog operation
name fixed by a mapping document). The producer replies with the document part and proof
parts as `BRIDGE_RESPONSE` (`0x0101`) frames, or with `BRIDGE_STREAM_DATA` / `BRIDGE_STREAM_END`
(§7.4) for a large document, all echoing the request's `correlation_id` (NPAMP-BRIDGE §5).
A `BRIDGE_REQUEST` in this class carries no document foreign message and no document part,
and therefore MUST NOT carry a DocumentBinding TLV; the document and proof parts that
constitute the reply each carry one (§6.1).

### 7.2 Push: a producer advertises a document unsolicited

A producer MAY advertise a document set without a prior consumer request. A pushed document
set that consists of a single document part with no detached proofs MAY be carried as one
`BRIDGE_NOTIFY` (`0x0103`) bearing the document part and `proof_count = 0`. A `BRIDGE_NOTIFY`
MUST set `corr_len = 0` (NPAMP-BRIDGE §5, §8); a single-frame pushed document therefore
carries no correlation, which is sufficient because it has no proof parts to group with.

A document set that has detached proofs, or a document large enough to require streaming,
needs a shared `correlation_id` so the consumer can group the document with its proofs, and
NPAMP-BRIDGE permits a non-empty `correlation_id` only on a `BRIDGE_REQUEST` and the replies
that echo it. A multi-part document set MUST therefore be carried under such a correlation.
Because the Bridge channel is bidirectional and either peer MAY originate a `BRIDGE_REQUEST`
(NPAMP-BRIDGE §5), a producer that wishes to push a multi-part set MAY originate the exchange
itself by emitting a `BRIDGE_REQUEST` that opens the correlation and then delivering the
document and proof parts as `BRIDGE_STREAM_DATA` (`0x0104`) frames terminated by
`BRIDGE_STREAM_END` (`0x0105`) under that one `correlation_id` (§7.4). A producer MUST NOT
attempt to associate multiple bare `corr_len = 0` notifications into one document set,
because such frames carry no correlation and cannot be grouped.

### 7.3 Ordering within a document set

The document part and its proof parts MAY arrive in any order, because the N-PAMP
per-channel sequence space orders frames but does not correlate them (NPAMP-BRIDGE §5). A
consumer MUST assemble a document set by `correlation_id` and `doc_id`, MUST NOT assume the
document part precedes its proofs, and MUST be able to receive a proof part before the
document part it covers. A consumer determines completeness by `proof_count`: the set is
complete when the document part and all `proof_count` distinct `proof_index` values have
been received.

### 7.4 Large documents and streaming

A document too large for one frame MUST be carried as an ordered sequence of
`BRIDGE_STREAM_DATA` (`0x0104`) frames terminated by `BRIDGE_STREAM_END` (`0x0105`) with the
BridgeEnvelope `final` flag set, all echoing one `correlation_id` (NPAMP-BRIDGE §5).
Reassembly concatenates the foreign-message octets of the stream parts in N-PAMP sequence
order to recover the document octets; the digest of §5 is computed over the concatenation,
not over any single frame. The DocumentBinding `digest` asserted on a streamed document is
the digest of the fully reassembled document octets. A detached proof MAY itself be streamed
by the same mechanism when it is too large for one frame. A consumer MUST NOT compute or
compare a document digest until `BRIDGE_STREAM_END` has been received and reassembly is
complete; a premature digest over a partial document MUST NOT be treated as a mismatch.

### 7.5 A document set is atomic to the consumer

A consumer MUST NOT present a document set as advertised until it is complete (§7.3) and the
document's digest has been recomputed and matched (§5). A consumer that times out or
otherwise abandons an incomplete set MUST discard the partial set and MUST NOT present the
document part alone as if it were a complete, proof-bearing advertisement.

## 8. Errors

NPAMP-CC-DOC reports failures using the NPAMP-BRIDGE structured-error model (NPAMP-BRIDGE
§6): a `BRIDGE_ERROR` (`0x0102`) frame echoing the `correlation_id` of the document set,
carrying the error below in place of a foreign message. These codes extend the NPAMP-BRIDGE
transport-error set for this class and do not collide with NPAMP-BRIDGE codes 1–5.

| Code | Name | Meaning |
|---|---|---|
| 16 | BindingMalformed | The DocumentBinding TLV is absent, truncated, internally inconsistent, names a `digest_alg` the receiver does not recognize, or disagrees with another part of the same set. |
| 17 | DigestMismatch | The recomputed digest of the recovered document octets does not equal the asserted `digest`. The document MUST NOT be presented as verified. |
| 18 | DigestUnstable | The implementation cannot guarantee octet preservation for this document set (§4) and refuses to carry it rather than deliver octets a verifier could not reproduce. |
| 19 | ProofUnbound | A detached proof does not bind to the document by the rules of §6.3. |
| 20 | ProofUnsupported | A `proof_alg` is not recognized by the receiver; the proof is uncheckable by this peer. |
| 21 | SetIncomplete | The document set could not be completed (a missing document part or a missing `proof_index`) within the consumer's bound. |

A receiver MUST NOT collapse distinct codes above into one, and MUST NOT report a document
as delivered or verified when any of `DigestMismatch`, `DigestUnstable`, `ProofUnbound`, or
`SetIncomplete` applies to it. Reporting success for an undelivered or unverifiable document
set is prohibited (NPAMP-BRIDGE §6).

## 9. Safety annotation

A document set is, by its nature, an advertisement: serving a document is `read_only` under
the NPAMP-BRIDGE SafetyLabel model (NPAMP-BRIDGE §7). A producer serving a document set in
response to a request SHOULD attach a SafetyLabel TLV (Type `0x0013`) with `effect =
read_only` to the document part. Where the act of requesting a document set is itself
state-mutating in a particular deployment (for example a request that causes the producer to
generate, register, or sign a fresh document), the requester MUST attach a SafetyLabel
describing that effect to the `BRIDGE_REQUEST`, and the fail-safe rule of NPAMP-BRIDGE §7
applies: absence of a SafetyLabel on a state-mutating request MUST be treated as
`destructive`, not as `read_only`. The SafetyLabel describes intent and does not replace
authorization, and it does not replace the document's own detached proofs, which carry the
document's authenticity independently of any transport-level annotation.

## 10. Code points consumed

NPAMP-CC-DOC consumes only code points the core specification reserves and the NPAMP-BRIDGE
frame types the bridge framework defines. It defines no new core frame type, no new
Bridge-channel frame type, and no change to the core wire format.

| Resource | Origin | Use in this document |
|---|---|---|
| Channel `0x000D` (Bridge) | Core specification — "encapsulation of external agent protocols" | Default channel for NPAMP-CC-DOC frames (§3). |
| Channel `0x0010` (Discovery) | Core specification — "agent, tool, and service discovery and capability advertisement" | Optional channel for advertisement carriage (§1.1, §3). |
| Bridge frame types `0x0100`–`0x0105` | NPAMP-BRIDGE §2 | Reused unchanged for document and proof carriage (§3, §7). |
| TLV `0x0010` (BridgeEnvelope) | Core specification — companion reservation; NPAMP-BRIDGE | Carried on every frame, unchanged (§6.1). |
| TLV `0x0013` (SafetyLabel) | Core specification — companion reservation; NPAMP-BRIDGE | Carried per §9, unchanged. |
| TLV `0xTBD-DOCBIND` (DocumentBinding) | **Pending a core-specification reservation** | The document-binding descriptor of §6. See §11. |

This document does not request the creation of any IANA-hosted registry. The DocumentBinding
descriptor requires one variable-length extension-TLV code point that the core specification
has not yet reserved for companion use; until that reservation exists, the descriptor's
layout is normative but its tag is unassigned (§11).

## 11. Open questions for the maintainer

The following items require a decision by the maintainer of the core specification before
this document can be finalized:

1. **DocumentBinding TLV code point (blocking).** The core specification's reserved
   companion TLV tags are `0x0010`, `0x0013`, and `0x0014`. NPAMP-BRIDGE consumes `0x0010`
   (BridgeEnvelope) and `0x0013` (SafetyLabel). The only remaining core-reserved companion
   TLV tag, `0x0014`, is specified by the core registry as a fixed 32-octet, handshake-only
   tag, which does not fit a variable-length, data-channel document-binding descriptor. This
   document therefore needs a **new variable-length companion TLV code point** to be reserved
   by the core specification (a natural choice is one additional tag in the companion-reserved
   region near `0x0010`–`0x0014`, or an explicit new reservation). Until the core specification
   reserves such a tag, `0xTBD-DOCBIND` in §6.1 is a placeholder and MUST NOT be assigned a
   concrete value by an implementation.

2. **Whether DocumentBinding belongs in a TLV or inside an extended BridgeEnvelope.** An
   alternative to a new TLV is to extend the NPAMP-BRIDGE BridgeEnvelope with optional
   trailing document-binding fields. That would avoid a new code point but would change
   NPAMP-BRIDGE, which this document is constrained not to do. The maintainer should confirm
   the preference for a separate TLV (this document's choice) over a BridgeEnvelope revision.

3. **Home registry for `digest_alg` and non-signature `proof_alg` identifiers.** Signature
   `proof_alg` values can draw on the core signature code points. Digest identifiers and
   non-signature proof identifiers (transparency receipts, key-binding objects) have no home
   in the core specification today; this document defers them to the protocol-registry
   companion (§6.4). The maintainer should confirm that registry as their home, or designate
   another.

## 12. Conformance

An implementation conforms to NPAMP-CC-DOC if and only if, for carriage of a capability or
schema document and its detached proofs on the Bridge channel `0x000D` or the Discovery
channel `0x0010`, it:

1. Conforms to NPAMP-BRIDGE for every frame it emits and parses in this class (§3);
2. Delivers each carried document and each carried detached proof octet-for-octet,
   performing no canonicalization, transcoding, re-serialization, or document-layer
   compression, and refuses with `DigestUnstable` any document set whose octet preservation
   it cannot guarantee (§4);
3. Computes and compares the document digest over the exact recovered document octets, using
   the asserted `digest_alg`, with a constant-time comparison, and rejects a mismatch with
   `DigestMismatch` without presenting the document as verified (§5);
4. Emits and parses a well-formed DocumentBinding descriptor on every document and proof
   part, and rejects an absent, truncated, or inconsistent descriptor with `BindingMalformed`
   (§6.1, §6.2);
5. Binds each detached proof to its document by `correlation_id`, `doc_id`, and digest
   triple, and reports an unbound proof as `ProofUnbound` rather than discarding it silently
   (§6.3);
6. Treats algorithm identifiers as carried, not performed, draws signature identifiers from
   the core signature code points where applicable, and reports an unrecognized `proof_alg`
   as `ProofUnsupported` (§6.4);
7. Assembles a document set by `correlation_id` and `doc_id` independent of frame order,
   reassembles a streamed document by N-PAMP sequence order before computing its digest, and
   presents a document set only when it is complete and its digest matches (§7);
8. Reports failures using the NPAMP-BRIDGE structured-error model with the codes of §8,
   never collapsing distinct codes and never reporting success for an undelivered or
   unverifiable document set; and
9. Applies the SafetyLabel fail-safe of NPAMP-BRIDGE §7 to any state-mutating document
   request (§9).

A conformance test suite SHOULD assert each clause above with recorded exchanges that
include: a single-frame document with no proofs; a document with one detached signature
proof; a document with multiple proofs of mixed `proof_alg`; a streamed multi-frame document
whose digest is computed over the reassembly; a proof part arriving before its document part;
a deliberately altered document octet that MUST produce `DigestMismatch`; and an unbound
proof that MUST produce `ProofUnbound`.
