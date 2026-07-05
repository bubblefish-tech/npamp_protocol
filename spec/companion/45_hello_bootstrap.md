# NPAMP-HELLO — Capability Bootstrap (companion to draft-bubblefish-npamp-01)

> Status: **DRAFT companion specification.** The key words MUST, MUST NOT, REQUIRED, SHALL,
> SHALL NOT, SHOULD, SHOULD NOT, RECOMMENDED, MAY, and OPTIONAL are to be interpreted as described
> in BCP 14 (RFC 2119, RFC 8174) when, and only when, they appear in all capitals. This document
> defines the post-handshake capability exchange on the N-PAMP **Control channel `0x0000`**: how
> two peers learn which protocols and channels each carries, immediately after the handshake, with
> no directory and no third-party lookup. It consumes only code points the core specification
> reserves and introduces no change to the core wire format.

## 1. Scope

### 1.1 In scope
1. A Control-channel HELLO exchange in which each peer advertises, as an ordered name-list, the
   foreign-protocol identifiers (NPAMP-REG `protocol_id`) and core channels it carries.
2. A deterministic selection rule (the set both peers can speak).
3. Forward-compatibility (ignore-unknown plus GREASE).
4. Downgrade protection.

### 1.2 Not in scope
This document does NOT: enumerate the methods, operations, or schemas of any carried protocol
(those are obtained after selection, through the carried protocol itself); define any directory,
registry, publish, or query operation; fetch any capability data from a third party; or persist a
peer's advertisement beyond the live association. It is a **selector, not a directory** (§8).

## 2. Relationship to the core specification

HELLO rides the Control channel `0x0000`, which the core specification registers for "Connection
control, handshake completion, capability epoch". A peer MUST send HELLO only AFTER the handshake
completes and the Finished MAC verifies. Every HELLO frame is therefore AEAD-protected under the
established per-(direction, epoch, suite, channel) keys and is mutually authenticated by the
handshake. A network attacker cannot insert, strip, reorder, or alter a HELLO frame without
invalidating the frame's AEAD tag.

## 3. Frame types

Within the Control channel `0x0000` channel-specific frame-type namespace (types begin at `0x0100`;
core specification §4.6):

| Type | Name | Reply | Meaning |
|---|---|---|---|
| 0x0110 | HELLO | (the peer's own HELLO) | Advertises the sender's carried protocols and channels and its NPAMP-HELLO version. Each peer sends exactly one HELLO as its first Control-channel application frame. |
| 0x0111 | HELLO_DONE | None | Marks the sender's capability epoch complete. After sending HELLO_DONE a peer MUST NOT advertise additional protocols on this association without a new handshake. |

The reserved all-channel frame types (PING, CLOSE, ERROR, KEY_UPDATE, and the remainder; core
specification §4.6) retain their core meaning on the Control channel.

## 4. Frame payload

A HELLO payload is a single **deterministically encoded CBOR** map (core specification, deterministic
CBOR, RFC 8949). Integer keys:

| Field (key) | CBOR type | Meaning |
|---|---|---|
| `version` (0) | Unsigned int | The sender's highest supported NPAMP-HELLO version. |
| `protocols` (1) | Array of unsigned int | Ordered, most-preferred first. Each entry is a Bridge Protocol Identifier (NPAMP-REG) the sender carries, or a core channel ID it offers. |
| `params` (2) | Map | OPTIONAL bootstrap constants that MUST be known before first use (for example a maximum frame size). A receiver MUST ignore an unknown key. |
| `grease` (3) | Array of unsigned int | OPTIONAL reserved values with no meaning; a receiver MUST ignore them. A sender SHOULD include at least one. |

A receiver MUST ignore an unrecognized non-negative integer key in a HELLO payload, so later
revisions MAY add fields without breaking a conformant receiver. A receiver MUST reject (CLOSE) a
payload carrying a negative integer key it does not recognize, reserving the negative key space for
forward-incompatible additions. HELLO carries identifiers only; it MUST NOT carry per-protocol
descriptors, schemas, human-readable metadata, or endpoint locators (§8).

## 5. Selection

The set of protocols usable on the association is the intersection of the two peers' `protocols`
lists. Where ordering matters, the order is the **initiating peer's** preference order: the selected
entry is the first in the initiator's list that also appears in the responder's list. A peer MUST
NOT emit carried-protocol traffic for a `protocol_id` that is not in the selected set; a receiver
MUST reject such traffic per NPAMP-BRIDGE (`ProtocolUnsupported`).

## 6. Version negotiation

A peer proposes its highest `version`. If the peer supports that version it MUST echo it; otherwise
it MUST return the highest version it supports. If the peers cannot agree on a common version, a
peer MUST close the association (CLOSE). A peer MUST operate only at a version both peers support.

## 7. Downgrade protection

Because HELLO frames are AEAD-protected and the handshake mutually authenticates both peer
identities (core specification Finished MAC over the transcript), a man-in-the-middle cannot strip
or alter a HELLO without detection. For defense in depth against a peer that advertises one set in
the handshake and a different set after it, a peer SHOULD commit a digest of its offered `protocols`
into the handshake transcript and, on receiving the other peer's HELLO, verify the HELLO against the
committed digest; a mismatch MUST abort the association.

## 8. The directory line (normative non-scope)

This document defines a SELECTOR. An implementation MUST NOT, under this document:
1. Carry per-protocol descriptors, schemas, examples, input/output modes, or human metadata in HELLO;
2. Carry an endpoint URL, origin, or any locator a peer would dereference out of band;
3. Expose a publish operation (registering capabilities anywhere) or a query operation (looking up
   capabilities by criteria);
4. Persist a peer's HELLO so as to answer "what does peer X carry?" outside the live association.

Test: if a component can answer "what does peer X carry?" without X being the other end of the
current live association, it is a directory, and a directory is out of scope for this document.

## 9. Conformance

An implementation conforms to NPAMP-HELLO if and only if, on the Control channel `0x0000`, it:
1. Sends exactly one HELLO as its first Control-channel application frame, only after the Finished
   MAC verifies, AEAD-protected (§2, §3);
2. Encodes the HELLO payload as deterministic CBOR, ignoring unknown non-negative keys and rejecting
   unknown negative keys (§4);
3. Computes the usable protocol set as the intersection in the initiator's preference order, and
   refuses carried traffic outside that set (§5);
4. Negotiates `version` per §6 and operates only at a commonly supported version;
5. Provides downgrade protection per §7;
6. Carries identifiers only and implements none of the directory behaviors prohibited in §8;
7. Emits and ignores GREASE values to keep the ignore-unknown path exercised (§4).

A conformance test suite SHOULD assert each clause with a recorded HELLO exchange, including an
unknown-key payload (ignored), a GREASE entry (ignored), a non-overlapping protocol set (empty
selection), a version mismatch (CLOSE), and a stripped-HELLO attempt (rejected by AEAD/commitment).
