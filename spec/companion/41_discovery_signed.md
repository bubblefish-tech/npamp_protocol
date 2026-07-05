# NPAMP-DISC-SIGNED — Signed and Offline Discovery (companion to draft-bubblefish-npamp-01)

> Status: **DRAFT companion specification.** The key words MUST, MUST NOT, REQUIRED, SHALL, SHALL
> NOT, SHOULD, SHOULD NOT, RECOMMENDED, MAY, and OPTIONAL are to be interpreted as described in
> BCP 14 (RFC 2119, RFC 8174) when, and only when, they appear in all capitals. This document
> extends **NPAMP-DISC** (`40_discovery.md`) to make a Discovery Record **self-authenticating at
> rest**: individually signed so its authenticity survives outside a live association and can be
> verified offline against a trust anchor the deployer configures. It consumes only code points the
> core specification reserves and introduces no change to the core wire format or to the NPAMP-DISC
> frame types.

## 1. Scope

### 1.1 In scope
1. A detached signature over a Discovery Record (NPAMP-DISC §5), producing a Signed Discovery Record.
2. A Discovery Document — a distributable bundle of Signed Discovery Records, verifiable with no live
   N-PAMP session.
3. Verification against a deployer-configured trust anchor.
4. A revocation/freshness mechanism.

### 1.2 Not in scope
This document does NOT: operate a registry or directory service; assign trust tiers or rank signers;
mint a global identity namespace; or define a default trust anchor. **Trust is a property of the
signed record verified against a deployer-chosen anchor — never membership in a vendor-run
directory.** The advisory rule of NPAMP-DISC §10 (an advertisement is a claim, not authorization)
continues to apply unchanged.

## 2. Signed Discovery Record

A Signed Discovery Record is a deterministically encoded CBOR map (core specification, RFC 8949):

| Field (key) | CBOR type | Required | Meaning |
|---|---|---|---|
| `record` (0) | Map | Yes | The Discovery Record exactly as defined by NPAMP-DISC §5. |
| `signer` (1) | Byte string | Yes | The signer's PeerHandle (NPAMP-PEERHANDLE). |
| `not_after` (2) | Unsigned int | Yes | Expiry, in seconds since the Unix epoch. A verifier MUST reject a record whose `not_after` is in the past. |
| `sig_suite` (3) | Unsigned int | Yes | The signature suite: `0x0905` ML-DSA-87, or `0x0807` Ed25519 (core specification signature registry). |
| `signature` (4) | Byte string | Yes | The detached signature (see §3). |

## 3. Signing

The signature is computed with the algorithm named by `sig_suite`, over the **deterministic-CBOR
byte encoding of the map containing fields `record` (0), `signer` (1), `not_after` (2), and
`sig_suite` (3)** — that is, the same map with field `signature` (4) removed. The signing key is the
key named by `signer` (its PeerHandle, per NPAMP-PEERHANDLE §2). This is a canonicalize-then-sign
construction; the deterministic CBOR encoding is the canonical form, so every signer and verifier
produces byte-identical signing input for identical content.

## 4. Verification (offline)

A verifier of a Signed Discovery Record MUST, in order:
1. Confirm `not_after` is in the future;
2. Recompute the signer's PeerHandle from the verifying key and confirm it equals `signer`
   (NPAMP-PEERHANDLE §4);
3. Confirm `signer` is in the verifier's configured trust anchor (§5);
4. Verify `signature` over the canonical encoding (§3) under the signer's key for `sig_suite`.

All four checks MUST pass; a record failing any check MUST be rejected. No live N-PAMP session is
required at any step — a Signed Discovery Record is verifiable from bytes alone.

## 5. Trust anchor

The trust anchor is the set of signer PeerHandles (or their keys) that the **deployer** configures as
trusted. This document defines no default anchor and operates no anchor service. An empty anchor set
means no Signed Discovery Record is trusted. A deployment MAY scope different anchor sets to
different peers or contexts.

## 6. Discovery Document

A Discovery Document is a deterministically encoded CBOR array of Signed Discovery Records, suitable
for out-of-band distribution (a file, an HTTP body, an object store, etc.). A consumer verifies each
contained record per §4 and ignores any that fail. A Discovery Document carries no endpoint, no query
interface, and no live pointer: it is data, not a service. Distributing a Discovery Document does not
make its publisher a directory operator, because the document is self-verifying and confers no
authority beyond the deployer's own trust anchor.

## 7. Revocation and freshness

Each record carries `not_after`. Short validity is RECOMMENDED (on the order of hours to a few days)
so a compromised or superseded record expires quickly; a signer extends validity by re-signing with a
later `not_after`. A deployment MAY additionally publish an online status interface; however, the
absence of a successful online check MUST NOT be treated as "revoked" while `not_after` is still in
the future, so that offline verification remains usable.

## 8. Signature-suite selection and denial-of-service

When a signer chooses `sig_suite` for records carried in a live association over NPAMP-DISC, it MUST
choose a suite permitted by the negotiated profile. A verifier exposed on an unauthenticated query
path MUST NOT be forced by an attacker to perform unbounded large-signature verifications: an
implementation SHOULD rate-limit verification and MAY bound the number and size of signatures it
will verify per peer. ML-DSA-87 signatures are 4627 octets; an implementation MUST account for that
size in its frame-size and resource budgets.

## 9. Conformance

An implementation conforms to NPAMP-DISC-SIGNED if and only if it:
1. Encodes a Signed Discovery Record exactly per §2 and signs the canonical input per §3;
2. Verifies a Signed Discovery Record by performing all four checks of §4 in order, rejecting on any
   failure, with no live session required;
3. Resolves trust against a deployer-configured anchor and never against a built-in or vendor-run
   directory (§5);
4. Treats a Discovery Document as self-verifying data and exposes no publish or query service over it
   (§6, and NPAMP-HELLO §8 directory line);
5. Enforces `not_after` freshness and does not treat a missing online check as revocation while
   `not_after` is valid (§7);
6. Bounds signature-verification work on unauthenticated paths (§8).

A conformance test suite SHOULD assert: a valid signed record (accepted); a tampered record body
(signature fails ⇒ rejected); an expired `not_after` (rejected); a signer not in the anchor
(rejected); a `signer` that does not recompute from the key (rejected); and offline verification of a
Discovery Document with no live association.
