# NPAMP-PEERHANDLE — Self-Certifying Peer Identifier (companion to draft-bubblefish-npamp-01)

> Status: **DRAFT companion specification.** The key words MUST, MUST NOT, REQUIRED, SHALL, SHALL
> NOT, SHOULD, SHOULD NOT, RECOMMENDED, MAY, and OPTIONAL are to be interpreted as described in
> BCP 14 (RFC 2119, RFC 8174) when, and only when, they appear in all capitals. This document
> defines a connection-scoped, registry-free, self-certifying NAME for a peer, derived from the
> peer's existing N-PAMP signing key, so that "who am I talking to" is provable without a
> certificate authority or directory. It reuses existing standards — the multiformats
> multicodec/multibase encoding and the `did:peer` self-certifying pattern — and defines no new
> cryptography and no change to the core wire format.

## 1. Scope

### 1.1 In scope
Deriving a PeerHandle from a peer's public signing key; carrying the full key on the wire;
verifying a PeerHandle; and an OPTIONAL cross-signature by which a carried foreign identity asserts
control of the N-PAMP key.

### 1.2 Not in scope
This document does NOT define: trust tiers or any ranking of peers; a global identity root that
others must recognize; key rotation under a stable name; or any registry or directory. A PeerHandle
names the key that N-PAMP already authenticates in its handshake. It asserts "this is the key I am
encrypting to," NOT "I am the definitive agent identity."

## 2. Derivation

For an ML-DSA-87 (FIPS 204) signing key:

```
  multicodec_key = multicodec(0x1212, ml_dsa_87_public_key)
                   ; 0x1212 = "mldsa-87-pub" in the multiformats multicodec registry (draft)
  PeerHandle     = multibase(base32, multihash(0x12, SHA-256(multicodec_key)))
                   ; 0x12 = "sha2-256" in the multicodec registry
```

For an Ed25519 (RFC 8032) signing key, the multicodec code point `0xed` ("ed25519-pub") is used in
place of `0x1212`. The first byte of the multicodec-tagged value identifies the key algorithm, so a
single PeerHandle format covers Ed25519 or ML-DSA-87 (or a hybrid pair, named by two handles)
without ambiguity.

Because an ML-DSA-87 public key is 2592 octets, a PeerHandle is a HASH of the key, not the inlined
key (compare the libp2p rule that keys above 42 octets are hashed rather than inlined). A verifier
recomputes the handle from the received key (§4); the handle is therefore self-certifying.

## 3. Carrying the key

The full public key is carried as an RFC 7250 raw public key — a `SubjectPublicKeyInfo` (SPKI) —
using the IETF LAMPS `id-ml-dsa-87` algorithm identifier (draft-ietf-lamps-dilithium-certificates)
for ML-DSA-87, or the Ed25519 algorithm identifier (RFC 8410). The N-PAMP handshake already conveys
this signing key and proves possession of it (core specification: both peers sign the handshake
transcript and confirm with the Finished MAC). This document adds only the NAME derived from that
key; it introduces no new key-exchange or signing operation.

## 4. Verification

A verifier:
1. Obtains the peer's SPKI public key from the handshake;
2. Recomputes the PeerHandle from that key per §2;
3. Checks that the recomputed PeerHandle equals the PeerHandle the peer claims;
4. Relies on the core handshake's Finished MAC as the proof that the peer holds the corresponding
   private key.

A PeerHandle mismatch MUST abort the association. No certificate authority, directory, or third
party is consulted at any step.

## 5. Cross-signing (optional)

A carried foreign identity (for example an AGTP Agent-ID, or a W3C DID) MAY assert that it controls
the N-PAMP signing key by signing, with the foreign identity's own key, a statement:

```
  { "controls": <PeerHandle>, "foreign_id": <foreign identifier>, "not_after": <expiry> }
```

A verifier that already trusts the foreign identity thereby links it to the PeerHandle for the
stated validity period. This is a proof-of-possession assertion in the spirit of `did:peer` DID
Rotation; it requires no registry and is verified inline. Absence of a cross-signature MUST NOT be
treated as a failure; it simply means no foreign identity is linked.

## 6. Connection scope and rotation

A PeerHandle is valid for the association on which its key was authenticated. This document defines
no persistence of a PeerHandle as a lookup key and no namespace that other parties must recognize.
Because the name is a function of the key, rotating the key produces a NEW PeerHandle; a deployment
that needs continuity across a rotation MUST carry that continuity in a carried identity layer
(for example a foreign-identity cross-signature, §5), not in this document.

## 7. Conformance

An implementation conforms to NPAMP-PEERHANDLE if and only if it:
1. Derives a PeerHandle exactly per §2 (multicodec-tagged key, then a SHA-256 multihash, then
   multibase base32), using `0x1212` for ML-DSA-87 and `0xed` for Ed25519;
2. Carries the full public key as an RFC 7250 SPKI with the correct algorithm identifier (§3);
3. Verifies a claimed PeerHandle by recomputation and aborts on mismatch (§4);
4. If cross-signing is used, verifies the foreign signature and the `not_after` before linking the
   foreign identity (§5);
5. Treats the PeerHandle as connection-scoped, mints a new handle on key rotation, and operates no
   registry or trust ranking (§1.2, §6).

A conformance test suite SHOULD assert: a correct handle recomputed from a received ML-DSA-87 key; a
tampered key (handle mismatch ⇒ abort); an Ed25519 handle; a valid cross-signature (linked); and an
expired cross-signature (not linked).

## 8. Open item (maintainer)

The multicodec code point `0x1212` (`mldsa-87-pub`) is recorded as `draft` status in the multiformats
registry. If it changes before finalization, §2 MUST be updated to the final value. The ML-DSA-87
key (2592 octets) and signature (4627 octets) sizes MUST be checked against the N-PAMP transport's
maximum frame size and latency budget before this companion is promoted beyond DRAFT.
