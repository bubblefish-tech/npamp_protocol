# N-PAMP-01 — TLV Type Registry (reference)

> **Derived extract.** Authoritative source: `../ietf/draft-bubblefish-npamp-latest.md`
> (revision draft-bubblefish-npamp-01; integrity pinned in ../PIN.json), §9.4 "TLV Type Registry". The draft governs.
> Machine-readable: `../registries/tlv_tags.csv`.

Tags marked "(reserved)" are described in the Extension Points section.

| Tag | Name | Length | Description |
|---|---|---|---|
| 0x01 | ProfileOffer | Var | Profiles offered by the client, one octet per profile (handshake only). |
| 0x02 | ProfileSelect | 1 | Profile selected by the server (handshake only). |
| 0x03 | KEMOffer | Var | KEMs offered by the client. |
| 0x04 | KEMSelect | 2 | KEM selected by the server. |
| 0x05 | SigOffer | Var | Signature algorithms offered. |
| 0x06 | SigSelect | 2 | Signature algorithm selected. |
| 0x07 | KEMShare | Var | Public KEM share. |
| 0x08 | KEMCiphertext | Var | KEM encapsulation ciphertext. |
| 0x09 | IdentityKey | Var | Sender's identity public key (handshake AUTH). |
| 0x0A | CertVerify | Var | SignatureScheme (u16) + signature over the transcript (handshake AUTH). |
| 0x0B | Finished | Var | Finished MAC, length = negotiated KDF-hash output (handshake AUTH). |
| 0x0C | AEADOffer | Var | AEAD suites offered by the client (handshake only). |
| 0x0D | AEADSelect | 2 | AEAD suite selected by the server (handshake only). |
| 0x10 | (reserved) | Var | Reserved for a companion specification. |
| 0x12 | AnomalyCharge | 32 | Per-frame integrity charge. |
| 0x13 | (reserved) | Var | Reserved for a companion specification. |
| 0x14 | (reserved) | 32 | Reserved for a companion specification (handshake only). |
| 0x15 | PathChallenge | 32 | Path-migration challenge nonce. |
| 0x16 | PathResponse | 64 | Path-migration response. |
| 0x17 | KeyUpdateMarker | 8 | Key-update epoch marker. |
| 0x18 | ProtectionMode | 1 | Protection-mode selector. |
| 0x8000-0xFFFF | (reserved) | -- | Forward-incompatible extension points (Type high bit set). |

> **Note.** Tag `0x12` is AnomalyCharge (length 32); tag `0x14` is reserved
> (length 32); the handshake tags `0x01`–`0x0D` are required by the handshake
> binding. All values above are normative in the draft's TLV Type Registry.
