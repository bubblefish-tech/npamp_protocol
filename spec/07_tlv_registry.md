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
| 0x0D | AEADSelect | Var (2*N) | Ordered list of the server-selected AEAD suites, primary first (2 octets per suite; N=1 at Standard, N=2 at High/Sovereign for per-frame diversification). Handshake only. |
| 0x10 | (reserved) | Var | Reserved for a companion specification. |
| 0x12 | OpaqueContentType | Var | Full IANA media-type string for opaque carriage, when the payload's media type is not one of the BridgeEnvelope content_type enumerated values (companion specification NPAMP-CC-OPAQUE). |
| 0x13 | (reserved) | Var | Reserved for a companion specification. |
| 0x14 | (reserved) | 32 | Reserved for a companion specification (handshake only). |
| 0x15 | (reserved) | -- | Reserved; path validation uses the PATH_CHALLENGE / PATH_RESPONSE frames (0x0008 / 0x0009), not a TLV. |
| 0x16 | (reserved) | -- | Reserved; see 0x15. |
| 0x17 | KeyUpdateMarker | 8 | Key-update epoch marker. |
| 0x18 | ProtectionMode | 1 | Reserved; no defined values (header protection provided by the secure transport). |
| 0x8000-0xFFFF | (reserved) | -- | Forward-incompatible extension points (Type high bit set). |

> **Note.** Tag `0x14` is reserved (length 32); the handshake tags `0x01`–`0x0D`
> are required by the handshake binding. All values above are normative in the
> draft's TLV Type Registry.
