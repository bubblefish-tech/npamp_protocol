# N-PAMP Code-Point Registries

**Every N-PAMP code point in one place.** This page renders the eight
machine-readable registry CSVs that live under `registries/` in the repository, so
a reader can browse the whole allocated code-point surface — channels, frame
types, TLV tags, profiles, cryptographic suites, and Bridge protocol identifiers —
without opening the CSVs by hand.

!!! note "Derived, machine-readable-backed extract"
    The authoritative machine-readable form of each registry is its CSV under
    `registries/` (validated against its JSON Schema in `registries/schemas/` by
    `scripts/validate-registries.py`). The authoritative *normative* form is the
    Internet-Draft `ietf/draft-bubblefish-npamp-latest.md`
    (revision **draft-bubblefish-npamp-01**; integrity pinned in `PIN.json`) and
    the companion specifications it references. **The CSVs and the draft govern;**
    this page is a rendered mirror of them. Each table below cites the exact CSV
    and the authoritative specification section.

## Registry catalogue

The N-PAMP core specification is published through the IETF **Independent
Submission** stream. Per the draft's IANA posture (core specification §8 /
`spec/09_extension_points.md`), the channel, frame-type, and TLV registries are
**defined and maintained within the specification itself** and extended by
companion specifications and future revisions — they do **not** create
IANA-hosted registries. The only IANA-registry actions the draft requests are the
**ALPN identifier** `n-pamp/2` (Expert Review) and the provisional **`npamp://`
URI scheme** (First Come First Served); both are written up in
`IANA_ALPN_n-pamp-2_registration_request.md`.

| Registry | Key column | Rows / ranges | Assignment governed by | Machine-readable | Authoritative section |
|---|---|---|---|---|---|
| Channels | `channel_id` (u16) | 20 assigned (0x0000–0x0013) + reserved | Core spec + future revisions | `registries/channels.csv` | [Channels](../spec/03_channels.md) |
| Frame types | `frame_type` (u16) | 14 assigned + reserved companion ranges | Core spec + companion specs | `registries/frame_types_reserved.csv` | [Frame types](../spec/04_frame_types.md) |
| TLV tags | `tag` (u16) | 20 assigned + reserved companion tags | Core spec + companion specs | `registries/tlv_tags.csv` | [TLV registry](../spec/07_tlv_registry.md) |
| Profiles | `profile` / `code` (u8) | 3 (Standard, High, Sovereign) | Core spec + future revisions | `registries/profiles.csv` | [Profiles](../spec/05_profiles.md) |
| KEM suites | `code_point` (u16) | 2 | Core spec + future revisions | `registries/kem.csv` | [Cryptographic suites](../spec/06_cryptographic_suites.md) |
| AEAD suites | `code_point` (u16) | 2 | Core spec + future revisions | `registries/aead.csv` | [Cryptographic suites](../spec/06_cryptographic_suites.md) |
| Signature schemes | `code_point` (u16) | 2 | Core spec + future revisions | `registries/signatures.csv` | [Cryptographic suites](../spec/06_cryptographic_suites.md) |
| Bridge protocol IDs | `protocol_id` (u8) | 4 assigned + reserved/experimental/private ranges | **Specification Required** (RFC 8126) | `registries/bridge_protocol_ids.csv` | [Bridge protocol registry](../spec/companion/30_protocol_registry.md) |
| Per-channel frame types | `(channel_id, frame_type)` (u16,u16) | 108 rows across 12 Standard-profile channels | Core spec §4.6 + companion specs | `registries/frame_types_channel.csv` | [Frame types §4.6](../spec/04_frame_types.md) |

The eight registries above are rendered in full as mirror tables below. The
ninth — the **per-channel frame-type registry** (`registries/frame_types_channel.csv`) —
expresses the §4.6 per-channel frame-type namespace, in which the same numeric
`frame_type` (e.g. `0x0100`) recurs on different channels; because that table is
large (108 rows) and impl-scoped, it is linked rather than mirrored inline, and is
gated by its own composite-key + Go-lockstep validator
(`scripts/validate-frame-types-channel.py`) rather than the docs drift-check.

To request a new code point, see the **[registration request
template](REGISTRATION-REQUEST.md)** and the [Registration & assignment
policies](#registration-assignment-policies) section at the foot of this page.

## Channel registry

Twenty multiplexed, full-duplex channels, each with an independent per-direction
sequence space and independent traffic keys. Channel IDs `0x0014`–`0xFFFF` are
reserved (see `spec/09_extension_points.md`): `0x0014`–`0x001F` future core,
`0x0020`–`0xEFFF` extension channels, `0xF000`–`0xFFFE` GREASE (receivers MUST
ignore), `0xFFFF` MUST NOT appear on the wire.

Machine-readable: `../registries/channels.csv` · Authoritative:
[core specification §Channels](../spec/03_channels.md).

| Channel ID | Name | Purpose | Min profile | Direction |
|---|---|---|---|---|
| 0x0000 | Control | Connection control, handshake completion, capability epoch | Standard | Bidirectional |
| 0x0001 | Memory | Persistent-state create/read/update/delete and retrieval | Standard | Multi-stream |
| 0x0002 | Capability | Capability issuance, delegation, revocation, lookup | Standard | Bidirectional |
| 0x0003 | Identity | Identity resolution, attestation, presence | Standard | Bidirectional |
| 0x0004 | Governance | Policy proposals, votes, quorum closure | High | Bidirectional |
| 0x0005 | Immune | Anomaly reports and defensive gossip | Standard | Bidirectional |
| 0x0006 | Federation | Cross-instance synchronization and gossip | High | Multi-stream |
| 0x0007 | Settlement | Agent-to-agent settlement and receipts | Standard | Bidirectional |
| 0x0008 | Compliance | Attestation and regulatory export | High | Bidirectional |
| 0x0009 | Sensory | Bulk telemetry and low-priority observations | High | Multi-stream |
| 0x000A | Telemetry | Operational metrics and health reporting | Standard | Bidirectional |
| 0x000B | Audit | Audit-epoch commitments and transparency-log entries | Sovereign | Bidirectional |
| 0x000C | Stream | Multiplexed full-duplex streaming (tokens, audio, video, file transfer) | Standard | Multi-stream |
| 0x000D | Bridge | Encapsulation of external agent protocols within N-PAMP frames | Standard | Bidirectional |
| 0x000E | Commerce | Multi-party agentic commerce and payment mandates | Standard | Bidirectional |
| 0x000F | Interaction | Agent-to-human user-interface events | Standard | Bidirectional |
| 0x0010 | Discovery | Agent, tool, and service discovery and capability advertisement | Standard | Bidirectional |
| 0x0011 | Workflow | Multi-agent orchestration and task delegation | Standard | Bidirectional |
| 0x0012 | Knowledge | Retrieval queries with ranked results and provenance | Standard | Multi-stream |
| 0x0013 | Spatial | Physical-world state for robotics and IoT (high-frequency) | High | Multi-stream |

## Frame-type registry

Frame types `0x0000`–`0x000A` are connection-level control frames. `0x0100`–`0x0103`
are the Control-channel (0x0000) handshake frames. Channel-specific frame types
begin at `0x0100` within each channel's own frame namespace. The reserved ranges
are held for the companion specifications named against each range.

Machine-readable: `../registries/frame_types_reserved.csv` · Authoritative:
[core specification §Frame types](../spec/04_frame_types.md) and
[§Extension points](../spec/09_extension_points.md).

| Frame type | Name | Description |
|---|---|---|
| 0x0000 | (reserved) | Reserved; MUST NOT be used as a frame type. |
| 0x0001 | PING | Liveness probe. |
| 0x0002 | PONG | Reply to PING. |
| 0x0003 | CLOSE | Authenticated close; AEAD-protected. |
| 0x0004 | CLOSE_ACK | Reply to CLOSE. |
| 0x0005 | ERROR | Error report; AEAD-protected. |
| 0x0006 | KEY_UPDATE | Initiate key update for this (channel, direction). |
| 0x0007 | KEY_UPDATE_ACK | Acknowledge key update. |
| 0x0008 | PATH_CHALLENGE | Path-migration challenge. |
| 0x0009 | PATH_RESPONSE | Path-migration response. |
| 0x000A | FLOW_UPDATE | Connection-level flow-control credit update. |
| 0x0030–0x0034 | (reserved) | Reserved for companion specifications: Stream-channel sub-stream lifecycle and flow-control extension frames. |
| 0x0035–0x0036 | (reserved) | Reserved for companion specifications: Memory-channel eviction and revive extension frames. |
| 0x0060–0x0063 | (reserved) | Reserved for companion specifications: Capability-channel token extension frames. |
| 0x0080–0x0080 | (reserved) | Reserved for companion specifications: Control-channel flow-extension frames. |
| 0x0090–0x0090 | (reserved) | Reserved for companion specifications: Audit-channel per-frame integrity-extension frames. |
| 0x00A0–0x00A3 | (reserved) | Reserved for companion specifications: Settlement/Audit batch-commitment extension frames. |
| 0x00B0–0x00B4 | (reserved) | Reserved for companion specifications: Governance-channel quorum extension frames. |
| 0x00C0–0x00C4 | (reserved) | Reserved for companion specifications: Immune-channel propagation extension frames. |
| 0x0100 | CLIENT_HELLO | Control channel (0x0000) handshake: client hello (cleartext). |
| 0x0101 | SERVER_HELLO | Control channel (0x0000) handshake: server hello (cleartext). |
| 0x0102 | SERVER_AUTH | Control channel (0x0000) handshake: server authentication (AEAD-sealed). |
| 0x0103 | CLIENT_AUTH | Control channel (0x0000) handshake: client authentication (AEAD-sealed). |
| 0x0100–0xFFFF | (channel-specific) | Channel-specific frame types begin at 0x0100 within each channel's frame namespace (per channel; the 0x0100–0x0103 rows above are the Control-channel handshake assignments). |

## TLV type registry

TLV tags carried in the extension region of a frame and in the handshake AUTH
frames. Tags marked "(reserved)" are held for companion specifications
(`spec/09_extension_points.md`). Tags `0x8000`–`0xFFFF` remain reserved as
forward-incompatible extension points (Type high bit set).

Machine-readable: `../registries/tlv_tags.csv` · Authoritative:
[core specification §TLV registry](../spec/07_tlv_registry.md).

| Tag | Name | Length | Description |
|---|---|---|---|
| 0x01 | ProfileOffer | var | Profiles offered by the client, one octet per profile (handshake only). |
| 0x02 | ProfileSelect | 1 | Profile selected by the server (handshake only). |
| 0x03 | KEMOffer | var | KEMs offered by the client. |
| 0x04 | KEMSelect | 2 | KEM selected by the server. |
| 0x05 | SigOffer | var | Signature algorithms offered. |
| 0x06 | SigSelect | 2 | Signature algorithm selected. |
| 0x07 | KEMShare | var | Public KEM share. |
| 0x08 | KEMCiphertext | var | KEM encapsulation ciphertext. |
| 0x09 | IdentityKey | var | Sender's identity public key (handshake AUTH). |
| 0x0A | CertVerify | var | SignatureScheme (u16) + signature over the transcript (handshake AUTH). |
| 0x0B | Finished | var | Finished MAC, length = negotiated KDF-hash output (handshake AUTH). |
| 0x0C | AEADOffer | var | AEAD suites offered by the client (handshake only). |
| 0x0D | AEADSelect | 2 | AEAD suite selected by the server (handshake only). |
| 0x10 | (reserved) | var | Reserved for a companion specification. |
| 0x12 | AnomalyCharge | 32 | Per-frame integrity charge. |
| 0x13 | (reserved) | var | Reserved for a companion specification. |
| 0x14 | (reserved) | 32 | Reserved for a companion specification (handshake only). |
| 0x15 | PathChallenge | 32 | Path-migration challenge nonce. |
| 0x16 | PathResponse | 64 | Path-migration response. |
| 0x17 | KeyUpdateMarker | 8 | Key-update epoch marker. |
| 0x18 | ProtectionMode | 1 | Protection-mode selector. |
| 0x8000–0xFFFF | (reserved) | -- | Forward-incompatible extension points (Type high bit set). |

## Profile registry

Three negotiated security profiles hold the wire format constant while escalating
the cryptographic primitives. The `code` is the one-octet profile selector carried
in the handshake.

Machine-readable: `../registries/profiles.csv` · Authoritative:
[core specification §Profiles](../spec/05_profiles.md).

| Profile | Code | Min KEM | Allowed signatures | KDF hash | Per-frame AEAD diversification | Downgrade refusal | Mandatory key update | Summary |
|---|---|---|---|---|---|---|---|---|
| Standard | 0x01 | X25519MLKEM768 | Ed25519 | SHA-256 | Off | Off | Yes | Baseline hybrid post-quantum security. |
| High | 0x02 | X25519MLKEM1024 | Ed25519, ML-DSA-87 | SHA-384 | On | Refuses Standard | Yes (tighter bounds) | Stronger KEM parameters and stronger hash; downgrade refusal to Standard. |
| Sovereign | 0x03 | X25519MLKEM1024 | ML-DSA-87 | SHA-384 | On | Refuses below Sovereign | Yes (tightest bounds) | Highest standard-crypto strength; downgrade refusal below Sovereign. |

## KEM-suite registry

Hybrid post-quantum key establishment combining X25519 with ML-KEM (FIPS 203).
The suite name lists X25519 first, but the shared secrets are concatenated
**ML-KEM-first** as HKDF-Extract input keying material (ADR-0005; NIST SP 800-56C
Rev. 2).

Machine-readable: `../registries/kem.csv` · Authoritative:
[core specification §Cryptographic suites](../spec/06_cryptographic_suites.md).

| Code point | Name | Profiles | Construction |
|---|---|---|---|
| 0x11ec | X25519MLKEM768 | Standard, High | Hybrid X25519MLKEM768 (FIPS 203); the suite name lists X25519 first, but the shared secrets are concatenated ML-KEM-768_SS \|\| X25519_SS (ML-KEM-first; ADR-0005 / NIST SP 800-56C Rev.2) as input keying material to HKDF-Extract. |
| 0x11ed | X25519MLKEM1024 | High, Sovereign | Hybrid X25519MLKEM1024 (FIPS 203); the suite name lists X25519 first, but the shared secrets are concatenated ML-KEM-1024_SS \|\| X25519_SS (ML-KEM-first; ADR-0005 / NIST SP 800-56C Rev.2) as input keying material to HKDF-Extract. Sovereign MUST NOT accept X25519MLKEM768. |

## AEAD-suite registry

Authenticated encryption suites for the record layer. Both use a 32-octet key, a
12-octet nonce, and a 16-octet authentication tag.

Machine-readable: `../registries/aead.csv` · Authoritative:
[core specification §Cryptographic suites](../spec/06_cryptographic_suites.md).

| Code point | Name | Key bytes | Nonce bytes | Tag bytes | Reference |
|---|---|---|---|---|---|
| 0x0001 | AES-256-GCM | 32 | 12 | 16 | RFC 5116 |
| 0x0002 | ChaCha20-Poly1305 | 32 | 12 | 16 | RFC 8439 |

## Signature-scheme registry

Signature schemes used for identity, capability tokens, and audit-epoch
authentication.

Machine-readable: `../registries/signatures.csv` · Authoritative:
[core specification §Cryptographic suites](../spec/06_cryptographic_suites.md).

| Code point | Name | Usage | Profiles | Reference |
|---|---|---|---|---|
| 0x0807 | Ed25519 | Identity, capability tokens | All | RFC 8032 |
| 0x0905 | ML-DSA-87 | Identity, audit epoch | High, Sovereign | FIPS 204 |

## Bridge protocol-ID registry

The one-octet `protocol_id` is the first octet of the BridgeEnvelope TLV (core TLV
type `0x0010`) carried on the Bridge channel `0x000D`; it names the foreign
agentic protocol carried verbatim in the frame. This is the **only** N-PAMP
registry with an open registration procedure: values `0x05`–`0x0F` are assigned
under the **Specification Required** policy of RFC 8126. The full procedure,
carriage-class definitions, and designated-expert criteria are in the companion
registry [NPAMP-REG](../spec/companion/30_protocol_registry.md).

Machine-readable: `../registries/bridge_protocol_ids.csv` · Authoritative:
[NPAMP-REG — Bridge protocol registry](../spec/companion/30_protocol_registry.md).

| `protocol_id` | Name | Carriage class | Mapping reference | Assignment policy | Description |
|---|---|---|---|---|---|
| 0x00 | (reserved) | -- | -- | Not assignable | Reserved (the null identifier). MUST NOT be used as a protocol_id; a receiver MUST reject a BridgeEnvelope whose protocol_id is 0x00 with EnvelopeMalformed (NPAMP-BRIDGE transport error code 1). NPAMP-REG Sections 4 and 9. |
| 0x01 | MCP — Model Context Protocol | JSONRPC | NPAMP-MAP-MCP | Specification Required | Standards-assigned; named directly by NPAMP-BRIDGE and recorded in NPAMP-REG Section 6; MUST NOT be reassigned. |
| 0x02 | A2A — Agent2Agent | JSONRPC (with DOC for the AgentCard) | NPAMP-MAP-A2A | Specification Required | Standards-assigned; named directly by NPAMP-BRIDGE and recorded in NPAMP-REG Section 6; MUST NOT be reassigned. |
| 0x03 | HTTP/2 generic carriage | HTTP | NPAMP-CC-HTTP | Specification Required | Standards-assigned; named directly by NPAMP-BRIDGE and recorded in NPAMP-REG Section 6; MUST NOT be reassigned. |
| 0x04 | WebSocket generic carriage | STREAM | NPAMP-CC-STREAM | Specification Required | Standards-assigned; named directly by NPAMP-BRIDGE and recorded in NPAMP-REG Section 6; MUST NOT be reassigned. |
| 0x05–0x0F | (unassigned) | -- | -- | Specification Required | Unassigned standards range; available under the Specification Required policy of RFC 8126 via the registration procedure of NPAMP-REG Section 8. |
| 0x10–0x7F | (experimental) | -- | -- | No registration | Experimental range; usable without registration; carries no guaranteed cross-domain meaning; a sender MUST NOT use it without out-of-band agreement with the peer. NPAMP-REG Section 7.1. |
| 0x80–0xFF | (private use) | -- | -- | No registration | Private-use range; usable within a single administrative domain without registration; never assigned by this registry; MUST NOT be emitted toward a peer outside that domain. NPAMP-REG Section 7.2. |

## Registration & assignment policies

N-PAMP registries fall into three registration regimes. Choose the row that
matches the registry you want to touch, then use the
**[registration request template](REGISTRATION-REQUEST.md)**.

| Registry / range | RFC 8126 policy | How to request | Decided by |
|---|---|---|---|
| Bridge `protocol_id` `0x05`–`0x0F` | **Specification Required** | Registration request (NPAMP-REG §8.2 fields) + a stable public specification | Designated expert (NPAMP-REG §8.3) |
| Bridge `protocol_id` `0x10`–`0x7F` (experimental) | **No registration** | Use directly under out-of-band peer agreement (NPAMP-REG §7.1) | Nobody — unregistered |
| Bridge `protocol_id` `0x80`–`0xFF` (private use) | **No registration** | Use within one administrative domain (NPAMP-REG §7.2) | The controlling domain |
| Bridge `protocol_id` `0x00`–`0x04` | **Not assignable / already assigned** | — MUST NOT be reassigned | — |
| Core channel / frame-type / TLV registries | Maintained **in the specification** (Independent Submission) | An **NEP** (`process/NEP-0000`) + ADR + PR against the draft; additive registrations vs. major-version layout changes per `CONTRIBUTING.md` | Draft editor / IESG-independent review |
| Core profile / KEM / AEAD / signature suites | Maintained **in the specification** | An **NEP** + ADR + PR (a new suite identifier is an additive registration) | Draft editor / IESG-independent review |
| ALPN identifier (`n-pamp/2`) | **Expert Review** (RFC 7301 §6) | IANA registration request (see `IANA_ALPN_n-pamp-2_registration_request.md`) | IANA designated expert |
| `npamp://` URI scheme | **First Come First Served / Provisional** (RFC 7595) | IANA registration request (see `IANA_ALPN_n-pamp-2_registration_request.md`) | IANA (provisional) |

!!! warning "Wire stability"
    Per `CONTRIBUTING.md` §"Code-point stability", changes to the 36-octet header
    geometry, the magic value, the header CRC, the channel registry, the
    frame-type number space, or the TLV number space are **major-version** changes
    (a new ALPN identifier, e.g. `n-pamp/3`), not additive registrations. Additive
    suite/identifier registrations do not change the wire layout.
