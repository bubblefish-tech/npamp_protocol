---
title: "N-PAMP: Native Post-Quantum Agent Messaging Protocol"
abbrev: N-PAMP
docname: draft-bubblefish-npamp-02
category: info
ipr: trust200902
submissionType: independent
area: ART
date: 2026

keyword:
  - post-quantum
  - agents
  - transport
  - ALPN

stand_alone: yes
pi: [toc, sortrefs, symrefs]

author:
  -
    ins: S. Sammartano
    name: Shawn Sammartano
    org: BubbleFish Technologies, Inc.
    # Required: a working, MONITORED email (below). ISE correspondence, the IETF
    # conflict review, and AUTH48 final-proof all go to this address. A postal
    # address is OPTIONAL under current RFC Editor practice and is omitted here.
    email: npamp-editor@bubblefish.sh

normative:
  RFC2119:
  RFC8174:
  RFC5116:
  RFC5869:
  RFC7301:
  RFC3986:
  RFC7595:
  RFC8032:
  RFC8439:
  RFC8446:
  RFC8949:
  RFC9000:
  RFC9001:
  FIPS203:
    title: "Module-Lattice-Based Key-Encapsulation Mechanism Standard"
    author:
      - org: National Institute of Standards and Technology (NIST)
    date: 2024
    seriesinfo:
      FIPS: 203
  FIPS204:
    title: "Module-Lattice-Based Digital Signature Standard"
    author:
      - org: National Institute of Standards and Technology (NIST)
    date: 2024
    seriesinfo:
      FIPS: 204
  SP800-56C:
    title: "Recommendation for Key-Derivation Methods in Key-Establishment Schemes"
    author:
      - org: National Institute of Standards and Technology (NIST)
    date: 2020-08
    target: https://csrc.nist.gov/pubs/sp/800/56/c/r2/final
    seriesinfo:
      NIST: Special Publication 800-56C Rev. 2

informative:
  RFC8126:
  RFC3552:
  I-D.ietf-tls-ecdhe-mlkem:

--- abstract

The Native Post-Quantum Agent Messaging Protocol (N-PAMP) is a binary,
multi-channel, wire-level protocol for authenticated communication between
autonomous software agents. N-PAMP operates beneath application-layer agent
protocols and provides a single fixed-size frame format, a registry of
multiplexed channels, and three escalating security profiles (Standard,
High, and Sovereign) built on standard post-quantum and classical
cryptography. The protocol uses a hybrid key-encapsulation mechanism
combining X25519 with ML-KEM, authenticated encryption with associated
data, and a forward-secure key schedule. N-PAMP runs over QUIC as its
primary transport and over TCP with TLS 1.3 as a fallback, negotiated via
the Application-Layer Protocol Negotiation (ALPN) identifier "n-pamp/2".
This document describes the wire format, channel architecture, profile
negotiation, and cryptographic suites of N-PAMP, and reserves code-point
ranges for extensions defined in companion specifications.

--- middle

# Introduction

Autonomous software agents increasingly communicate with one another over
long-lived associations that carry control traffic, persistent state, capability
delegation, identity attestation, and operational telemetry on a single
connection. Existing transport-layer protocols such as TLS 1.3 {{RFC8446}} and
QUIC {{RFC9000}}, and application-layer agent protocols layered above them, do
not by themselves provide a unified binary frame format with semantic channel
multiplexing, profile-negotiated cryptographic strength, and mandatory
authenticated encryption tailored to agent-to-agent traffic.

N-PAMP addresses this gap. It defines a single fixed-size frame header, a set of
multiplexed channels each carrying a distinct class of agent traffic, and three
negotiated security profiles that hold the wire format constant while escalating
the cryptographic primitives and operational requirements. All three profiles
employ a hybrid key-encapsulation mechanism (KEM) combining the classical X25519
key agreement with a NIST-standardized module-lattice KEM (ML-KEM, {{FIPS203}}),
so that the confidentiality of an association is preserved if either the
classical or the post-quantum component remains unbroken.

N-PAMP is deliberately scoped as a transport substrate. It does not define
application-layer semantics for the data carried on its channels; those are the
subject of companion specifications. This document specifies the wire format,
the channel registry, profile negotiation, and the cryptographic suites, and it
reserves code-point ranges so that companion extensions can be defined without
colliding with the core protocol.

## Goals

The design goals of N-PAMP are:

* Cryptographic agility within a stable wire format. The frame format does not
  change between profiles; the cryptographic primitives, modes, and operational
  requirements do.

* Defense in depth through hybrid post-quantum and classical key establishment,
  authenticated encryption, and a forward-secure key schedule.

* Channel multiplexing so that a single association can carry several classes of
  agent traffic with independent sequence spaces and per-channel keying.

* Interoperability across profiles, so that an endpoint operating at a higher
  profile MAY interoperate with a lower-profile peer when local policy permits.

## Non-Goals

This document does NOT:

* Replace TLS for ordinary web traffic. N-PAMP is purpose-built for
  autonomous-agent, multi-channel traffic over long-lived associations.

* Define application-layer semantics for the data carried on its channels.

* Define a general-purpose IP-layer tunneling or VPN protocol.

## Terminology

For the purposes of this document:

Association:
: A long-lived, cryptographically authenticated session between two N-PAMP
  endpoints, identified by a stable Association ID.

Channel:
: A semantic multiplexing lane within an association, identified by a 16-bit
  Channel ID, carrying one class of agent traffic with its own sequence space.

Frame:
: The atomic unit of transmission, consisting of a fixed 36-octet header,
  optional extension TLVs, and an AEAD-protected payload.

Profile:
: One of three negotiated levels of cryptographic strength and operational
  requirement (Standard, High, Sovereign).

# Conventions and Definitions

{::boilerplate bcp14-tagged}

# Protocol Overview {#protocol-overview}

N-PAMP is a binary protocol. Every unit of communication is a frame consisting
of a fixed 36-octet header ({{wire-format}}), zero or more extension TLVs, and a
payload protected by an authenticated-encryption-with-associated-data (AEAD)
construction {{RFC5116}}. Frames are carried on channels ({{channel-architecture}}),
each of which has an independent per-direction sequence space.

An N-PAMP association is established by a handshake that:

1. establishes a hybrid X25519 + ML-KEM shared secret;

2. negotiates a security profile, a KEM, a signature algorithm, and one or more
   AEAD suites;

3. authenticates both peers by signing a transcript that binds the negotiated
   parameters and both peer identities; and

4. derives a forward-secure key schedule from which per-channel, per-direction
   traffic keys are obtained.

The negotiated profile, the KEM identifier, the signature identifier, the
selected AEAD suite(s), and both peer identities are all bound into the
handshake transcript and confirmed by a Finished message authentication code
(MAC). A man-in-the-middle that alters any negotiated parameter or substitutes
an identity invalidates the Finished MAC and aborts the handshake; this is the
structural defense against downgrade, unknown-key-share, and
identity-substitution attacks (see {{security-considerations}}).

N-PAMP uses QUIC {{RFC9000}} (secured with TLS 1.3, {{RFC9001}}) as its primary
transport and TCP with TLS 1.3 {{RFC8446}} as a fallback. In both cases, the
application protocol is negotiated using the ALPN extension {{RFC7301}} with the
identifier "n-pamp/2" ({{iana-considerations}}).

# Wire Format {#wire-format}

## Frame Structure

Every N-PAMP frame has the following structure:

~~~
+--------+-------------+-------------------+-----------+
| Header | Extension   | Payload           | AEAD Tag  |
| 36 B   | TLVs (var)  | (var, encrypted)  | (16 B)    |
+--------+-------------+-------------------+-----------+
~~~
{: title="N-PAMP frame structure"}

The 36-octet header is fixed-size. Zero or more extension TLVs MAY accompany a
frame. The payload is AEAD-sealed, and the associated data covers the 21-octet
header prefix (octets 0-20, through the Payload Length field, the same octets
protected by the header CRC32C) so that any modification to those header fields
is detected on decryption.

## Frame Header

The fixed header is 36 octets, laid out as follows. Multi-octet integers are
encoded in network byte order (big-endian) unless stated otherwise.

~~~
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     'N'       |     'P'       |     'A'       |     'M'       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Ver   | Flags |          Frame Type           |  Channel ID   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                   Sequence Number (64 bits)                   +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                   Payload Length (32 bits)                    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                   CRC32C over octets 0-20                     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+             Reserved + Padding (11 octets, zero)              +
|                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
~~~
{: title="36-octet N-PAMP frame header"}

The fields are:

| Offset | Size | Field | Description |
|---|---|---|---|
| 0-3 | 4 octets | Magic | ASCII "NPAM" (0x4E 0x50 0x41 0x4D). |
| 4 | 4 bits | Ver | Protocol major version, the high nibble of octet 4. The value 0x2 designates the wire format described in this document (wire major version 2). |
| 4 | 4 bits | Flags | The low nibble of octet 4 (see {{frame-flags}}). |
| 5-6 | 2 octets | Frame Type | Frame type within the channel (see {{frame-types}}). |
| 7-8 | 2 octets | Channel ID | The semantic channel ({{channel-architecture}}). |
| 9-16 | 8 octets | Sequence Number | Per-(channel, direction) monotonic sequence number, starting at 0. |
| 17-20 | 4 octets | Payload Length | Byte count of the payload following the header. |
| 21-24 | 4 octets | CRC32C | CRC32C (Castagnoli polynomial 0x1EDC6F41) computed over header octets 0-20. Receivers MUST validate it before processing any other header field. |
| 25-35 | 11 octets | Reserved | MUST be zero; receivers MUST reject frames whose reserved octets are non-zero. |
{: title="Frame header fields"}

All multi-octet integers are big-endian. The Ver field carries the wire major
version; the value 0x02 corresponds to the ALPN identifier "n-pamp/2".

## Frame Flags {#frame-flags}

The low nibble of header octet 4 carries four flag bits:

| Bit | Name | Meaning |
|---|---|---|
| 0 (0x01) | URG | Urgent-priority scheduling. |
| 1 (0x02) | ENC | Payload is AEAD-encrypted. |
| 2 (0x04) | COMP | Payload is compressed. |
| 3 (0x08) | FRAG | Frame is a fragment of a larger logical message. |
{: title="Frame flags"}

## Extension TLVs

Zero or more Type-Length-Value (TLV) extensions MAY accompany a frame. Each TLV
is encoded as:

~~~
+---------+---------+-----------+
| Type    | Length  | Value     |
| 16 bits | 16 bits | Length B  |
+---------+---------+-----------+
~~~
{: title="Extension TLV encoding"}

Type and Length are 16-bit unsigned integers in network byte order; Length is the
byte count of Value (0 to 65535). A receiver that encounters an unknown TLV whose
Type has the high bit (0x8000) clear MUST ignore that TLV. A receiver that
encounters an unknown TLV whose Type has the high bit (0x8000) set MUST treat it
as a forward-incompatible extension and reject the frame. The TLV type registry
maintained by this specification is given in {{tlv-registry}}.

## Payload Encoding

The payload carries a frame-type-specific body. The body MAY be encoded in a
binary serialization, in deterministic CBOR {{RFC8949}}, or as raw octets. The
selected encoding is signaled within the channel-local interpretation of the
Frame Type field.

## Reserved Frame Types {#frame-types}

Each channel defines its own frame types in the 0x0000-0xFFFF space. The
following frame types are reserved across all channels and have the same meaning
on every channel:

| Type | Name | Description |
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
{: title="Reserved frame types (all channels)"}

Frame types are interpreted within the channel on which they appear, as
identified by the Channel ID field of the frame header ({{wire-format}}). A given
frame-type value MAY have a different meaning on different channels, except for
the all-channel reserved types above, which have the same meaning on every
channel. Each channel's frame-type namespace is partitioned as follows:

- 0x0000-0x000A: reserved all-channel frame types (the table above); the same
  meaning on every channel.
- 0x000B-0x002F: unassigned; reserved to this specification for future
  all-channel or core additions. A frame whose type is in this range and is not
  defined by this specification MUST be treated as an unknown frame type.
- 0x0030-0x00FF: companion-extension band. Frame types in this range are reserved
  for extensions defined in companion specifications and are scoped to a specific
  channel; the individual reservations are enumerated in {{extension-points}}.
- 0x0100-0xFFFF: channel-specific application frame types. Each channel defines
  its own frame types in this range; the same value on two different channels
  denotes two unrelated frames. The Control channel's handshake frame types
  (below) occupy 0x0100-0x0103.

The Control channel (0x0000) assigns the following channel-specific frame types for
the N-PAMP handshake ({{handshake}}):

| Type | Name | Description |
|---|---|---|
| 0x0100 | CLIENT_HELLO | First handshake flight (client); cleartext. |
| 0x0101 | SERVER_HELLO | Second handshake flight (server); cleartext. |
| 0x0102 | SERVER_AUTH | Server authentication flight; AEAD-protected. |
| 0x0103 | CLIENT_AUTH | Client authentication flight; AEAD-protected. |
{: title="Control-channel handshake frame types"}

## CLOSE Frame

A CLOSE frame is authenticated like any other frame. A receiver MUST verify the
AEAD tag before honoring a close. An unauthenticated or forged CLOSE frame MUST
be dropped and SHOULD be counted as a security event.

# Channel Architecture {#channel-architecture}

N-PAMP multiplexes traffic over channels identified by a 16-bit Channel ID. Each
channel carries one class of agent traffic and has an independent
per-direction sequence space and independent traffic keys
({{cryptographic-suites}}). A peer that has not advertised a channel during the
handshake MUST NOT receive frames on that channel; frames on an unadvertised
channel MUST be dropped.

## Core Channel Registry {#channel-registry}

The following channels are defined and maintained by this specification:

| ID | Name | Purpose | Min Profile | Direction |
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
{: title="Core channel registry"}

The Min Profile column gives the lowest profile at which a channel may be
enabled; a channel is available at that profile and at every higher profile
(for example, a "High" channel is available at High and Sovereign). The Audit
channel is enabled by default only at Sovereign; other profiles MAY enable it.
The Control and Immune channels SHOULD be scheduled at higher priority than bulk
channels (Memory, Sensory, Telemetry) during congestion.

All N-PAMP channels are full-duplex: each peer maintains an independent send and
receive sequence space and independent per-direction traffic keys, so both peers
MAY transmit on a channel simultaneously. The Direction column classifies each
channel as follows:

| Direction | Meaning |
|---|---|
| Bidirectional | Both peers send and receive frames on a single stream. |
| Multi-stream | Bidirectional, and the channel MAY open multiple concurrent transport streams within its stream family. |
{: title="Channel directionality"}

The Stream channel (0x000C) provides general-purpose multiplexed full-duplex
streaming, carrying concurrent bidirectional sub-streams (for example token,
audio, video, and file-transfer streams), each with independent flow control.

Channel IDs not listed in {{channel-registry}}, and in particular the ranges
enumerated in {{extension-points}}, are reserved for extensions defined in
companion specifications.

# Profile Negotiation {#profile-negotiation}

N-PAMP defines three security profiles. The profiles share one wire format and
differ in the cryptographic primitives and operational requirements they
mandate. Each profile is an escalation of the previous one in cryptographic
strength.

| Profile | Code | Summary |
|---|---|---|
| Standard | 0x01 | Baseline hybrid post-quantum security. |
| High | 0x02 | Stronger KEM parameters and stronger hash; downgrade refusal to Standard. |
| Sovereign | 0x03 | Highest standard-crypto strength; downgrade refusal below Sovereign. |
{: title="Security profiles"}

Profile code points 0x00 and 0x04-0xFF are reserved by this specification.

The profile is offered by the client and selected by the server during the
handshake, and is carried in the handshake transcript. Because the profile is
part of the transcript that the Finished MAC covers, an attacker who strips a
profile from the offer or forces a lower selection invalidates the MAC and
aborts the handshake.

The profile invariants are:

| Property | Standard | High | Sovereign |
|---|---|---|---|
| Minimum KEM | X25519MLKEM768 | X25519MLKEM1024 | X25519MLKEM1024 |
| Allowed signatures | Ed25519 | Ed25519, ML-DSA-87 | ML-DSA-87 |
| KDF hash | SHA-256 | SHA-384 | SHA-384 |
| Per-frame AEAD diversification | Off | On | On |
| Downgrade refusal | Off | Refuses Standard | Refuses below Sovereign |
| Mandatory key update | Yes | Yes (tighter bounds) | Yes (tightest bounds) |
{: title="Profile invariants"}

The server MUST select a profile from the client's offered set. The selected
profile MUST be no lower than the server's configured minimum acceptable peer
profile. A Sovereign server with a minimum acceptable peer profile of Sovereign
completes a handshake only when the client offers Sovereign and Sovereign is
selected.

A High or Sovereign endpoint MAY interoperate with a lower-profile peer for
read-only or capability-discovery operations when local policy permits, by
accepting a lower selected profile; otherwise it refuses the downgrade as shown
above.

# Cryptographic Suites {#cryptographic-suites}

All cryptographic primitives used by N-PAMP are published standards.

## Key Encapsulation Mechanisms

| Code point | Name | Profiles |
|---|---|---|
| 0x11ec | X25519MLKEM768 | Standard, High |
| 0x11ed | X25519MLKEM1024 | High, Sovereign |
{: title="KEM code points"}

Both are hybrid KEMs combining X25519 ECDH with ML-KEM {{FIPS203}} (ML-KEM-768
and ML-KEM-1024, respectively). The two shared secrets are concatenated as
(ML-KEM shared secret || X25519 shared secret) and supplied as input keying
material to HKDF-Extract {{RFC5869}}. The ML-KEM shared secret is placed first so
the FIPS-approved key-establishment output leads the HKDF input ({{SP800-56C}}),
matching the X25519MLKEM768 construction of {{I-D.ietf-tls-ecdhe-mlkem}}.
The suite name lists X25519 first, but the shared-secret concatenation and the
on-wire KEMShare/KEMCiphertext layout are ML-KEM-first. The Sovereign profile
MUST NOT accept X25519MLKEM768.

## Authenticated Encryption

| Code point | Name | Key | Nonce | Tag |
|---|---|---|---|---|
| 0x0001 | AES-256-GCM | 32 | 12 | 16 |
| 0x0002 | ChaCha20-Poly1305 | 32 | 12 | 16 |
{: title="AEAD code points"}

AES-256-GCM is used as specified for AEAD ciphers in {{RFC5116}};
ChaCha20-Poly1305 is used as specified in {{RFC8439}}. Endpoints operating at the
High and Sovereign profiles MUST support both AEAD suites because per-frame AEAD
diversification at those profiles selects between them. Endpoints operating at
the Standard profile MUST support at least one of the two.

## Signatures

| Code point | Name | Usage | Profiles |
|---|---|---|---|
| 0x0807 | Ed25519 | Identity, capability tokens | All |
| 0x0905 | ML-DSA-87 | Identity, audit epoch | High, Sovereign |
{: title="Signature code points"}

Ed25519 is used as specified in {{RFC8032}}. ML-DSA-87 is the
module-lattice-based digital signature algorithm standardized in {{FIPS204}}. The
Sovereign profile uses ML-DSA-87 for identity and audit signatures.

## Key Derivation and Hashing

All key derivation uses HKDF {{RFC5869}}. The KDF hash is SHA-256 at the Standard
profile and SHA-384 at the High and Sovereign profiles. The HKDF-Expand-Label
construction follows TLS 1.3 {{RFC8446}}, with the literal label prefix "n-pamp "
(with the trailing space) in place of TLS 1.3's "tls13 ", providing domain
separation from TLS 1.3, from QUIC, and from earlier N-PAMP versions. A conforming
implementation MUST use the "n-pamp " prefix; use of the "tls13 " prefix is
non-conformant. The full key-schedule ladder is specified in {{key-schedule}}.

## Key Schedule and Nonces

Traffic secrets are derived per (direction, epoch, AEAD suite, channel) tuple, so
that no two distinct contexts share a key. Each traffic secret yields an AEAD
key, an AEAD initialization vector, and a header-protection key by
HKDF-Expand-Label. The per-frame nonce is the AEAD IV exclusive-ORed with the
left-zero-padded sequence number, identical in form to the construction used in
TLS 1.3 {{RFC8446}} and QUIC {{RFC9001}}. This namespace partitioning prevents
cross-direction, cross-suite, and cross-channel nonce reuse, and supports forward
secrecy: on key update, traffic secrets for the new epoch are derived afresh and
the prior epoch's secrets are zeroized.

## Random Number Generation

All randomness that participates in security MUST come from a cryptographically
secure random number generator. Implementations MUST NOT use a non-cryptographic
source for any field that participates in security.

# Handshake {#handshake}

The N-PAMP handshake is a 1.5-RTT, mutually-authenticated exchange of four frames
on the Control channel (0x0000, sequence 0), after which both peers are
authenticated and a forward-secure key schedule is established. It reuses TLS 1.3
{{RFC8446}} constructions (HKDF-Expand-Label, CertificateVerify, Finished) with
N-PAMP framing and context; each divergence from TLS 1.3 is noted inline in the
relevant subsection below. One construction serves all three profiles; a profile
selects a parameter row (see {{profile-negotiation}} and {{cryptographic-suites}}),
so H and HashLen below are read from the negotiated profile.

## Message Flow

| Flight | Frame | Type | TLVs (in order) | Encryption |
|---|---|---|---|---|
| 1 | CLIENT_HELLO | 0x0100 | ProfileOffer, KEMOffer, SigOffer, AEADOffer, KEMShare | cleartext |
| 2 | SERVER_HELLO | 0x0101 | ProfileSelect, KEMSelect, SigSelect, AEADSelect, KEMCiphertext | cleartext |
| 2 | SERVER_AUTH | 0x0102 | IdentityKey, CertVerify, Finished | AEAD-sealed |
| 3 | CLIENT_AUTH | 0x0103 | IdentityKey, CertVerify, Finished | AEAD-sealed |
{: title="Handshake flights"}

There is no separate Finished frame; the Finished MAC is a TLV inside each AUTH
frame. Each frame is a standard 36-octet N-PAMP frame ({{wire-format}}) on channel
0x0000 with sequence 0; the AUTH frames set FlagENC and are AEAD-sealed
({{auth-frame-sealing}}). A server reaches the Established state only after it has
verified CLIENT_AUTH; the master secret is derived at the client-authentication
boundary.

## Transcript

The handshake transcript is a running byte buffer; a transcript hash is H over all
bytes absorbed so far. Unlike TLS 1.3 {{RFC8446}} Section 4.4.1, which hashes whole
handshake messages, N-PAMP absorbs at per-TLV granularity and absorbs only the
2-octet big-endian frame type of each frame: the remaining 34 header octets and the
AEAD tag are NOT absorbed. For each frame, the 2-octet frame type is absorbed,
followed by each of that frame's TLVs in canonical Type(2) || Length(2) || Value
form, in order. Five transcript hashes are named:

| Symbol | Absorbed through | Used by |
|---|---|---|
| TH_kem | CLIENT_HELLO and SERVER_HELLO TLVs | handshake-secret labels |
| TH_sId | ... server IdentityKey | server CertVerify signs this |
| TH_sCV | ... server CertVerify (excludes server Finished) | server Finished MACs this |
| TH_cId | ... server Finished, CLIENT_AUTH, client IdentityKey | client CertVerify signs this |
| TH_cCV | ... client CertVerify (excludes client Finished) | client Finished MACs this; master derived from this |
{: title="Handshake transcript hashes"}

Because both peers absorb the identical decoded on-wire TLV bytes, their transcripts
are byte-identical.

## Key Schedule {#key-schedule}

The key schedule is a single HKDF-Extract {{RFC5869}} followed by sibling
HKDF-Expand-Label derivations (simpler than TLS 1.3 {{RFC8446}} Section 7.1's
three-stage chain; N-PAMP defines no PSK or 0-RTT in this binding).
HKDF-Expand-Label is as in TLS 1.3 Section 7.1 with the N-PAMP label prefix
"n-pamp " (with the trailing space) in place of "tls13 ":

~~~
HKDF-Expand-Label(Secret, Label, Context, Length) =
    HKDF-Expand(Secret, HkdfLabel, Length)
HkdfLabel = uint16(Length) || opaque("n-pamp " || Label)
                           || opaque(Context)
~~~

The KEM output ({{cryptographic-suites}}) is the 64-octet value
(ML-KEM shared secret || X25519 shared secret), fed directly as input keying
material:

~~~
handshake_secret = HKDF-Extract(salt = HashLen zero octets,
                                IKM  = ML-KEM_SS || X25519_SS)
c_hs_secret = HKDF-Expand-Label(handshake_secret,
                                "c hs", TH_kem, HashLen)
s_hs_secret = HKDF-Expand-Label(handshake_secret,
                                "s hs", TH_kem, HashLen)
master      = HKDF-Expand-Label(handshake_secret,
                                "master", TH_cCV, HashLen)
~~~

The Extract salt is HashLen zero octets (the {{RFC5869}} default). The master secret
is derived only at the client-authentication boundary, from TH_cCV. Handshake-phase
traffic keys descend from c_hs_secret and s_hs_secret; application-phase traffic
keys descend from master, using the traffic-secret construction of
{{cryptographic-suites}}. Because the parents differ, an identical
(direction, epoch, suite, channel) tuple yields different (key, iv) across the
handshake and application phases, so no (key, nonce) pair is shared across phases.

## Authentication

### CertVerify

The CertVerify TLV (0x0A) carries a signature over the transcript, structured as in
TLS 1.3 {{RFC8446}} Section 4.4.3 with N-PAMP context strings:

~~~
signing_input = (0x20 x 64) || context || 0x00 || transcript_hash
context (server) = "N-PAMP/2, server CertificateVerify"
context (client) = "N-PAMP/2, client CertificateVerify"
~~~

The context strings are fixed protocol constants (they are the values bound into
the reference implementations and the interoperability test vectors) and do not
change with the Internet-Draft revision number. The signed transcript_hash is TH_sId
(server) or TH_cId (client): the transcript through the signer's own IdentityKey,
before its own CertVerify. The TLV value is the 2-octet SignatureScheme (Ed25519 =
0x0807) followed by the signature, whose length is delimited by the TLV Length. A
verifier MUST reject a signature scheme it did not negotiate and MUST check the
role: the differing context string makes a server CertVerify unusable as a client
CertVerify.

### Finished

The Finished TLV (0x0B) carries an HMAC per TLS 1.3 {{RFC8446}} Section 4.4.4, keyed
by the sender's handshake traffic secret:

~~~
finished_key = HKDF-Expand-Label(BaseKey, "finished", "", HashLen)
verify_data  = HMAC(finished_key, transcript_hash)
~~~

BaseKey is c_hs_secret or s_hs_secret per direction; the HMAC hash is H. The MAC'd
transcript_hash is TH_sCV (server) or TH_cCV (client): the transcript through the
signer's own CertVerify, excluding its own Finished. The verify_data length is
HashLen. Verification MUST be constant-time and MUST abort on mismatch.

### AUTH-Frame Sealing {#auth-frame-sealing}

SERVER_AUTH and CLIENT_AUTH are sealed with the negotiated AEAD under the
per-direction handshake key and IV ({{key-schedule}}): FlagENC is set, Channel is
0x0000, and Seq is 0. The AAD is the 21-octet frame header prefix and the nonce is
the IV exclusive-ORed with the sequence number, as in {{cryptographic-suites}}. On
open, exactly three TLVs -- IdentityKey, CertVerify, Finished, in that order -- MUST
be present.

### Downgrade Protection {#handshake-downgrade}

The negotiated profile and algorithm selections are carried in the cleartext
CLIENT_HELLO and SERVER_HELLO and are absorbed into the transcript that both the
Finished MAC and CertVerify cover. Stripping a profile from an offer, or forcing a
lower selection, therefore invalidates the Finished MAC and aborts the handshake.
N-PAMP uses this transcript binding for downgrade protection rather than a
TLS-style ServerHello.Random sentinel.

# Extension Points {#extension-points}

N-PAMP reserves code-point ranges for extensions defined in companion
specifications. The core protocol in this document neither defines nor requires
any extension; it only reserves the ranges below so that extensions can be
specified without colliding with the core wire format. The algorithms and
semantics that occupy these ranges are out of scope for this document and are
defined in companion specifications.

## Reserved Frame-Type Ranges

All companion frame-type reservations lie within the companion-extension band
0x0030-0x00FF defined in {{frame-types}}, and each is scoped to a specific
channel. The following per-channel frame-type code points are reserved for
extensions defined in companion specifications:

| Range | Channel | Reserved for |
|---|---|---|
| 0x0030 - 0x0034 | Stream (0x000C) | Stream-channel sub-stream lifecycle and flow-control extension frames |
| 0x0035 - 0x0036 | Memory (0x0001) | Memory-channel eviction and revive extension frames |
| 0x0060 - 0x0063 | Capability (0x0002) | Capability-channel token extension frames |
| 0x0080 - 0x0080 | Control (0x0000) | Control-channel flow-extension frames |
| 0x0090 - 0x0090 | Audit (0x000B) | Audit-channel per-frame integrity-extension frames |
| 0x00A0 - 0x00A3 | Settlement/Audit (0x0007/0x000B) | Settlement/Audit batch-commitment extension frames |
| 0x00B0 - 0x00B4 | Governance (0x0004) | Governance-channel quorum extension frames |
| 0x00C0 - 0x00C4 | Immune (0x0005) | Immune-channel propagation extension frames |
{: title="Reserved frame-type ranges (companion specifications)"}

## Reserved TLV Tags

The TLV types 0x0010, 0x0013, and 0x0014 are reserved for extension TLVs defined
in companion specifications. TLV types in the range 0x8000-0xFFFF remain reserved
as forward-incompatible extension points per {{wire-format}}.

## Reserved Channel-ID Range

Channel IDs in the range 0x0014-0xFFFF are reserved. Channels 0x0014-0x001F are
reserved for future core additions by this specification; 0x0020-0xEFFF are
reserved for extension channels defined in companion specifications; 0xF000-0xFFFE
are GREASE values that receivers MUST ignore; and 0xFFFF MUST NOT appear on the
wire. The specific extension assignments are out of scope for this document.

No algorithms, parameters, or semantics for any reserved range are defined in
this document.

# IANA Considerations {#iana-considerations}

## ALPN Protocol Identifier

IANA has registered the following value in the "TLS Application-Layer Protocol
Negotiation (ALPN) Protocol IDs" registry established by {{RFC7301}}. The
registration was made under an earlier version of this document; IANA is requested
to update its reference to the current version:

| Protocol | Identification Sequence | Reference |
|---|---|---|
| N-PAMP, wire major version 2 | 0x6E 0x2D 0x70 0x61 0x6D 0x70 0x2F 0x32 ("n-pamp/2") | (this document) |
{: title="ALPN registration (n-pamp/2)"}

The identification sequence is the 8-octet UTF-8 string "n-pamp/2". The trailing
digit "2" equals the N-PAMP wire major version (the value 0x02 carried in the Ver
field of the frame header, {{wire-format}}). The registration policy for the ALPN
registry is Expert Review {{RFC8126}}.

The earlier identifier "n-pamp/1" is deprecated. Implementations SHOULD NOT
negotiate "n-pamp/1" for new associations. Future wire major versions will use
distinct ALPN identifiers (for example, "n-pamp/3").

## URI Scheme Registration

The "npamp" URI scheme has been provisionally registered in the "Uniform Resource
Identifier (URI) Schemes" registry, following the template and the
provisional-registration procedure (First Come First Served) of {{RFC7595}}, under
an earlier version of this document; IANA is requested to update its reference to
the current version. The registration template follows:

**Scheme name:** npamp

**Status:** Provisional

**Applications/protocols that use this scheme:** The protocol defined in this
document (N-PAMP). An "npamp" URI names an N-PAMP endpoint and an optional
resource path within that endpoint.

**URI scheme syntax:** The "npamp" scheme uses the generic URI syntax of
{{RFC3986}}:

~~~ abnf
npamp-URI = "npamp://" authority path-abempty [ "?" query ]
~~~

where "authority", "path-abempty", and "query" are as defined in {{RFC3986}}. The
"authority" component identifies the N-PAMP endpoint (host and optional port).
N-PAMP does not reserve a fixed default port; the underlying transport is
negotiated as described in {{protocol-overview}}.

**Encoding considerations:** "npamp" URIs are processed as defined in
{{RFC3986}}; non-ASCII characters in the path or query components are
percent-encoded UTF-8 octets.

**Interoperability considerations:** None beyond those of {{RFC3986}}. The scheme
carries no protocol semantics of its own; all behavior is defined by N-PAMP.

**Security considerations:** See {{security-considerations}}. An "npamp" URI is
only an identifier. Connecting to an "npamp" endpoint invokes the N-PAMP
handshake and its authentication, confidentiality, and downgrade protections;
dereferencing an "npamp" URI MUST NOT bypass the security profile negotiated by
N-PAMP.

**Contact:** Shawn Sammartano, BubbleFish Technologies, Inc.

**Change controller:** Shawn Sammartano, BubbleFish Technologies, Inc.

**Reference:** This document.

## Registries Maintained by This Specification

The N-PAMP channel registry ({{channel-registry}}), the frame-type registry
({{frame-types}}), and the TLV type registry ({{tlv-registry}}) are defined and
maintained within this specification. Because this document is published through
the Independent Submission stream, it does not request the creation of new
IANA-hosted registries for these code points; the registries are normative within
this document and are extended by companion specifications and by future
revisions of this document, not by IANA registration actions.

## TLV Type Registry {#tlv-registry}

The following TLV tags are defined by this specification. Tags marked "reserved"
are described in {{extension-points}}.

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
| 0x09 | IdentityKey | var | Sender's identity public key (handshake AUTH; see {{handshake}}). |
| 0x0A | CertVerify | var | Signature over the transcript (handshake AUTH; see {{handshake}}). |
| 0x0B | Finished | var | HashLen-octet Finished MAC (handshake AUTH; see {{handshake}}). |
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
| 0x8000-0xFFFF | (reserved) | -- | Forward-incompatible extension points (Type high bit set). |
{: title="TLV type registry"}

# Security Considerations {#security-considerations}

This section follows the spirit of {{RFC3552}}. N-PAMP inherits the security
properties of its underlying transports, TLS 1.3 {{RFC8446}} and QUIC
{{RFC9001}}, and adds the considerations below.

## Hybrid Key Establishment

Every profile uses a hybrid KEM that concatenates an ML-KEM shared secret with an
X25519 shared secret {{FIPS203}} (ML-KEM first) before key derivation. The confidentiality of an
association is preserved as long as at least one of the two components remains
unbroken; an adversary must defeat both the classical and the post-quantum
component to recover traffic keys. N-PAMP makes no claim of unconditional or
"quantum-proof" security; it provides post-quantum hybrid security against the
adversaries addressed by its component primitives.

## Downgrade, Unknown-Key-Share, and Identity Substitution

The negotiated profile, KEM, signature algorithm, AEAD suite(s), and both peer
identities are bound into the handshake transcript and confirmed by the Finished
MAC ({{protocol-overview}}, {{profile-negotiation}}). Altering any negotiated
parameter, stripping a profile from the offer, or substituting a peer identity
invalidates the Finished MAC and aborts the handshake. The High and Sovereign
profiles additionally refuse to complete at a profile below their configured
minimum.

## Authenticated Encryption and Nonce Management

All payloads are protected by AEAD {{RFC5116}}. Traffic keys are partitioned per
(direction, epoch, suite, channel), which structurally prevents nonce reuse
across directions, AEAD suites, and channels. AEAD tag verification MUST be
performed before any payload is processed, and equality comparisons of
authentication values MUST be constant-time to avoid timing side channels.

## Replay

Each (channel, direction) pair maintains a sliding replay window over sequence
numbers. Frames outside the window or already recorded within it MUST be
rejected. Where 0-RTT data is permitted, it MUST be limited to idempotent
operations and protected against replay by an anti-replay mechanism scoped to the
current epoch; the Sovereign profile disables 0-RTT entirely.

## Forward Secrecy and Key Update

Endpoints MUST perform key updates within profile-specific bounds on elapsed
time, frames sent, and bytes protected, with the tightest bounds at the Sovereign
profile. On key update, the prior epoch's traffic secrets MUST be zeroized so
that compromise of the current epoch does not expose previously protected
traffic. Rotation of the master secret requires a fresh handshake.

## Connection Migration

When carried over QUIC, an endpoint MUST validate a peer's new path with a
challenge-response exchange (PATH_CHALLENGE / PATH_RESPONSE) before accepting an
address change, to prevent off-path migration spoofing.

## Authenticated Close

CLOSE frames are AEAD-protected and MUST be verified before being honored, so
that an off-path attacker cannot tear down an association with a forged CLOSE.

## Extension Points {#sec-extension-points}

The reserved code-point ranges in {{extension-points}} carry no algorithms or
semantics in this document. Any security properties of extensions occupying those
ranges are the responsibility of the companion specifications that define them and
are out of scope here.

## Implementation Considerations

Where the wire format requires deterministic encoding (for example, deterministic
CBOR {{RFC8949}} or canonical integer encodings), implementations MUST produce
byte-identical output for identical inputs, because non-deterministic encodings
can invalidate transcript and integrity computations across peers.

--- back

# Acknowledgments
{:numbered="false"}

The author thanks the reviewers of earlier N-PAMP drafts for their feedback.

# Changes Since draft-bubblefish-npamp-01
{:numbered="false"}

This revision is editorial and makes no change to the wire format; no code point
is added, removed, or renumbered, and every draft-01 implementation remains
conformant.

- Frame-type namespace. Restates the frame-type namespace description in
  {{frame-types}} as an explicit four-band partition (0x0000-0x000A all-channel
  reserved; 0x000B-0x002F reserved for future core additions; 0x0030-0x00FF the
  companion-extension band; 0x0100-0xFFFF channel-specific application frame
  types), resolving an inconsistency in draft-01 between the "begin at 0x0100"
  statement and the companion reserved ranges that sit below 0x0100. A frame type
  has always been interpreted within its channel, scoped by the Channel ID field
  of the frame header; this revision states that partition explicitly. No code
  point moves.
- Stream reserved range. Reserves frame-type range 0x0030-0x0034 for the Stream
  channel (0x000C) in the companion-extension band ({{extension-points}}); this
  gives a forthcoming Stream companion a reserved home for sub-stream lifecycle and
  flow-control extension frames. The range is reserved for a companion
  specification, and this document defines no frame within it.
- Reserved-range table. Adds a Channel column to the Reserved Frame-Type Ranges
  table ({{extension-points}}), making each range's owning channel explicit.

# Changes Since draft-bubblefish-npamp-00
{:numbered="false"}

This revision makes the following changes relative to draft-bubblefish-npamp-00:

- Hybrid KEM combiner order (wire-breaking). The hybrid shared-secret concatenation
  for both X25519MLKEM768 and X25519MLKEM1024 is now ML-KEM_SS || X25519_SS (ML-KEM
  first), replacing the X25519-first order of draft-00, so that the FIPS-approved key-establishment output leads the HKDF
  input per NIST SP 800-56C Rev. 2 ({{SP800-56C}}) and matches the construction of
  {{I-D.ietf-tls-ecdhe-mlkem}}. This changes the derived keys and is NOT interoperable
  with draft-00.
- Handshake binding. Adds the normative 1.5-RTT mutually-authenticated handshake
  ({{handshake}}): the four-frame flow, the per-TLV transcript, the single
  HKDF-Extract key schedule with the "n-pamp " label prefix, CertVerify, Finished,
  AUTH-frame sealing, and downgrade protection.
- Handshake code points. Assigns the Control-channel handshake frame types
  0x0100-0x0103 and the handshake TLV tags 0x09-0x0D (IdentityKey, CertVerify,
  Finished, AEADOffer, AEADSelect).
- ProfileOffer length. Corrects the ProfileOffer (TLV 0x01) length from a fixed 4 to a
  variable list of one-octet profile identifiers, matching the other negotiation
  offers and the reference implementations.
- IANA Considerations. Updated to reflect that the ALPN identifier "n-pamp/2" and the
  "npamp" URI scheme are already registered, requesting a reference update to this
  revision rather than a new assignment.
