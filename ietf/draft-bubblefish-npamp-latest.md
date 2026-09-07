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
  BCP14:
  RFC5116:
  RFC5869:
  RFC7301:
  RFC3986:
  RFC7595:
  RFC8032:
  RFC8439:
  RFC9846:
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
  RFC10024:
  I-D.ietf-tls-mldsa:

informative:
  RFC8126:
  RFC3552:
  RFC9293:
  RFC9147:

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
the Application-Layer Protocol Negotiation (ALPN) identifier "n-pamp/3".
This document describes the wire format, channel architecture, profile
negotiation, and cryptographic suites of N-PAMP, and reserves code-point
ranges for extensions defined in companion specifications.

--- middle

# Introduction

Autonomous software agents increasingly communicate with one another over
long-lived associations that carry control traffic, persistent state, capability
delegation, identity attestation, and operational telemetry on a single
connection. Existing transport-layer protocols such as TLS 1.3 {{RFC9846}} and
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

{::boilerplate bcp14-tagged-bcp14}

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
transport and TCP with TLS 1.3 {{RFC9846}} as a fallback. In both cases, the
application protocol is negotiated using the ALPN extension {{RFC7301}} with the
identifier "n-pamp/3" ({{iana-considerations}}).

# Wire Format {#wire-format}

## Frame Structure

Every N-PAMP frame has the following structure:

~~~
+--------+------------------------------------------------+
| Header | Payload                                        |
| 36 B   | (var; frame-type body, then 16-octet AEAD tag) |
+--------+------------------------------------------------+
~~~
{: title="N-PAMP frame structure"}

The 36-octet header is fixed-size. Everything after the header is a single Payload
region whose length is the Payload Length field: it carries the frame-type-specific
body (which, where a frame type uses them, contains extension TLVs decoded per that
frame type) and ends with the 16-octet AEAD tag, which is counted in Payload Length.
There is no separate extension-TLV region between the header and the payload;
extension TLVs are frame-type payload content (see Extension TLVs). The payload is
AEAD-sealed, and the associated data covers the 21-octet header prefix (octets 0-20,
through the Payload Length field, the same octets protected by the header CRC32C) so
that any modification to those header fields is detected on decryption. The CRC32C
(octets 21-24) and the reserved octets (25-35) are OUTSIDE the AEAD associated-data
range (octets 0-20); a receiver MUST NOT make any security decision based on them.
The CRC32C is a non-cryptographic integrity check (an on-path attacker who alters a
header field can recompute it), and the reserved octets carry no meaning beyond the
MUST-be-zero rule; only the AEAD tag over the AD-covered header prefix authenticates
the header.

## Stream Framing

N-PAMP frames are self-delimiting: each frame carries its own length in the Payload
Length header field, so no inter-frame delimiter or separate total-length prefix is
used. Over a stream transport (TCP with TLS 1.3), a receiver locates each frame
boundary by reading the fixed 36-octet header, taking Payload Length (octets 17-20,
big-endian), and consuming exactly 36 + Payload Length octets; the next frame begins
at the following octet. A receiver that has buffered fewer than 36 octets, or fewer
than 36 + Payload Length octets, MUST wait for more input before parsing the frame.
Over QUIC a frame MAY additionally align to a stream or datagram boundary, but the
same Payload-Length self-delimiting rule applies within any byte run.

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
| 4 | 4 bits | Ver | Wire-format version (high nibble of octet 4). The value 0x2 designates this frame layout; it is invariant and does not identify the crypto generation (see {{iana-considerations}}). |
| 4 | 4 bits | Flags | The low nibble of octet 4 (see {{frame-flags}}). |
| 5-6 | 2 octets | Frame Type | Frame type within the channel (see {{frame-types}}). |
| 7-8 | 2 octets | Channel ID | The semantic channel ({{channel-architecture}}). |
| 9-16 | 8 octets | Sequence Number | Per-(channel, direction) monotonic sequence number, starting at 0 in the keyed session; the four handshake frames are the exception and all use sequence 0 ({{handshake}}). |
| 17-20 | 4 octets | Payload Length | Octet count of everything following the 36-octet header -- the frame-type body (including any extension TLVs) and the trailing 16-octet AEAD tag. This single quantity locates the frame boundary on a stream transport. |
| 21-24 | 4 octets | CRC32C | CRC32C (Castagnoli polynomial 0x1EDC6F41) computed over header octets 0-20. Receivers MUST validate it before processing any other header field. |
| 25-35 | 11 octets | Reserved | MUST be zero; receivers MUST reject frames whose reserved octets are non-zero. |
{: title="Frame header fields"}

All multi-octet integers are big-endian. The Ver field carries the wire-format
version (the frame layout); the value 0x02 is invariant and does not identify the
crypto generation. The crypto generation is carried out of band by the negotiated
ALPN identifier (currently "n-pamp/3"), or by explicit configuration where frames
are exchanged without TLS; a raw frame is not generation-self-describing. A receiver
MUST reject any frame whose Ver nibble is not 0x02.

## Frame Flags {#frame-flags}

The low nibble of header octet 4 carries four flag bits:

| Bit | Name | Meaning |
|---|---|---|
| 0 (0x01) | (reserved) | Reserved (formerly URG); MUST be 0. A receiver MUST reject a frame that sets this bit. |
| 1 (0x02) | ENC | Payload is AEAD-encrypted. |
| 2 (0x04) | COMP | Payload is compressed. |
| 3 (0x08) | (reserved) | Reserved (formerly FRAG); MUST be 0. A receiver MUST reject a frame that sets this bit. |
{: title="Frame flags"}

## Extension TLVs

Where a frame type uses Type-Length-Value (TLV) extensions, they appear inside
that frame type's payload, decoded per the frame type's grammar; there is no
separate extension-TLV region between the header and the payload. Each TLV is
encoded as:

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
as a forward-incompatible extension and reject the frame with the registered error
code `unknown_critical_tlv` ({{error-registry}}). The TLV type registry
maintained by this specification is given in {{tlv-registry}}.

## Payload Encoding

The payload carries a frame-type-specific body. The body MAY be encoded in a
binary serialization, in deterministic CBOR {{RFC8949}} (per the Deterministic
Encoding Profile, {{det-encoding}}), or as raw octets. The selected encoding is
signaled within the channel-local interpretation of the Frame Type field.

### Deterministic Encoding Profile {#det-encoding}

Wherever this document or a companion specification requires "deterministic CBOR",
the encoding MUST conform to the core deterministic encoding requirements of
{{RFC8949}}, Section 4.2.1, with the following pins:

- Map keys are sorted in **bytewise lexicographic order of their encoded bytes**
  ({{RFC8949}}, Section 4.2.1), NOT the length-first order of Section 4.2.3.
- Integers and byte-/text-string lengths use the **shortest form**
  ({{RFC8949}}, Section 4.2.1).
- **No indefinite-length** items are used ({{RFC8949}}, Section 4.2.1).
- A decoder MUST reject a map that contains **duplicate keys** as malformed
  ({{RFC8949}}, Section 5.6).
- On any CBOR-bearing surface that admits numbers, the **integer/float rule** of
  {{RFC8949}}, Section 4.2.2 applies: a value representable as an integer is not
  encoded as a floating-point number.
- In a **sealed body** (a CBOR value inside an AEAD-protected payload), tags and
  floating-point values MUST NOT appear, so that two conformant encoders emit
  byte-identical sealed input.

Because AEAD sealing and transcript hashing are computed over the exact octets, a
non-deterministic or non-conformant encoding invalidates integrity and transcript
computation across peers; a receiver MUST reject a frame whose CBOR body violates
this profile.

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

An endpoint closes an association with an acknowledged teardown on the Control channel
(0x0000). A CLOSE frame (0x0003) is authenticated like any other frame: a receiver MUST
verify the AEAD tag before honoring it, and an unauthenticated or forged CLOSE frame
MUST be dropped and SHOULD be counted as a security event, so an off-path attacker
cannot tear down an association with a forged CLOSE.

The exchange is CLOSE then CLOSE_ACK and closes the whole association (every channel):

1. The closer seals and sends a CLOSE frame on Control. CLOSE is the closer's final
   frame: after sending it the closer MUST NOT send any further application frame on
   any channel, and it moves to the CLOSING state. Because each (channel, direction)
   is delivered in order ({{wire-format}}), every frame the closer sent before CLOSE is
   delivered ahead of it, so no in-flight frame the closer already sent is lost.
2. The peer, on a verified CLOSE, MUST first process any frames it has already received
   in sequence order up to the CLOSE (in-flight frames are not discarded), then seal and
   send a CLOSE_ACK frame (0x0004) on Control, then tear down (CLOSED). After sending
   CLOSE_ACK it MUST NOT send any further frame.
3. The closer, in CLOSING, awaits CLOSE_ACK under the CLOSE_ACK-wait timer (its bounds
   are stated with the other numeric bounds, {{security-considerations}}). While it
   waits it MAY continue to receive and process frames the peer had in flight. On
   CLOSE_ACK it moves to CLOSED; on the timer's expiry it forces teardown and records
   the outcome as `close_incomplete` ({{error-registry}}) -- the peer is unresponsive, so
   no further ERROR is sent.

CLOSE and CLOSE_ACK carry no payload; the frame type and its AEAD authentication are the
whole of the message. A receiver MUST reject a CLOSE or CLOSE_ACK that carries a
non-empty payload with `unexpected_message`. Once an endpoint reaches CLOSED it
processes no further frame, and the association's key schedule -- the master secret and
every cached epoch key -- is zeroized ({{security-considerations}}).

## ERROR Frame {#error-handling}

Reject conditions have one of two reactions. A **fatal** condition aborts the
connection: after a traffic key is established, an endpoint that aborts on a fatal
condition MUST send an ERROR frame (0x0005) on the Control channel (0x0000) carrying
the condition's code before it tears the connection down; before any traffic key is
established -- an initiator before it has processed SERVER_HELLO -- it aborts WITHOUT an
ERROR (so there is no unauthenticated ERROR an off-path attacker could forge), and the
peer detects the abort through the transport or the handshake-completion timer. Two
fatal codes are triggered by a timer rather than a received frame -- `handshake_timeout`
and `close_incomplete` -- and force teardown directly: the endpoint MAY send a
best-effort ERROR if a traffic key is established, but MAY omit it when the peer is
unresponsive, and it records the outcome and tears down regardless. A **discard**
condition is not fatal: the offending frame is dropped and the condition
is counted, the connection survives, and no ERROR frame is sent. Each code's reaction
is given in the registry below.

The ERROR frame is AEAD-protected under the current traffic key. A receiver MUST verify
the AEAD tag before reading an ERROR frame and MUST NOT make any security decision
based on an unauthenticated or malformed ERROR; an authenticated ERROR frame is
advisory -- it reports the sender's reason for aborting and does not itself change the
receiver's keys or state beyond letting the receiver surface the reason and close.

The ERROR payload is a deterministic-CBOR ({{det-encoding}}) map with two integer keys:

~~~
error-body = {
  1 => code:    0..255,   ; Error/Alert Code Registry value (below)
  2 => context: bstr,     ; diagnostic detail; always present,
                          ; MAY be zero-length
}
~~~

The `context` is an implementation-chosen diagnostic detail (for example, the
offending frame type) and carries no normative meaning; it is always present and MAY
be zero-length, and a receiver MUST NOT parse `context` into any security decision.

### Error/Alert Code Registry {#error-registry}

Every "MUST reject" / "MUST abort" condition in this document maps to exactly one of
the following codes. A fatal code is carried in the ERROR frame, so a passive observer
holding the keys can decide from the wire which fatal condition fired; a discard code
names a frame the receiver silently drops and counts, which produces no wire signal
(its conformance is asserted as no response plus connection survival). Code 0 is
reserved.

| Code | Name | Reaction | Condition |
|---|---|---|---|
| 0 | (reserved) | -- | Reserved; MUST NOT be sent. |
| 1 | unexpected_message | fatal | A frame not legal for the current state ({{handshake-state-machine}} total default): out-of-order, wrong-flight, repeated, an application frame before ESTABLISHED, an unsolicited acknowledgement (a KEY_UPDATE_ACK / MASTER_RATCHET_ACK / REKEM_ACK / CLOSE_ACK for which the endpoint has no outstanding corresponding request), or an effecting frame in ESTABLISHED_READONLY. |
| 2 | decrypt_failed | fatal | A handshake AEAD open, CertVerify signature, or Finished MAC failed to verify at WAIT_SA or WAIT_CA ({{handshake-state-machine}}) -- a fatal handshake authentication failure. In an ESTABLISHED keyed session an AEAD-open failure is NOT decrypt_failed: it is a silently-dropped, counted record whose association survives ({{record-layer-drops}}). |
| 3 | replay_detected | discard | A frame's sequence number was below the replay window or already recorded within it (Replay, {{security-considerations}}); the frame is dropped and counted, the connection survives. |
| 4 | unknown_channel | discard | A frame arrived on a channel the peer did not advertise during the handshake ({{channel-architecture}}); the frame is dropped and counted. |
| 5 | unknown_critical_tlv | fatal | A frame carried an unknown extension TLV with the high bit (0x8000) set ({{tlv-registry}}). |
| 6 | handshake_timeout | fatal | The handshake did not complete within the handshake-completion timer. |
| 7 | downgrade_detected | fatal | A profile or algorithm selection was not covered by the transcript the Finished MAC and CertVerify authenticate ({{handshake-downgrade}}). |
| 8 | close_incomplete | fatal | A CLOSE was not acknowledged within the CLOSE_ACK-wait timer (Authenticated Close, {{security-considerations}}). |
| 9 | key_update_out_of_order | fatal | A KeyUpdateMarker (on a KEY_UPDATE or a KEY_UPDATE_ACK) announced an epoch other than current + 1, or was malformed ({{key-update}}). |
| 10 | flow_control_error | fatal | A peer's cumulative sent-payload total exceeded the connection-level receive limit the receiver advertised via FLOW_UPDATE ({{flow-control}}). |
{: title="Error/Alert code registry"}

The code is a one-octet value (0-255), so every value is classified. Codes 11-255 are
unassigned and reserved to this specification for future core conditions. Because this
document is published through the Independent Submission stream, this registry is
normative within the document and is extended by future revisions, not by an IANA
registration action; the registration policy for any IANA-hosted mirror would be RFC
Required / First Come First Served ({{RFC8126}}), with code points assigned at
publication and never self-allocated.

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
| Multi-stream | Bidirectional, and the channel MAY carry multiple concurrent logical sub-streams multiplexed within its frame payloads (for example the Stream channel's sub-streams), all over the channel's single ordered per-direction sequence. |
{: title="Channel directionality"}

The Stream channel (0x000C) provides general-purpose multiplexed full-duplex
streaming, carrying concurrent bidirectional sub-streams (for example token,
audio, video, and file-transfer streams), each with independent flow control.

A channel's frames for a given direction form a single ordered sequence carried over one
transport byte run (one QUIC stream, or the TCP-with-TLS byte stream); the per-(channel,
direction) sequence number is assigned by a single writer ({{key-schedule}}), and nonce
uniqueness and the replay window depend on that single monotonic sequence. This revision
therefore does NOT define a channel opening multiple concurrent transport-layer streams:
the frame header carries no per-transport-stream identifier, and splitting one channel's
frames across independently ordered transport streams would break the single-writer
sequence and risk nonce reuse. "Multi-stream" accordingly denotes payload-layer sub-stream
multiplexing (for example the NPAMP-STREAM `sub_stream_id`), never transport-stream
multiplexing; an implementation MUST carry each (channel, direction) as one ordered
sequence. A future revision that adds concurrent transport-stream operation MUST also
define the per-transport-stream correlation and the corresponding sequence and nonce
separation, and negotiates a new ALPN generation.

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
| Minimum KEM | X25519MLKEM768 | SecP384r1MLKEM1024 | SecP384r1MLKEM1024 |
| Allowed signatures | Ed25519 | Ed25519, ML-DSA-87 | ML-DSA-87 |
| KDF hash | SHA-256 | SHA-384 | SHA-384 |
| Per-frame AEAD divers. | Off | On | On |
| Downgrade refusal | Off | Refuses Standard | Refuses below Sovereign |
| Mandatory key update | Yes | Yes (tighter) | Yes (tightest) |
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
| 0x11ed | SecP384r1MLKEM1024 | High, Sovereign |
{: title="KEM code points"}

Both are hybrid KEMs combining an elliptic-curve ECDH with ML-KEM {{FIPS203}}, per
{{RFC10024}}. The concatenation order is per-group: for each group
the FIPS-approved component leads the HKDF input as that group's defining
construction requires (see {{SP800-56C}}), so the two groups differ.

X25519MLKEM768 (0x11ec) combines X25519 with ML-KEM-768 and is ML-KEM-first: the
shared secret is (ML-KEM-768 SS || X25519 SS); KEMShare is (ML-KEM-768 ek (1184) ||
X25519 pub (32)) = 1216 octets; KEMCiphertext is (ML-KEM-768 ct (1088) || server
X25519 pub (32)) = 1120 octets. The suite name lists X25519 first, but the bytes are
ML-KEM-first ({{RFC10024}} records this reversed order as historical).

SecP384r1MLKEM1024 (0x11ed) combines secp384r1 (P-384) with ML-KEM-1024 and is
ECDHE-first (P-384 first): the shared secret is (ECDHE SS (48) || ML-KEM-1024 SS
(32)) = 80 octets; KEMShare is (secp384r1 pub (97) || ML-KEM-1024 ek (1568)) = 1665
octets; KEMCiphertext is (server secp384r1 pub (97) || ML-KEM-1024 ct (1568)) = 1665
octets. The secp384r1 share is the uncompressed point encoding of {{RFC9846}} Section
4.3.8.2; the ECDHE shared secret is the shared-point x-coordinate.

Both feed the concatenation raw to HKDF-Extract {{RFC5869}} as input keying material.
The Sovereign profile MUST NOT accept X25519MLKEM768.

## Authenticated Encryption

| Code point | Name | Key | Nonce | Tag |
|---|---|---|---|---|
| 0x0001 | AES-256-GCM | 32 | 12 | 16 |
| 0x0002 | ChaCha20-Poly1305 | 32 | 12 | 16 |
{: title="AEAD code points"}

AES-256-GCM is used as specified for AEAD ciphers in {{RFC5116}};
ChaCha20-Poly1305 is used as specified in {{RFC8439}}. AES-256-GCM (0x0001) is
Mandatory-To-Implement in every profile, so two conformant endpoints always share
at least one AEAD -- a non-empty MUST-support intersection for every profile x
algorithm class (the Danvers Doctrine, BCP 61). Endpoints operating at the Standard
profile MUST support AES-256-GCM and MAY additionally support ChaCha20-Poly1305.
Endpoints operating at the High and Sovereign profiles MUST support both AEAD suites
because per-frame AEAD diversification at those profiles selects between them.

At High and Sovereign, per-frame AEAD diversification selects each frame's AEAD suite
deterministically from the sequence number, with no per-frame wire flag: the suite is
`AEADSelect[seq mod N]`, where AEADSelect is the negotiated ordered list of selectable
suites (primary first) and N is its length. Both peers derive the same suite from the
shared per-(channel, direction) sequence number. Consequently AEADSelect (TLV 0x0D)
carries the ordered list of selectable suites (2 octets per suite, primary first):
one suite at Standard, both at High and Sovereign. The former fixed 2-octet encoding
does not stand while two suites are selectable.

## Signatures

| Code point | Name | Usage | Profiles |
|---|---|---|---|
| 0x0807 | Ed25519 | Identity, capability tokens | All |
| 0x0904 | ML-DSA-44 | Reserved (IANA TLS SignatureScheme); unused | -- |
| 0x0905 | ML-DSA-65 | Reserved (IANA TLS SignatureScheme); unused | -- |
| 0x0906 | ML-DSA-87 | Identity, audit epoch | High, Sovereign |
{: title="Signature code points"}

The ML-DSA code points reference the IANA TLS SignatureScheme registry
({{I-D.ietf-tls-mldsa}}): 0x0904 = ML-DSA-44, 0x0905 = ML-DSA-65, 0x0906 = ML-DSA-87.
Ed25519 is used as specified in {{RFC8032}}. ML-DSA-87 is the module-lattice-based
digital signature algorithm standardized in {{FIPS204}}. N-PAMP negotiates only
ML-DSA-87 (0x0906) at High and Sovereign; 0x0904 and 0x0905 are listed so N-PAMP's
namespace does not shadow the IANA values. The Sovereign profile uses ML-DSA-87 for
identity and audit signatures.

The hybrid-KEM construction authority {{RFC10024}} (formerly the Internet-Draft
`draft-ietf-tls-ecdhe-mlkem`, published August 2026) is cited directly as a published
RFC. The ML-DSA SignatureScheme code points {{I-D.ietf-tls-mldsa}} remain an active
Internet-Draft at the time of writing; on its publication as an RFC, this citation is
to be updated to the assigned RFC number.

## Key Derivation and Hashing

All key derivation uses HKDF {{RFC5869}}. The KDF hash is SHA-256 at the Standard
profile and SHA-384 at the High and Sovereign profiles. The HKDF-Expand-Label
construction follows TLS 1.3 {{RFC9846}}, with the literal label prefix "n-pamp "
(with the trailing space) in place of TLS 1.3's "tls13 ", providing domain
separation from TLS 1.3, from QUIC, and from earlier N-PAMP versions. A conforming
implementation MUST use the "n-pamp " prefix; use of the "tls13 " prefix is
non-conformant. The full key-schedule ladder is specified in {{key-schedule}}.

## Key Schedule and Nonces

Traffic secrets are derived per (direction, epoch, AEAD suite, channel) tuple, so
that no two distinct contexts share a key. Each traffic secret yields an AEAD
key and an AEAD initialization vector by HKDF-Expand-Label; N-PAMP derives no
separate header-protection key, because header protection is provided by the secure
transport. The per-frame nonce is the AEAD IV exclusive-ORed with the
left-zero-padded sequence number, identical in form to the construction used in
TLS 1.3 {{RFC9846}} and QUIC {{RFC9001}}. This namespace partitioning prevents
cross-direction, cross-suite, and cross-channel nonce reuse, and supports forward
secrecy: on key update, traffic secrets for the new epoch are derived afresh and
the prior epoch's secrets are zeroized.

Within a single (direction, epoch, AEAD suite, channel) key, sequence-number
assignment MUST be atomic and single-writer: each frame MUST be sealed under exactly
the sequence number it was assigned, so that a multi-threaded sender cannot reuse a
sequence number, and therefore a nonce, under one key. An endpoint MUST perform a
key update before the negotiated AEAD's usage limit is reached, and MUST NOT let the
sequence space wrap within an epoch; a key update begins a new epoch with fresh
secrets (see the key-update procedure). Cross-(direction, epoch, suite, channel)
reuse is structurally prevented by the key separation above; this rule covers the
remaining intra-key case.

## Random Number Generation

All randomness that participates in security MUST come from a cryptographically
secure random number generator. Implementations MUST NOT use a non-cryptographic
source for any field that participates in security.

# Handshake {#handshake}

The N-PAMP handshake is a 1.5-RTT, mutually-authenticated exchange of four frames
on the Control channel (0x0000, sequence 0), after which both peers are
authenticated and a forward-secure key schedule is established. It reuses TLS 1.3
{{RFC9846}} constructions (HKDF-Expand-Label, CertificateVerify, Finished) with
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

All four handshake frames use sequence number 0 -- the exception to the general
per-(channel, direction) monotonic sequence rule ({{wire-format}}). Each direction
AEAD-seals at most one handshake frame (SERVER_AUTH server-to-client and CLIENT_AUTH
client-to-server; the HELLO frames are cleartext), so sequence 0 is sealed at most
once per direction under the handshake key and no (key, nonce) pair repeats. The
monotonic per-(channel, direction) sequence space of the keyed session begins at
sequence 0 of epoch 0, which starts when the handshake completes.

## State Machine {#handshake-state-machine}

The handshake and the keyed session form one state machine per endpoint. The
per-state transition rules and the total default in this section are normative; the
diagram is informative (following the {{RFC9293}} Section 3.10 model, in which the
event-by-state processing rules bind and a summary diagram does not). Each state is
named for what the endpoint is waiting for. Every frame that can arrive in a state is
either listed with its transition below or is covered by the total default; there is
no state in which an unexpected frame is silently ignored.

An endpoint plays one role, fixed when the connection is set up: the initiator sends
CLIENT_HELLO first, and the responder waits for it. The two roles have distinct
handshake states and converge on the shared keyed-session states ESTABLISHED,
CLOSING, and CLOSED.

| Role | State | Waiting for |
|---|---|---|
| initiator | START | (initial) about to send CLIENT_HELLO |
| initiator | WAIT_SH | SERVER_HELLO |
| initiator | WAIT_SA | SERVER_AUTH (handshake keys already derived from SERVER_HELLO) |
| responder | LISTEN | (initial) CLIENT_HELLO |
| responder | WAIT_CA | CLIENT_AUTH (SERVER_HELLO and SERVER_AUTH already sent) |
| both | ESTABLISHED | application frames on any open channel (keyed) |
| both | CLOSING | CLOSE_ACK (this endpoint has sent CLOSE) |
| both | CLOSED | (terminal) |
{: title="Protocol states"}

~~~
(informative)
initiator: START --send CLIENT_HELLO-->
           WAIT_SH --recv SERVER_HELLO--> WAIT_SA
           WAIT_SA --recv+verify SERVER_AUTH;
           send CLIENT_AUTH; key master--> ESTABLISHED
responder: LISTEN --recv CLIENT_HELLO;
           send SERVER_HELLO, SERVER_AUTH--> WAIT_CA
           WAIT_CA --recv+verify CLIENT_AUTH--> ESTABLISHED
both:      ESTABLISHED --KEY_UPDATE-->
           ESTABLISHED (epoch advances in place)
           ESTABLISHED --send/recv CLOSE--> CLOSING
           --CLOSE_ACK / timeout--> CLOSED
~~~

Normative transitions -- initiator:

- START: the endpoint sends CLIENT_HELLO and moves to WAIT_SH. No frame is legal to
  receive in START.
- WAIT_SH: on SERVER_HELLO, the endpoint checks that every selection is one it offered
  (a stripped or downgraded selection is additionally caught by the transcript binding
  of the Finished MAC and CertVerify, Downgrade Protection), derives the handshake
  traffic keys, and moves to WAIT_SA.
- WAIT_SA: on SERVER_AUTH -- which MUST carry exactly IdentityKey, CertVerify, and
  Finished, in that order -- the endpoint verifies the CertVerify signature and the
  Finished MAC; on success it sends CLIENT_AUTH, derives the master secret, and moves
  to ESTABLISHED. There is no CLIENT_AUTH acknowledgement frame; the initiator is
  ESTABLISHED once CLIENT_AUTH is sent.

Normative transitions -- responder:

- LISTEN: on CLIENT_HELLO, the endpoint selects the profile and algorithms from the
  offer, sends SERVER_HELLO and the AEAD-sealed SERVER_AUTH, and moves to WAIT_CA. No
  other frame is legal in LISTEN.
- WAIT_CA: on CLIENT_AUTH -- exactly IdentityKey, CertVerify, Finished, in that order --
  the endpoint verifies the CertVerify signature and the Finished MAC; on success it
  reaches ESTABLISHED. The responder reaches ESTABLISHED only after it has verified
  CLIENT_AUTH.

A failed AEAD open, CertVerify signature, or Finished MAC at either WAIT_SA or WAIT_CA
is a fatal handshake authentication failure: the endpoint MUST abort with the
registered code `decrypt_failed` (error registry) and derive no session keys.

Normative transitions -- keyed session (both roles):

- ESTABLISHED: application frames on any open channel are processed in place. A
  KEY_UPDATE is processed as in the Forward Secrecy and Key Update section (the epoch
  advances and a KEY_UPDATE_ACK is sent; the endpoint remains ESTABLISHED). The
  record-layer control frames MASTER_RATCHET and REKEM on the Control channel (the
  master-ratchet and re-KEM sub-protocol; registered in the frame-type registry) are
  processed in place in the same way -- each advances the ratchet, is acknowledged, and
  the endpoint remains ESTABLISHED. These REQUEST frames (KEY_UPDATE, MASTER_RATCHET,
  REKEM) are legal in ESTABLISHED and are not `unexpected_message`. The corresponding
  ACKNOWLEDGEMENT frames -- KEY_UPDATE_ACK, MASTER_RATCHET_ACK, and REKEM_ACK -- are legal
  in ESTABLISHED ONLY as the confirmation of an exchange THIS endpoint initiated: an
  endpoint that has sent the matching KEY_UPDATE (correlated per (channel, epoch)),
  MASTER_RATCHET (per generation), or REKEM processes the acknowledgement in place with
  no reaction and remains ESTABLISHED. An UNSOLICITED acknowledgement -- one for which the
  endpoint has no outstanding corresponding request -- is NOT exempt from the total
  default: it MUST be rejected with `unexpected_message` and the connection MUST be torn
  down, exactly as an unsolicited CLOSE_ACK is; an endpoint MUST NOT silently ignore it.
  Sending or receiving an authenticated CLOSE moves the endpoint to CLOSING
  (Authenticated Close).
- CLOSING: the endpoint awaits CLOSE_ACK under the CLOSE_ACK-wait timer; on CLOSE_ACK,
  or on that timer's expiry, it moves to CLOSED.
- CLOSED: terminal; no frame is processed.

Total default (normative): in any state, a frame not listed above for that state -- a
handshake frame arriving out of order, a frame from a later or earlier flight, a
repeated frame, an application frame before ESTABLISHED, or any frame of an unknown or
unexpected type -- MUST be treated as a fatal error with the registered code
`unexpected_message` (error registry), and the connection MUST be torn down. The
record-layer REQUEST frames listed above as legal for ESTABLISHED -- KEY_UPDATE and the
master-ratchet / re-KEM requests -- are "listed above for that state" and are therefore
not caught by this default; the acknowledgement frames (KEY_UPDATE_ACK,
MASTER_RATCHET_ACK, REKEM_ACK) are exempt ONLY when they confirm an exchange this
endpoint initiated -- an unsolicited acknowledgement IS caught by this default, as stated
in the ESTABLISHED transition above. The full state transitions of the master-ratchet
and re-KEM sub-protocol are given in that sub-protocol's own specification rather than in
this core state machine. An
endpoint MUST NOT silently ignore an unexpected frame and MUST NOT attempt to recover
by skipping it; "ignore" is never the reaction to an unexpected message. This is what
closes the skip / hop / repeat deviant-trace family, and the deviant-trace conformance
suite is generated from these rules.

The record-layer drop rule: the total default above governs
AUTHENTICATED frames -- frames that opened under the current traffic key. A frame that is
NOT authenticated is not an "unexpected message" and MUST NOT be treated as one. In an
ESTABLISHED keyed session, a frame that is not AEAD-protected (cleartext), a frame whose
AEAD tag fails to verify (forged or corrupted), and a frame at a sequence position other
than the one expected (a replay or a reorder) are each silently DROPPED and SHOULD be
counted as a security event, and the association SURVIVES: the endpoint reads the next
frame. An endpoint MUST NOT tear the association down on an unauthenticated frame, and
MUST NOT surface it to the application in a way that ends the association -- otherwise an
off-path attacker who can inject a single frame could end any association at will. This
is the same principle as the forged-CLOSE drop rule in the Security Considerations, and
the record-layer resilience of DTLS 1.3 ({{RFC9147}} Section 4.5.2, "invalid records
SHOULD be silently discarded, thus preserving the association") and QUIC ({{RFC9001}}
Section 6.6.2, "QUIC ignores any packet that cannot be authenticated"). A sequence AHEAD
of the expected value cannot arise from a conformant peer over the in-order transports
this document specifies (TCP + TLS 1.3, QUIC per-stream) and is treated as the same drop;
the retained-state bound is the replay window (Numeric Bounds; Replay in the Security
Considerations). This is distinct from a frame that fails to PARSE at the wire level (bad
magic, header CRC, or an out-of-range length): a framing failure means the byte stream is
no longer trustworthy on an in-order stream transport, so it is a fatal transport-level
error, not a survivable drop.
{: #record-layer-drops}

Every named code used above -- `unexpected_message`, `decrypt_failed`, `replay_detected`
(Replay), `unknown_critical_tlv` (an unknown must-understand extension TLV),
`handshake_timeout` (the handshake-completion timer), and `close_incomplete`
(teardown) -- is defined in the core error/alert registry ({{error-registry}}), which
classifies each as fatal or discard: a fatal code appears on the wire in an ERROR
frame so that a conformance test can assert the exact code, while a discard code
(`replay_detected`) names a silently-dropped frame that produces no ERROR. The
negotiated profilexKEMxAEADxsignature mode fixes exactly one legal required-message
set for the AUTH frames -- there is no "mixed-mode" transition -- and the composite
negotiation machine together with the distinct bound read-only/discovery state are
specified in the negotiation state rules that follow.

## Negotiation and the Read-Only State {#negotiation-state}

The negotiable dimensions -- profile, KEM, AEAD, and signature algorithm -- are selected
together at exactly one point, the server's SERVER_HELLO. That selection fixes one
composite mode for the connection, and the mode fixes exactly one legal
required-message set for the AUTH frames and one keyed-session behaviour. There is no
transition in which two modes are mixed, and no point after SERVER_HELLO at which a
negotiable dimension is renegotiated within the connection. Because the ProfileSelect,
KEMSelect, SigSelect, and AEADSelect TLVs of SERVER_HELLO -- and the ProfileOffer,
KEMOffer, SigOffer, and AEADOffer of CLIENT_HELLO -- are absorbed into the transcript
that both the Finished MAC and CertVerify cover ({{handshake-downgrade}}), an attacker
cannot splice one mode's messages into another mode's handshake without invalidating
the MAC. This is the composite-state-machine discipline whose absence produced the
cross-protocol downgrade attacks on earlier negotiated protocols: N-PAMP standardizes
the single mode-selection point and cryptographically binds it, rather than leaving the
multiplexer for each implementation to compose differently.

A High or Sovereign endpoint that accepts a lower selected profile under the read-only
/ capability-discovery policy exception ({{profile-negotiation}}) does NOT enter the
full ESTABLISHED state. It enters a distinct ESTABLISHED_READONLY state whose legal
event set is restricted to capability-discovery frames (the Discovery channel, 0x0010)
and to operations the endpoint's local policy classifies as read-only. A frame that
would effect a state change -- any frame the endpoint's policy does not classify as
read-only -- MUST be rejected in ESTABLISHED_READONLY with the registered code
`unexpected_message` (error registry) and MUST NOT be honored. The restriction is
cryptographically bound: the selected profile is carried in SERVER_HELLO and covered by
the transcript that Finished and CertVerify authenticate, so a peer cannot strip the
read-only restriction, nor escalate a downgraded, discovery-only association into an
effecting one, without breaking the handshake authentication. An endpoint that requires
effecting operations MUST NOT accept the downgrade; it refuses it per the profile
invariants ({{profile-negotiation}}). The precise mapping of channels and operations to
read-only versus effecting is a matter of local and companion-defined policy; the
Discovery channel (0x0010) is always read-only, and the core requirement here is that
ESTABLISHED_READONLY is a distinct, transcript-bound state that admits no effecting
frame.

## Transcript

The handshake transcript is a running byte buffer; a transcript hash is H over all
bytes absorbed so far. Unlike TLS 1.3 {{RFC9846}} Section 4.1, which hashes whole
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
HKDF-Expand-Label derivations (simpler than TLS 1.3 {{RFC9846}} Section 7.1's
three-stage chain; N-PAMP defines no PSK or 0-RTT in this binding).
HKDF-Expand-Label is as in TLS 1.3 Section 7.1 with the N-PAMP label prefix
"n-pamp " (with the trailing space) in place of "tls13 ":

~~~
HKDF-Expand-Label(Secret, Label, Context, Length) =
    HKDF-Expand(Secret, HkdfLabel, Length)
HkdfLabel = uint16(Length) || opaque("n-pamp " || Label)
                           || opaque(Context)
~~~

The KEM output ({{cryptographic-suites}}) -- the per-group combined shared secret
(64 octets for X25519MLKEM768, 80 octets for SecP384r1MLKEM1024, in the per-group
order defined there) -- is fed directly as input keying material. That combined KEM
shared secret is the only secret input to the schedule: the HKDF-Extract below is
itself the hybrid combiner (a dual-PRF), and there is no separate multi-field
combiner value. The KEM public material (encapsulation keys, ciphertexts, and the
classical public key) is bound into the schedule through the transcript hash TH_kem --
the context of the c_hs/s_hs derivations -- rather than by folding it into the Extract
input:

~~~
handshake_secret = HKDF-Extract(salt = HashLen zero octets,
                                IKM = per-group combined KEM
                                shared secret)
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
TLS 1.3 {{RFC9846}} Section 4.5.2 with N-PAMP context strings:

~~~
signing_input = (0x20 x 64) || context || 0x00 || transcript_hash
context (server) = "N-PAMP/3, server CertificateVerify"
context (client) = "N-PAMP/3, client CertificateVerify"
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

The Finished TLV (0x0B) carries an HMAC per TLS 1.3 {{RFC9846}} Section 4.5.3, keyed
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

The TLV types 0x0010, 0x0012, and 0x0013 are reserved for extension TLVs defined
in companion specifications; all three are assigned (0x0010 BridgeEnvelope, 0x0012
OpaqueContentType, 0x0013 SafetyLabel -- {{tlv-registry}}). TLV type 0x0014 remains
reserved for a companion specification but is fixed at 32 octets and handshake-only,
so it cannot carry a variable-length extension value. TLV types in the range
0x8000-0xFFFF remain reserved as forward-incompatible extension points per
{{wire-format}}.

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

IANA is requested to register the following value in the "TLS Application-Layer
Protocol Negotiation (ALPN) Protocol IDs" registry established by {{RFC7301}}:

| Protocol | Identification Sequence | Reference |
|---|---|---|
| N-PAMP, crypto generation 3 | 0x6E 0x2D 0x70 0x61 0x6D 0x70 0x2F 0x33 ("n-pamp/3") | (this document) |
{: title="ALPN registration (n-pamp/3)"}

The identification sequence is the 8-octet UTF-8 string "n-pamp/3". The trailing
digit "3" is the N-PAMP crypto generation -- the cryptographic construction (hybrid
combiner order, KEM and signature code points). It is an axis independent of the
wire-format version: the Ver nibble 0x2 in the frame header ({{wire-format}})
identifies the frame layout and is invariant across generations. A raw frame is not
generation-self-describing; the generation is fixed by ALPN negotiation, or by
explicit configuration where frames are exchanged without TLS. The registration
policy for the ALPN registry is Expert Review {{RFC8126}}.

The earlier identifiers "n-pamp/1" and "n-pamp/2" are deprecated. Implementations
SHOULD NOT negotiate them for new associations. "n-pamp/2" is the prior crypto
generation, defined by an earlier revision of this document and superseded by
generation 3. Each new crypto generation uses a distinct ALPN identifier (a future
generation would use "n-pamp/4").

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
({{frame-types}}), the TLV type registry ({{tlv-registry}}), and the error/alert code
registry ({{error-registry}}) are defined and maintained within this specification. Because this document is published through
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
| 0x0D | AEADSelect | Var (2*N) | Ordered list of the server-selected AEAD suites, primary first (2 octets per suite; N=1 at Standard, N=2 at High/Sovereign for per-frame diversification). Handshake only. |
| 0x10 | (reserved) | var | Reserved for a companion specification. |
| 0x12 | OpaqueContentType | var | Full IANA media-type string for opaque carriage, when the payload's media type is not one of the BridgeEnvelope content_type enumerated values (companion specification NPAMP-CC-OPAQUE). |
| 0x13 | (reserved) | var | Reserved for a companion specification. |
| 0x14 | (reserved) | 32 | Reserved for a companion specification (handshake only). |
| 0x15 | (reserved) | -- | Reserved; path validation uses the PATH_CHALLENGE / PATH_RESPONSE frames (0x0008 / 0x0009), not a TLV. |
| 0x16 | (reserved) | -- | Reserved; see 0x15. |
| 0x17 | KeyUpdateMarker | 8 | Key-update epoch marker. |
| 0x18 | ProtectionMode | 1 | Reserved; no defined values (header protection provided by the secure transport). |
| 0x8000-0xFFFF | (reserved) | -- | Forward-incompatible extension points (Type high bit set). |
{: title="TLV type registry"}

# Security Considerations {#security-considerations}

This section follows the spirit of {{RFC3552}}. N-PAMP inherits the security
properties of its underlying transports, TLS 1.3 {{RFC9846}} and QUIC
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
numbers. The window width SHALL be at least 64 (a floor grounded in the min-32 /
preferred-64 precedent of RFC 4303); the RECOMMENDED default is 1024 for multi-core
receivers, and a receiver MAY choose a larger window. A frame whose sequence number
is below the window, or already recorded within it, MUST be dropped as a replay (the
frame is discarded and counted, the connection survives) with the registered error
code (`replay_detected`); in-window out-of-order arrival
is NOT a replay and MUST be accepted. The window check-and-record -- testing whether
a sequence number has been seen and marking it seen -- MUST be atomic per (channel,
direction), so that a duplicate cannot slip through under concurrent receive.

This binding defines no 0-RTT / early-data mechanism: there is no PSK or 0-RTT stage
in the key schedule ({{key-schedule}}), and no frame, TLV, or key derivation carries
early data. There is therefore no early-data replay surface; all application data is
protected under the post-handshake epoch keys and covered by the replay window above.

## Forward Secrecy and Key Update {#key-update}

Endpoints MUST perform key updates within profile-specific bounds on elapsed
time, frames sent, and bytes protected, with the tightest bounds at the Sovereign
profile; the concrete per-profile numeric bounds are given in the numeric-bounds
section. On key update, the prior epoch's traffic secrets MUST be zeroized so
that compromise of the current epoch does not expose previously protected
traffic. Key update rotates only the per-epoch traffic secrets derived from the
existing master secret; rotation of the master secret itself requires a fresh
handshake.

### The KEY_UPDATE exchange

Key update is scoped to a single (channel, direction): a KEY_UPDATE rotates only
the initiating endpoint's send direction on the named channel, and each
(channel, direction) pair carries its own independent epoch counter. An epoch is a
monotonically increasing 64-bit index that starts at 0 when the handshake
completes; the sequence-number space resets to 0 at the start of each epoch, so
the (direction, epoch, suite, channel) tuple that keys the AEAD (see the key
schedule, {{key-schedule}}) changes at every epoch boundary.

To rotate its send key on a channel, an endpoint:

1. Seals a KEY_UPDATE control frame (frame type 0x0006) under the CURRENT epoch's
   send key, carrying exactly one KeyUpdateMarker TLV (0x17) -- an 8-octet
   big-endian value equal to the NEXT epoch index (current + 1) -- and no other
   TLV. This is the last frame protected under the current epoch.
2. After emitting the KEY_UPDATE frame, derives the next epoch's send secrets,
   zeroizes the retired epoch's send secrets, and resets its send sequence number
   to 0. Every subsequent frame on that (channel, send direction) MUST be
   protected under the new epoch, beginning at sequence 0.

A receiver that opens a KEY_UPDATE frame:

1. MUST verify the frame carries exactly one KeyUpdateMarker TLV of 8 octets whose
   value equals its current receive epoch + 1. A KEY_UPDATE whose marker is
   malformed (absent, not the sole TLV, or not 8 octets) or announces any epoch
   other than current + 1 MUST be rejected with the registered error code
   `key_update_out_of_order` (see the error/alert registry) and the association
   MUST be torn down; a receiver MUST NOT skip or reorder epochs.
2. On a valid marker, derives the next epoch's receive secrets, zeroizes the
   retired epoch's receive secrets, and replies with a KEY_UPDATE_ACK control
   frame (frame type 0x0007) on its own send direction, sealed under its own
   current send epoch and carrying a KeyUpdateMarker for the epoch just adopted.
   KEY_UPDATE_ACK is a confirmation signal only: an initiator MUST NOT wait for
   KEY_UPDATE_ACK before protecting frames under its new send key, and the absence
   of KEY_UPDATE_ACK MUST NOT be treated as a failure of the initiator's own
   already-completed send-side rotation.

A receiver that opens a KEY_UPDATE_ACK frame correlates it against the KEY_UPDATE it
sent on that (channel, direction). A KEY_UPDATE_ACK whose KeyUpdateMarker is malformed
(the same cases as for a KEY_UPDATE -- absent, not the sole TLV, or not 8 octets) MUST be
rejected with `key_update_out_of_order`: the marker is the same TLV on either frame. A
well-formed KEY_UPDATE_ACK that acknowledges no KEY_UPDATE the receiver actually sent --
an unsolicited acknowledgement -- MUST be rejected with `unexpected_message` (State
Machine total default), exactly as an unsolicited CLOSE_ACK is. A KEY_UPDATE_ACK that
correctly confirms an outstanding KEY_UPDATE is processed with no reaction. Correlation
is by (channel, announced epoch); because KEY_UPDATE may be pipelined, more than one
acknowledgement may be outstanding on a (channel, direction) at once, and acknowledgements
need not arrive in the order the updates were sent.

### Epoch boundary and the drain rule

The KEY_UPDATE frame is the epoch boundary: it is the final frame protected under
the old epoch and it names the new one. Two invariants keep the boundary
unambiguous and prevent an in-flight frame from being lost or opened under the
wrong keys:

- Send-side invariant: an endpoint MUST NOT protect any frame bearing a sequence
  number higher than its KEY_UPDATE frame's under the old epoch's secrets. Because
  sequence-number assignment on a (channel, direction) is atomic and
  single-writer (see the key-schedule and nonce rules), the KEY_UPDATE frame is by
  construction the highest-sequence frame of its epoch, so no later frame can be
  sealed under the retired secrets.
- Receive-side drain rule: a receiver MUST retain the old epoch's receive secrets
  until it has opened the KEY_UPDATE frame that closes that epoch, and MUST NOT
  apply the new epoch's receive secrets to any frame that precedes the KEY_UPDATE
  boundary. Over a transport that delivers each (channel, direction) in order --
  the transports specified by this document -- the KEY_UPDATE frame is the last
  old-epoch frame, so every old-epoch frame has already been opened when the
  boundary is reached, and the old receive secrets are zeroized at that point.
  Over a transport that may reorder frames across the boundary, a receiver MUST
  retain the old epoch's receive secrets until a frame of the new epoch has been
  successfully opened -- a window bounded by the replay window so that retention is
  finite -- and then zeroize them, so that an old-epoch frame arriving after the
  KEY_UPDATE is still opened rather than dropped.

In both cases the retired secrets are zeroized, not merely released, once they can
no longer be needed. This preserves forward secrecy: a later compromise of the
current epoch's secrets recovers no traffic protected under any prior epoch.

## Connection-Level Flow Control {#flow-control}

A receiver bounds how much a peer may send it, connection-wide, with the FLOW_UPDATE
control frame (`0x000A`). This is the connection-level tier of a two-level flow-control
model that a Multi-stream channel companion composes with its own per-sub-stream credit
(for example NPAMP-STREAM's STREAM_WINDOW_UPDATE): the credit a sender may consume at any
instant is the smaller of the connection-level limit defined here and any per-sub-stream
limit a companion defines.

FLOW_UPDATE is an all-channel control frame carried on the Control channel (`0x0000`). Its
body is exactly one 8-octet big-endian unsigned integer -- the sender's new connection-level
receive limit: the maximum cumulative count of frame-payload octets (the octets after each
36-octet header, i.e. the frame body and its 16-octet AEAD tag) that the FLOW_UPDATE
recipient MAY have transmitted across all application channels since the connection was
established. Frames on the Control channel (`0x0000`) -- the handshake, KEY_UPDATE,
FLOW_UPDATE, CLOSE, PING, and the master ratchet -- are exempt and never count against the
limit, so a full application-data window can never starve the essential control exchange (a
sender can always send a KEY_UPDATE, a CLOSE, or a FLOW_UPDATE of its own). The body is
AEAD-sealed like any keyed frame; a FLOW_UPDATE whose body is not exactly 8 octets is
malformed and is rejected with `unexpected_message`.

The limit only increases. A FLOW_UPDATE whose value is less than or equal to the current
effective limit does not lower it and has no other effect (it MAY be re-sent to re-assert a
limit). A limit is never reduced on the wire; to slow a peer, a receiver withholds further
FLOW_UPDATE frames.

The limit is per direction: each peer advertises its own receive limit and independently
tracks the other peer's advertised limit against its own cumulative send total. Before the
first FLOW_UPDATE in a direction, the effective limit is the fixed initial connection window
in {{numeric-bounds}}.

A sender MUST NOT transmit an application-channel frame that would push its cumulative
sent-payload total above the current limit; it waits for a FLOW_UPDATE that raises the limit (a transfer larger than
the current window, including a single large frame, therefore requires the receiver to grant
credit first). A receiver that observes a peer's cumulative received-payload total exceed the
limit it advertised MUST treat it as `flow_control_error` (fatal, {{error-registry}}) and
tear the connection down -- the violation is computable by both sides from the same sealed
frames. Flow control bounds volume only; sequence numbers, the replay window, and frame
ordering are unaffected.

This revision defines the connection-level mechanism and its wire frame. A reference
implementation of FLOW_UPDATE emission and enforcement, with conformance vectors, is tracked
for the implementation-completeness phase.

## Numeric Bounds and Timers {#numeric-bounds}

This section collects the operational limits an implementation MUST enforce so that
two builds agree on accept/reject and no length or count is a resource-exhaustion
surface. Every bound carries a named rejection.

| Bound | Value | On violation |
|---|---|---|
| Maximum frame size (header + payload) | 16 MiB (2^24 octets) | Rejected at parse time (before the frame is opened); a keyed receiver MAY report `unexpected_message` before teardown. The base parser and the SDK enforce this same cap. |
| Maximum TLV count per frame | 64 | Reject the frame (`unexpected_message`). |
| Maximum CBOR nesting depth (bodies) | 8 | Reject the body as malformed (`unexpected_message`). |
| Replay-window width | 64 floor, 1024 default (Replay) | Below-window or duplicate is a `replay_detected` discard. |
| Connection-level initial receive window | 1 MiB (2^20 octets) per direction | A sender exceeding it before a FLOW_UPDATE ({{flow-control}}) raises the limit is a `flow_control_error`. |
{: title="Size and count bounds"}

The maximum frame size is a receiver-side hardening applied before a frame is opened:
because the Payload Length field is a 32-bit value (up to roughly 4 GiB), a receiver
MUST reject a frame whose declared total size exceeds 16 MiB before waiting to buffer
it, so a hostile length cannot pin the reader.

Key-update triggers are per profile. An endpoint MUST perform a key update before the
earliest of these bounds is reached, and always before the negotiated AEAD's usage
limit ({{cryptographic-suites}}); the bounds tighten with the profile:

| Profile | Max elapsed time | Max frames per epoch | Max bytes per epoch |
|---|---|---|---|
| Standard | 7 days | 2^24 | 2^40 |
| High | 1 day | 2^22 | 2^36 |
| Sovereign | 1 hour | 2^20 | 2^32 |
{: title="Per-profile key-update triggers"}

These are ceilings; an implementation MAY update sooner. They sit within the AEAD
confidentiality and integrity limits ({{RFC9846}} Section 5.5), so a key is retired
well before its safety margin.

Each timer is a normative block with all six slots plus an explicit clock granularity.
The granularity is 1 ms for every timer, so two implementations differ by at most one
tick on any comparison.

Handshake completion:

- Initial: profile-set (e.g. 10 s). Floor: 1 s. Ceiling: 60 s.
- Start: on CLIENT_HELLO. Stop / restart: on ESTABLISHED.
- On expiry: abort with `handshake_timeout`.

Idle / liveness:

- Initial: profile-set. Floor: none. Ceiling: none.
- Start: last frame sent or received. Stop / restart: any frame (restart).
- On expiry: send a keepalive (PING) or CLOSE.

Key-update-due:

- Initial: per-profile bounds above. Floor: none. Ceiling: tightest at Sovereign.
- Start: epoch start. Stop / restart: on completing a KEY_UPDATE.
- On expiry: trigger a key update.

CLOSE_ACK-wait:

- Initial: profile-set. Floor: 1 s. Ceiling: 60 s.
- Start: on sending CLOSE. Stop / restart: on receiving CLOSE_ACK.
- On expiry: force teardown, record `close_incomplete`.

(Protocol timers; clock granularity 1 ms for every timer.)

## Anti-Amplification and Reflection

N-PAMP's post-quantum handshake is large and asymmetric: a server's first
authentication flight carries the KEMCiphertext (up to 1665 octets at the Sovereign
profile), the server IdentityKey (an ML-DSA-87 public key is 2592 octets), and the
CertVerify signature (an ML-DSA-87 signature is 4627 octets), so it can be several
times the size of the client's opening HELLO. An attacker that spoofs a victim's
source address could therefore attempt to use an N-PAMP responder as a
reflection/amplification vector against that victim.

N-PAMP does not define its own address-validation mechanism; it relies on the
address validation of its underlying transport, and MUST NOT be deployed over an
unvalidated datagram transport that provides none.

* Over QUIC {{RFC9000}}, the transport's anti-amplification limit applies before
  N-PAMP's authentication flight can reach an unvalidated peer: prior to validating
  the client address, a server MUST NOT send more than three times as many bytes as
  it has received from that address ({{RFC9000}}, Section 8.1). Because a
  Sovereign-profile authentication flight can exceed that budget, QUIC's own address
  validation (a Retry token, {{RFC9000}} Section 8.1) gates the large response: it
  flows only to an address that has already been validated.
* Over TCP with TLS 1.3, the peer's address is validated by the TCP three-way
  handshake before any N-PAMP frame is exchanged, so a responder never sends an
  authentication flight to an unvalidated address.

Deployments therefore rely on the transport's address validation rather than on the
first flight fitting within an unvalidated-address budget; an operator MUST NOT carry
N-PAMP over a transport that omits address validation.

## Connection Migration

When carried over QUIC, an endpoint MUST validate a peer's new path with a
challenge-response exchange before accepting an address change, to prevent off-path
migration spoofing. The exchange uses the PATH_CHALLENGE (0x0008) and PATH_RESPONSE
(0x0009) control frames; path validation is carried by these frames only, never by a
TLV.

## Authenticated Close

The acknowledged CLOSE / CLOSE_ACK teardown, its timer, and in-flight-frame
disposition are specified in the CLOSE Frame section. CLOSE and CLOSE_ACK are
AEAD-protected and MUST be verified before being honored, so that an off-path attacker
cannot tear down an association with a forged CLOSE.

## Extension Points {#sec-extension-points}

The reserved code-point ranges in {{extension-points}} carry no algorithms or
semantics in this document. Any security properties of extensions occupying those
ranges are the responsibility of the companion specifications that define them and
are out of scope here.

## Implementation Considerations

Where the wire format requires deterministic encoding, implementations MUST follow
the Deterministic Encoding Profile ({{det-encoding}}) so that identical inputs
produce byte-identical output; non-deterministic or non-conformant encodings can
invalidate transcript and integrity computations across peers.

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
  order is per-group, placing the FIPS-approved component first per NIST SP 800-56C
  Rev. 2 (see {{SP800-56C}}) to match {{RFC10024}}: X25519MLKEM768 is
  ML-KEM-first (ML-KEM_SS || X25519_SS) and SecP384r1MLKEM1024 is ECDHE-first
  (ECDHE_SS || ML-KEM_SS). This replaces the X25519-first order of draft-00, changes
  the derived keys, and is NOT interoperable with draft-00.
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
- ALPN identifier and versioning (wire-breaking). The crypto generation is carried by
  the ALPN identifier, now "n-pamp/3", decoupled from the wire-format version (the Ver
  nibble, which stays 0x2). Because the CertVerify context string tracks the crypto
  generation, it moves to "N-PAMP/3, {server,client} CertificateVerify" and every
  CertVerify signature and downstream transcript point changes. "n-pamp/2" (the prior
  generation) is deprecated; IANA is requested to register "n-pamp/3". The "npamp" URI
  scheme is unchanged (it carries no version token; the generation is negotiated via
  ALPN).
