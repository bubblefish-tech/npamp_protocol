# IANA Registration Requests: n-pamp/2 (ALPN) and npamp:// (URI scheme)

This file collects the two IANA registration actions for the Native Post-Quantum
Agent Messaging Protocol (N-PAMP), so both are documented together:

1. ALPN protocol identifier "n-pamp/2" (RFC 7301, Section 6 template).
2. Provisional "npamp" URI scheme (RFC 7595 template).

Both actions are also requested in the IANA Considerations of the referenced
Internet-Draft; this file restates them in registry-template form for direct
submission to IANA.

# 1. ALPN Protocol-ID Registration Request: n-pamp/2

## Registration Template (RFC 7301, Section 6)

### Protocol

Native Post-Quantum Agent Messaging Protocol, wire major version 2 (N-PAMP).

N-PAMP is a binary, multi-channel, wire-level protocol for authenticated
communication between autonomous software agents, carried over QUIC (primary)
or TCP with TLS 1.3 (fallback). This ALPN identifier registers the wire major
version family. The trailing digit "2" equals the protocol's wire major version,
i.e., the value 0x02 carried in the Ver field of the N-PAMP frame header.
Wire-compatible revisions within the version-2 family use this same ALPN
identifier without renegotiation.

### Identification Sequence

The identification sequence is the 8-octet UTF-8 string "n-pamp/2".

Octets (hexadecimal):

```
0x6E 0x2D 0x70 0x61 0x6D 0x70 0x2F 0x32
```

UTF-8 string:

```
n-pamp/2
```

Length: 8 octets.

For reference, the octet-to-character mapping is:

| Octet | Character |
|---|---|
| 0x6E | n |
| 0x2D | - |
| 0x70 | p |
| 0x61 | a |
| 0x6D | m |
| 0x70 | p |
| 0x2F | / |
| 0x32 | 2 |

### Reference

draft-bubblefish-npamp-00 (Internet-Draft, Independent Submission stream,
category Informational), which specifies the N-PAMP wire format, channel
architecture, profile negotiation, and cryptographic suites, and contains the
IANA Considerations requesting this ALPN registration. Upon publication, the
reference is to be updated to the assigned RFC number.

## Registration Policy

Per Section 6 of RFC 7301, ALPN protocol identifiers are registered under the
Expert Review policy (RFC 8126). The Designated Expert(s) verify that:

- the identification sequence is unique within the ALPN registry;
- the specification describing the protocol is available; and
- the protocol is a genuine application-layer protocol that benefits from ALPN
  negotiation.

This request is submitted on that basis. The string "n-pamp/2" is, to the
requester's knowledge, not currently present in the ALPN registry.

## Deprecation of n-pamp/1

An earlier identifier, "n-pamp/1", was used by the wire major version 1 family of
N-PAMP. It is deprecated.

- New associations SHOULD NOT negotiate "n-pamp/1".
- Endpoints SHOULD prefer "n-pamp/2" in their ALPN offer.
- The two identifiers denote distinct, separately negotiated wire major versions;
  "n-pamp/2" is not wire-compatible with "n-pamp/1".

Future wire major versions will use distinct ALPN identifiers (for example,
"n-pamp/3"), each registered separately.

# 2. URI Scheme Registration Request: npamp:// (RFC 7595)

This is a provisional registration request for the "npamp" URI scheme, formatted
per the template of RFC 7595. Provisional registrations use the First Come First
Served policy.

**Scheme name:** npamp

**Status:** Provisional

**Applications/protocols that use this scheme:** N-PAMP (the protocol specified in
the referenced Internet-Draft). An "npamp" URI names an N-PAMP endpoint and an
optional resource path within that endpoint.

**URI scheme syntax (RFC 3986 generic syntax):**

```
npamp-URI = "npamp://" authority path-abempty [ "?" query ]
```

where "authority", "path-abempty", and "query" are as defined in RFC 3986. The
"authority" component identifies the N-PAMP endpoint (host and optional port).
N-PAMP does not reserve a fixed default port; the transport is negotiated as
described in the referenced Internet-Draft.

**Encoding considerations:** Processed per RFC 3986; non-ASCII characters in the
path or query are percent-encoded UTF-8 octets.

**Interoperability considerations:** None beyond those of RFC 3986. The scheme
carries no protocol semantics of its own; behavior is defined by N-PAMP.

**Security considerations:** An "npamp" URI is only an identifier. Connecting to an
"npamp" endpoint invokes the N-PAMP handshake and its authentication,
confidentiality, and downgrade protections; dereferencing an "npamp" URI must not
bypass the security profile negotiated by N-PAMP. See the Security Considerations
of the referenced Internet-Draft.

**Contact:** Shawn Sammartano, BubbleFish Technologies, Inc

**Change controller:** Shawn Sammartano, BubbleFish Technologies, Inc

**Reference:** draft-bubblefish-npamp-00 (to be updated to the assigned RFC number
upon publication).

# 3. Notes

- N-PAMP uses QUIC as its primary transport. The ALPN identification sequence is
  carried in the TLS 1.3 handshake within QUIC connection establishment to
  negotiate N-PAMP as the application protocol.

- TCP with TLS 1.3 is supported as a fallback transport. The same ALPN
  identification sequence is carried in the TLS ClientHello for TCP connections.

- N-PAMP frames use a fixed 36-octet header followed by optional TLV extensions
  and an AEAD-protected payload, as specified in the referenced Internet-Draft.
