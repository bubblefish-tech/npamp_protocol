# N-PAMP-01 — URI Scheme `npamp://` (reference)

> **Derived extract.** Authoritative source: `../ietf/draft-bubblefish-npamp-latest.md`
> (revision draft-bubblefish-npamp-01; integrity pinned in ../PIN.json), §9.2 "URI Scheme Registration". The draft governs.

Provisional registration of the **`npamp`** URI scheme in the "Uniform Resource
Identifier (URI) Schemes" registry, following RFC 7595 (First Come First Served).

- **Scheme name:** `npamp`
- **Status:** Provisional
- **Applications/protocols:** N-PAMP. An `npamp` URI names an N-PAMP endpoint and an
  optional resource path within that endpoint.
- **Syntax (generic RFC 3986 syntax):**

  ```abnf
  npamp-URI = "npamp://" authority path-abempty [ "?" query ]
  ```

  `authority` identifies the N-PAMP endpoint (host and optional port). N-PAMP does
  **not** reserve a fixed default port; the underlying transport is negotiated.
- **Encoding:** processed per RFC 3986; non-ASCII path/query octets are
  percent-encoded UTF-8.
- **Interoperability:** none beyond RFC 3986; the scheme carries no protocol
  semantics of its own.
- **Security:** an `npamp` URI is only an identifier. Connecting invokes the N-PAMP
  handshake and its authentication, confidentiality, and downgrade protections;
  dereferencing MUST NOT bypass the negotiated security profile.
- **Contact / Change controller:** Shawn Sammartano, BubbleFish Technologies, Inc.
