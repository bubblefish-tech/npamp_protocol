# Public-LLM egress: PQC-vs-classical hops and self-secured-object compensation

Reviewed doc, no code. Scope: an
N-PAMP mesh workload that must call a **public** LLM provider (a hosted
API — e.g. `api.openai.com`, `api.anthropic.com` — outside the mesh's trust
domain) as opposed to an in-mesh or self-hosted model reachable over N-PAMP
end to end.

## The problem this doc scopes

Every hop this build protects with N-PAMP's hybrid-PQC handshake requires
BOTH ends to speak N-PAMP. A public LLM provider does not, and will not —
it is a third-party HTTPS API a mesh operator does not control and cannot
require to run this protocol. So a real deployment's traffic to a public
LLM necessarily has at least one classical-TLS-only hop. This doc names
exactly which hop, for which traffic type, and states what still protects
the payload across that hop — so "the LLM call isn't PQC" is a precisely
scoped, honest statement instead of an unbounded one.

## Per-traffic-type hop table

| Traffic type | Hop 1: workload -> node agent / waypoint | Hop 2: node agent -> mesh egress point | Hop 3: mesh egress -> public LLM provider |
|---|---|---|---|
| **In-mesh agent-to-agent** (MCP/A2A over `NPAMP-CC-JSONRPC`) | N-PAMP hybrid-PQC (`nz_agent::tunnel` mux over a live `npamp::session::Session`) | N-PAMP hybrid-PQC (same session, no re-encryption) | N/A — never leaves the mesh |
| **Agent-to-self-hosted-model** (a model the operator runs inside the mesh, `NPAMP-CC-HTTP` or `NPAMP-CC-STREAM`) | N-PAMP hybrid-PQC | N-PAMP hybrid-PQC | N/A — never leaves the mesh |
| **Agent-to-public-LLM, request/response** (`NPAMP-CC-HTTP`) | N-PAMP hybrid-PQC | N-PAMP hybrid-PQC, to the mesh's designated egress waypoint/gateway | **Classical TLS 1.3 only** (the provider's own endpoint; no N-PAMP peer exists past this point) |
| **Agent-to-public-LLM, streaming** (`NPAMP-CC-STREAM`, e.g. SSE token streaming) | N-PAMP hybrid-PQC | N-PAMP hybrid-PQC, to egress | **Classical TLS 1.3 only**, same boundary as above — a streamed response is still bytes over the same classical hop, not a separate risk class |
| **Agent-to-public-LLM via agentgateway `appProtocol: npamp` backend (if/when upstream connection-type support lands)** | N-PAMP hybrid-PQC | N-PAMP hybrid-PQC to the gateway | Still **classical TLS only** past the gateway — the connection type protects the hop INTO the gateway/mesh edge, it cannot make a third-party provider speak N-PAMP it never agreed to |

**The one universal fact this table encodes:** the classical-TLS-only hop
is always the LAST hop, and always exactly one hop — the mesh egress point
to the public provider's own TLS endpoint. Every hop this deployment
controls (workload to node agent, node agent to egress) stays hybrid-PQC
regardless of destination; nothing about calling a public LLM ever
downgrades an IN-MESH hop.

## What "self-secured object" compensation means here

An N-AALP object crossing this boundary is not merely "some bytes inside a
TLS tunnel" — it carries its own COSE-signed envelope, `effect`-class,
`audience`, and identity fields, verified independent of whatever
transport carried it (see `impl/rust/nz-agent/src/waypoint.rs`'s
`EffectClass`/`AuthzHook`/`authorize()` — the same effect-class/audience
lattice this mesh's own `ext_authz` composition enforces at
the gateway). This is the property that COMPENSATES for the classical-only
last hop:

- **Confidentiality of the transport is lost past the egress point**
  (classical TLS only, not PQC) — a "harvest now, decrypt later" adversary
  who records ciphertext at that hop and later breaks classical crypto
  recovers the RAW BYTES of the request/response.
- **What that adversary does NOT get for free:** the object's own N-AALP
  signature is verifiable independent of the transport that carried it —
  it does not re-derive its integrity from TLS. Where a workload's
  agreement includes it (a design decision this build does not make
  unilaterally — see "What this doc does not decide" below), a
  content-addressed digest or a signed acknowledgment of the object sent to
  a public LLM can be recorded and verified by the ORIGINATING mesh side
  without trusting anything the classical-TLS hop or the provider says
  about what it received.
- **What self-secured-object compensation is NOT:** it is not equivalent
  PQC confidentiality. A signature proves who sent/received an object and
  that it was not altered; it does not make the request/response CONTENT
  resistant to a future classical-break disclosure. This doc does not
  claim otherwise — see "Honest limits" below.

## Honest limits (what this doc does NOT claim)

- This doc does not claim any mechanism makes the classical-TLS-only hop
  PQC-safe. It cannot be, without the public provider adopting N-PAMP —
  outside this build's control (a native `npamp` backend on the mesh side
  changes nothing about what the third-party provider speaks).
- This doc does not specify a NEW wire mechanism for "self-secured-object
  compensation" — it names the EXISTING N-AALP object properties
  (signature, effect-class, audience) already carried end to end by this
  mesh's carriage classes, and states precisely what they do and do not
  buy across a classical-only hop. Whether/how a deployment additionally
  logs or escrows a pre-egress digest for later verification is an
  operational/policy decision this doc scopes but does not make.
- Per-key-material exposure duration at the classical hop (how long a
  harvested ciphertext remains valuable before classical crypto is
  actually broken) is outside this doc's scope — that is a cryptographic
  timeline question, not a mesh-architecture one.

## Where this composes with already-built work

- The carriage classes named above (`NPAMP-CC-HTTP`, `NPAMP-CC-STREAM`,
  `NPAMP-CC-JSONRPC`) are already specified (`spec/companion/{20,21,23}_*`)
  and implemented (`impl/go/proxy/carriage_*.go`).
- The effect-class/audience lattice this doc cites as the self-secured
  object's own authorization surface is the same core `ext_authz` service
  (`impl/rust/nz-agent-extauthz`) enforces at the
  gateway boundary — this doc's "self-secured object" language is not a
  new concept, it names what that already-built,
  mutation-tested authorization core already checks.
- This build's connector work protects exactly Hop 1/Hop 2 in the table above
  for the `appProtocol: npamp` backend-dial case — this doc is the
  companion document naming what those hops do NOT cover (Hop 3), so the
  two pieces of work read as one coherent picture rather than two
  unrelated claims.
