# NEP-0000 — The N-PAMP Enhancement Proposal Process

| | |
|---|---|
| **NEP** | 0000 |
| **Title** | The N-PAMP Enhancement Proposal Process |
| **Author** | Shawn Sammartano, BubbleFish Technologies, Inc. (`npamp-editor@bubblefish.sh`) |
| **Type** | Process |
| **Status** | Active |
| **Created** | 2026-07-13 |
| **Requires** | — |
| **Supersedes** | — |
| **Discussion** | GitHub issues/PRs on this repository, label `nep` |

> This is a **meta-NEP**: it defines the NEP process itself, and it is never
> "completed". Like it does for the meta-documents of the projects it draws on
> (Python's PEP 1, the Rust RFC `README`, the Kubernetes KEP `README`), the
> `Active` status marks a Process document that stays in force until a later
> NEP supersedes it.

This process operates within the project's governance model:
[`GOVERNANCE.md`](../GOVERNANCE.md) defines who decides and by what rule — a NEP is
the proposal-scale container for the normative-change process in its §4 — and
[`MAINTAINERS.md`](../MAINTAINERS.md) lists the maintainers who review a NEP and
help enforce its §6 Final gate.

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHALL NOT**,
**SHOULD**, **SHOULD NOT**, **RECOMMENDED**, **MAY**, and **OPTIONAL** in this
document are to be interpreted as described in BCP 14 (RFC 2119, RFC 8174) when,
and only when, they appear in all capitals.

---

## Abstract

A **NEP** (N-PAMP Enhancement Proposal) is the design document a contributor
writes to propose, justify, and specify a substantial change to N-PAMP: a new
companion specification, a new channel, a new carriage class, a change that
alters bytes on the wire, or a new code-point range or registration policy. The
NEP is where the *why*, the *considered alternatives*, the normative
*specification text*, and the *evidence that the change is implementable and
gradable* are gathered in one reviewable place before the change lands in the
draft, the registries, or the reference implementations.

This document defines what a NEP is, when one is REQUIRED versus when a smaller
change may proceed with only a pull request and an Architecture Decision Record
(ADR); the NEP lifecycle (`Draft → Review → Accepted / Rejected → Final /
Withdrawn`); the sections every NEP MUST contain; the numbering and directory
convention (`process/NEP-NNNN-slug.md`); and — the load-bearing rule of this
process — that **a NEP MUST NOT reach `Final` until it has at least one working
reference implementation AND machine-gradable conformance vectors.** A NEP that
specifies behavior but ships no implementation and no vectors is at most
`Accepted`; it is never `Final`. That rule is what keeps N-PAMP a protocol whose
every normative claim is backed by executable evidence rather than prose.

The NEP process sits *above*, and feeds, the three-layer decision history that
[`CONTRIBUTING.md`](../CONTRIBUTING.md) already defines (ADRs in
[`decisions/`](../decisions/), the in-draft change log, and issue/PR labels). It
does not replace any of them.

## Motivation

This repository already records decisions well. `CONTRIBUTING.md` defines a
three-layer history — a MADR 4.0 ADR for every substantive decision, a per-revision
change-log appendix in the draft, and `design`/`editorial` issue labels per RFC
8874. That machinery is excellent for capturing *what was decided and why after
the fact*.

What it does not provide is a **container for a proposal that is too large for a
single ADR** — a change that touches the wire format, introduces a whole new
companion specification, or opens a new code-point range, and therefore needs
its own motivation, its own considered-options analysis, backwards-compatibility
reasoning, a reference implementation, and conformance vectors, all reviewed as
one unit before it lands. An ADR is a paragraph-scale record of a decision; a
NEP is the document-scale proposal that *produces* one or more ADRs when it is
accepted.

Every comparable protocol/standards project reached the same conclusion and
built the same kind of instrument:

- The **IETF** distinguishes an editorial nit (fixed in the next revision) from
  a normative change that alters interoperability and must be argued on its
  merits (RFC 2026 process; RFC 7282 rough consensus; RFC 8126 for registry
  changes). N-PAMP is offered through the IETF **Independent Submission** stream
  (RFC 4846), where the document author/editor — not a working-group vote — is
  responsible for each decision.
- **Python** created **PEP 1**: a numbered proposal with a fixed set of headers
  and sections, a `Draft → Accepted → Final` lifecycle, and the explicit rule
  that *"the reference implementation must be completed before any PEP is given
  status 'Final'."*
- **Rust** created the **RFC process**: a Markdown proposal, a template
  (Summary/Motivation/Guide-level/Reference-level/Drawbacks/Alternatives/Prior
  art/Unresolved/Future), a Final Comment Period, and a hard separation between
  an *accepted* RFC and the *implementation* that a separate tracking issue
  chases — "being 'active' is not a rubber stamp".
- **Kubernetes** created the **KEP process**: a numbered directory per proposal,
  maturity stages, and graduation gates that *require tests* — for a feature to
  reach GA, "the graduation criteria must include conformance tests" and "all GA
  endpoints must be hit by conformance tests".

The NEP process adopts the parts of these that fit an Independent-Submission,
single-editor, evidence-first protocol repo, and rejects the parts that assume a
working group or a multi-maintainer vote. In particular, from PEP 1 and KEP it
takes the principle that **a proposal is not "done" until it is implemented and
independently graded**, and binds that principle to the assets this repository
already ships: ten reference implementations and a pinned, standards-anchored
conformance corpus.

## Specification

### 1. What a NEP is

A NEP is a Markdown document in [`process/`](.), numbered `NEP-NNNN`, that
proposes and specifies one coherent change to N-PAMP and carries it from idea to
implemented, graded reality. A NEP has one **Author** (who MAY be the document
editor) and a single **Status** at any time. Its normative specification text,
once the NEP is `Accepted`, is merged into the governing document it targets (the
Internet-Draft, a companion specification, or a registry); the NEP remains as the
durable record of the proposal and its rationale.

There are three **types** of NEP (the PEP 1 taxonomy):

| Type | Purpose | Example |
|---|---|---|
| **Standards Track** | Adds or changes normative, on-the-wire or registry behavior. | A new channel; a new carriage class; a wire-format change; a new code-point range. |
| **Informational** | Describes a design issue, guideline, or convention without changing normative behavior. | A cross-implementation style guide; a worked-example convention. |
| **Process** | Changes how the project itself operates. | This document (NEP-0000); a change to the review workflow. |

Only **Standards Track** NEPs are subject to the reference-implementation and
conformance-vector gates for `Final` (§6). Informational and Process NEPs use the
reduced lifecycle of §5.5.

### 2. When a NEP is REQUIRED

A change **MUST** be proposed as a Standards Track NEP if it does any of the
following:

1. **Adds or removes a companion specification** — a new `spec/companion/*.md`
   document (a new carriage class, a new native-channel operations spec, a new
   discovery or identity companion, or a new per-protocol mapping that
   introduces a *new carriage class*; a thin mapping onto an **existing**
   carriage class is a §3 registration, not a NEP).
2. **Adds, removes, or repurposes a channel** — any change to
   [`registries/channels.csv`](../registries/channels.csv) that assigns a new
   channel code point, changes a channel's purpose, or changes a channel's
   minimum profile.
3. **Adds or changes a carriage class** — any change to the set of carriage
   classes defined by NPAMP-BRIDGE and its companions.
4. **Is wire-affecting** — anything an interoperating implementation must change
   its byte-level behavior to accommodate: the 36-octet header geometry, the
   magic value, the header CRC, the frame-type number space, the TLV number
   space, the handshake flights/transcript/key-schedule, the profile parameter
   rows, or the AEAD/KEM/signature suite set. `CONTRIBUTING.md` already flags
   these as **major-version** changes (a new ALPN identifier, e.g. `n-pamp/3`);
   such a change **MUST** be carried by a NEP.
5. **Opens or re-policies a code-point range** — creating a new registry,
   adding a new range to an existing registry, or changing a range's
   **registration policy** (for example, converting a range from
   "Specification Required" to "Experimental", per RFC 8126). Registries in
   scope include [`channels.csv`](../registries/channels.csv),
   [`frame_types_reserved.csv`](../registries/frame_types_reserved.csv),
   [`tlv_tags.csv`](../registries/tlv_tags.csv),
   [`profiles.csv`](../registries/profiles.csv),
   [`kem.csv`](../registries/kem.csv), [`aead.csv`](../registries/aead.csv),
   [`signatures.csv`](../registries/signatures.csv), and
   [`bridge_protocol_ids.csv`](../registries/bridge_protocol_ids.csv).

This mirrors the Rust "substantial change" trigger and the KEP "non-trivial
change" trigger: a NEP is for changes that other implementers must reason about,
not for changes visible only to this repository's editors.

### 3. When a NEP is NOT required

The following changes proceed through the existing pull-request + ADR path in
`CONTRIBUTING.md` and **MUST NOT** be inflated into a NEP:

1. **Editorial fixes** — wording, formatting, examples, typo/`idnits` cleanup,
   or non-normative clarification (the `editorial` label of `CONTRIBUTING.md`).
2. **A single additive code-point registration within an existing range whose
   policy already permits it** — e.g. registering one new `protocol_id` in the
   `bridge_protocol_ids` "Specification Required" range `0x05-0x0F`
   ([`bridge_protocol_ids.csv`](../registries/bridge_protocol_ids.csv)), or one
   new suite value in an additive registry. Per RFC 8126, a Specification
   Required registration needs a stable public specification reviewed by the
   designated expert, **not** a NEP. Such a registration still gets an ADR and a
   change-log bullet.
3. **A thin per-protocol mapping onto an already-defined carriage class** — e.g.
   a new `NN_map_*.md` that reuses JSONRPC/HTTP/MSG/STREAM/DOC/OPAQUE. It is a
   registration (item 2) plus a short document; it needs a NEP only if it
   introduces a *new* carriage class (§2.3).
4. **Reference-implementation-only changes** — bug fixes, refactors, added
   language ports, or test additions that do not change any normative document,
   registry, or vector.
5. **Non-normative repository mechanics** — CI, scripts, tooling, or pin/manifest
   maintenance that changes no normative artifact.

> Rule of thumb, taken from Rust: if the change "changes shape but not meaning"
> for an interoperating peer, it is not a NEP. If a conforming implementation on
> the other end of a connection would have to change to keep interoperating, it
> is.

When in doubt, open an issue labelled `nep` and ask the editor; the editor
decides whether a NEP is REQUIRED before any specification text is merged.

### 4. Numbering and directory convention

1. NEPs live in [`process/`](.) and are named `NEP-NNNN-slug.md`, where `NNNN`
   is a **4-digit, zero-padded** integer and `slug` is a short lowercase,
   dash-separated phrase (e.g. `process/NEP-0007-knowledge-channel-provenance.md`).
2. `NEP-0000` (this document) is the meta-NEP. Numbers are assigned **in
   ascending order** by the editor when a Draft is first accepted for the queue
   (the number is the proposal's identity for its whole life; it is **not** the
   GitHub PR number, to keep NEP numbers stable and gap-free).
3. A NEP's number **MUST NOT** be reused, even if the NEP is `Rejected` or
   `Withdrawn`; a withdrawn number is retired with the NEP.
4. Each NEP begins with the metadata table shown at the top of this document
   (NEP, Title, Author, Type, Status, Created, Requires, Supersedes, Discussion)
   and MAY add `Replaces`/`Superseded-By` when relevant.

### 5. The NEP lifecycle

```
                 editor queues it
   (author writes)      │
        Draft ──────────┴────────► Review ──────► Accepted ──────► Final
          │                          │               │  \             ▲
          │ author abandons          │ editor        │   \  (ref impl │
          ▼                          ▼ rejects       │    \  + vectors│
      Withdrawn                  Rejected             │     \   land)  │
          ▲                          ▲                │      └─────────┘
          └──────── author can withdraw at any pre-Final state ────────┘
```

The states, grounded in PEP 1 (`Draft → Accepted → Final`, plus
`Rejected`/`Withdrawn`) and the Rust RFC flow (draft → Final Comment Period →
accepted; postponed/closed):

#### 5.1 Draft
The author is actively writing. A NEP enters `Draft` when it is opened as a pull
request adding `process/NEP-NNNN-slug.md`. A Draft may change freely. It carries
no normative weight; nothing may cite a `Draft` NEP as settled.

#### 5.2 Review
The author has declared the NEP ready and the editor has opened the review
window. Discussion happens on the issue/PR under the `nep` label; the editor
seeks **rough consensus** in the RFC 7282 sense — objections are addressed on
their **technical merits**, not counted as votes ("consensus is when everyone is
sufficiently satisfied with the chosen solution, such that they no longer have
specific objections to it"). Analogous to the Rust **Final Comment Period**, the
review window is announced and stays open **at least ten calendar days** so that
reviewers in any time zone have a fair chance to object. The window is a floor,
not a ceiling; the editor extends it while substantive objections remain
unresolved.

#### 5.3 Accepted
The editor judges that rough consensus is reached and the **design** is sound,
and moves the NEP to `Accepted`. Because N-PAMP is an Independent Submission
(RFC 4846), acceptance is the **editor's deliberate decision**, informed by
consensus but not bound to a tally — consistent with `CONTRIBUTING.md`
("acceptance of a normative change is a deliberate editorial decision, not an
automatic merge").

On acceptance, the NEP's normative text is merged into its target document, and
the change is recorded in the existing three layers of `CONTRIBUTING.md`:
- **(1)** one or more MADR 4.0 ADRs in [`decisions/`](../decisions/) (the NEP
  cites the ADR number(s); the ADR cites the NEP);
- **(2)** a change-log bullet in the draft's `## Changes Since …` appendix; and
- **(3)** the closing/consensus labels on the issue/PR.

`Accepted` means **the design is ratified**. It does **not** mean the change is
proven implementable. Per §6, a Standards Track NEP **remains `Accepted`** —
never `Final` — until it ships a reference implementation and conformance
vectors. This is the deliberate PEP 1 / KEP separation of *approved design* from
*proven, gradable feature*.

#### 5.4 Final
The terminal success state for a **Standards Track** NEP. A NEP is promoted from
`Accepted` to `Final` **only** when the §6 gates are all satisfied. `Final` is
the state a downstream consumer relies on: a `Final` NEP is implemented in at
least one reference implementation and is graded by machine-checkable vectors
pinned in this repository.

#### 5.5 Rejected and Withdrawn
- **Rejected** — the editor concludes the proposal should not proceed
  (unsound, out of scope, or superseded by a better proposal). A `Rejected` NEP
  is kept in `process/` as a permanent record of the considered-and-declined
  option; its number is retired.
- **Withdrawn** — the **author** abandons the NEP (or concedes a competing
  proposal is superior — the PEP 1 sense of `Withdrawn`). Allowed from any
  pre-`Final` state. Also retained; number retired.

An abandoned-but-not-formally-withdrawn NEP MAY be marked `Withdrawn` by the
editor after a documented period of inactivity, the way Rust *postpones* a stale
RFC; the record notes it was withdrawn for inactivity and MAY be reopened under
a new number.

#### 5.6 Lifecycle for Informational and Process NEPs
Informational and Process NEPs use `Draft → Review → Accepted → Active` (or
`Rejected`/`Withdrawn`). They have **no `Final` state and are exempt from the §6
implementation/vector gates**, because they specify no on-the-wire behavior to
implement or grade. `Active` (as used by this NEP) marks an in-force
Informational/Process NEP; it is retired to `Superseded` when a later NEP
replaces it.

### 6. The Final gate (normative — the core rule of this process)

> **A Standards Track NEP MUST NOT be promoted to `Final` unless BOTH of the
> following exist, are merged into this repository, and pass CI:**
>
> **(a)** **at least one working reference implementation** of the NEP's
> normative behavior, in one of the repository's reference implementations
> under [`impl/`](../impl/) (the Go implementation is the primary reference);
> and
>
> **(b)** **machine-gradable conformance vectors** that exercise the NEP's
> normative behavior — a standards-anchored, non-circular oracle in the sense of
> [`spec/companion/55_conformance_requirements.md`](../spec/companion/55_conformance_requirements.md):
> new cases in the pinned conformance corpus
> ([`test-vectors/v1/conformance-corpus.json`](../test-vectors/v1/)) and/or a new
> pinned KAT set, such that a conforming implementation can be **graded
> pass/fail by tooling** (`npamp-conform` or the KAT gate), including the
> negative (MUST-reject) cases where the NEP defines any.
>
> **A NEP that specifies behavior but provides no reference implementation, or no
> machine-gradable vectors, is at most `Accepted`. It is never `Final`. A
> spec-only NEP is not a Final NEP.**

This rule is the direct application to N-PAMP of PEP 1 ("the reference
implementation must be completed before any PEP is given status 'Final'") and of
the Kubernetes graduation gate ("the graduation criteria must include conformance
tests … all GA endpoints must be hit by conformance tests"). It exists so that
`Final` in N-PAMP means the same thing it means in those projects: **the design
was not merely agreed, it was built and independently verified.**

Supporting requirements for the Final gate:

1. **Non-circularity (REQUIRED).** The conformance vectors MUST derive from an
   independent authority (the underlying RFC/FIPS/NIST standard, a published
   corpus such as Project Wycheproof, or an independent byte constructor) and
   **MUST NOT** be generated by the reference implementation they grade — the
   Wycheproof model this repository already uses. Vectors that are the output of
   the implementation under test do not satisfy gate (b).
2. **Pinning (REQUIRED).** New vectors MUST be added to
   [`PIN.json`](../PIN.json) / [`MANIFEST.sha256`](../MANIFEST.sha256) and pass
   [`scripts/verify-pins.ps1`](../scripts/verify-pins.ps1) and
   [`scripts/validate-schemas.py`](../scripts/validate-schemas.py) in CI, so the
   bytes a consumer relies on are provably the bytes the NEP shipped.
3. **Honest coverage (REQUIRED).** If a NEP's behavior is only partially
   gradable today (for example, a bridge/companion behavior for which no vector
   oracle yet exists — the Class B situation in
   `55_conformance_requirements.md` §5.2), the NEP MUST state exactly which parts
   are machine-graded and which remain specification-audited or self-attested.
   A NEP whose normative behavior is *entirely* un-gradable (no positive vector,
   no negative case, no KAT) **cannot** reach `Final`; it stops at `Accepted`
   with that limitation recorded, until an oracle is added.
4. **Wire-major-version NEPs.** A NEP that changes the wire in a
   backwards-incompatible way (§2.4) additionally requires a new ALPN identifier
   (e.g. `n-pamp/3`) and its own IANA registration before `Final`, per
   `CONTRIBUTING.md` "Code-point stability".

### 7. Firewall / controlled-material check (normative)

Every NEP **MUST** pass a firewall check before it may enter `Review`, and again
before `Final`. A NEP is a **public** document in the open reference repository;
it therefore **MUST NOT** contain any controlled or sealed material:

1. **No controlled or sealed material** — no controlled cryptographic extensions,
   and no High/Sovereign high-assurance implementation material, all of which are
   maintained separately and out of scope for this open reference
   ([ADR-0004](../decisions/0004-open-editions-publish-only-public-draft-primitives.md)).
   Publishing a **code point** (an identifier — e.g. a KEM/signature
   suite value, a channel number) is permitted, because it discloses an
   identifier, not an implementation; publishing the High/Sovereign
   *implementation material* behind such a code point is **not** (the repository
   "Scope": the registries list the High/Sovereign code points, but their
   high-assurance implementation material is maintained separately and is out of
   scope for this open reference).
2. **No private product or vendor-internal names** — a NEP names only the public
   protocol and its public author identity (Shawn Sammartano, BubbleFish
   Technologies, Inc.); it MUST NOT reference private downstream products or
   internal codenames.
3. **No absolute local filesystem paths** — all references are
   repository-relative.
4. **No non-public dependency** — a NEP's normative text MUST be reproducible
   from public standards and this repository alone; it MUST NOT depend on a
   non-public specification, corpus, or artifact.

The firewall check is a REQUIRED, recorded step (a reviewer sign-off, and the
repository's `firewall-scan` gate where present). A NEP that would require sealed
material to be complete does not belong in this repository and MUST be
`Rejected`.

### 8. Backwards / wire compatibility

This is a Process NEP; it changes no wire behavior and consumes no code points.
It is fully backwards compatible with the existing repository: it **adds** a
`process/` directory and a proposal instrument **on top of** the unchanged
three-layer decision history of `CONTRIBUTING.md`. Existing ADRs, the draft
change log, and the issue-label conventions continue exactly as they are; a NEP,
when `Accepted`, **produces** entries in those layers rather than bypassing them.
No existing document, registry, vector, or pin is altered by adopting this NEP.

### 9. Reference implementation

Per §5.6, a Process NEP is exempt from the §6 reference-implementation gate — it
specifies process, not on-the-wire behavior, so there is nothing to implement in
`impl/`. Its "implementation" is the process artifacts themselves: this document,
the `process/` directory, and the `nep` issue label. This NEP is `Active` on the
strength of those artifacts existing; it is not, and cannot be, `Final`.

### 10. Conformance vectors

Also per §5.6, a Process NEP has no machine-gradable conformance vectors, because
it defines no gradable wire behavior. The analogous "conformance" check for this
document is structural and is satisfiable by inspection: (i) `process/` exists
and contains `NEP-0000-nep-process.md`; (ii) the metadata table and required
sections of §11 are present; (iii) nothing in this document contradicts
`CONTRIBUTING.md`'s ADR/change-log/label process — it references and extends it.

### 11. Required NEP sections

Every NEP **MUST** contain, in order, the metadata table (§4.4) followed by these
sections. Sections marked *(Standards Track)* are REQUIRED for Standards Track
NEPs and MAY be marked "N/A" with a one-line reason for Informational/Process
NEPs.

1. **Abstract** — one paragraph: what the NEP changes and why, understandable on
   its own.
2. **Motivation** — the problem, the forces in tension, and why the existing
   design is insufficient. (Rust "Motivation"; PEP 1 "Motivation".)
3. **Specification** — the normative change in full, in the target document's
   style, precise enough that an independent implementer needs no further design
   decisions. Uses BCP 14 keywords where it states requirements. *(Standards
   Track: this is the text merged on `Accepted`.)*
4. **Backwards / Wire Compatibility** — the effect on interoperating peers;
   whether the change is additive or wire-major; migration guidance; and the new
   ALPN identifier if wire-major. *(Standards Track)*
5. **Reference Implementation** — the plan for, and then the link to, the working
   reference implementation under `impl/`. **REQUIRED to exist and be merged
   before `Final`** (§6a). *(Standards Track)*
6. **Conformance Vectors** — the plan for, and then the link to, the
   machine-gradable, non-circular vectors/KATs that grade the behavior.
   **REQUIRED to exist, be pinned, and pass CI before `Final`** (§6b).
   *(Standards Track)*
7. **Security Considerations** — the security effect of the change: new attack
   surface, downgrade/replay/nonce hazards, authentication bindings, and how they
   are mitigated. (IETF requirement for every draft; RFC 8126 for registry
   changes; PEP 1 "Security Implications".)
8. **Firewall / Controlled-Material Check** — an explicit statement, per §7, that
   the NEP contains no sealed identifiers, no private product names, and no
   non-public dependency, with the reviewer sign-off recorded.
9. **Considered Alternatives** — the options weighed and why they were not
   chosen (feeds the MADR ADR's "Considered Options"; Rust "Rationale and
   alternatives"; PEP 1 "Rejected Ideas").
10. **Decision Record Links** — the ADR number(s) in `decisions/` this NEP
    produced or updated, the change-log bullet, and the issue/PR (the three
    layers of `CONTRIBUTING.md`). Populated on `Accepted`.

### 12. Roles

- **Author** — writes and champions the NEP, and is responsible for the
  reference implementation and vectors reaching the repository before `Final`
  (the author MAY delegate the implementation, as Rust separates an accepted RFC
  from whoever implements it, but the NEP does not reach `Final` until they land).
- **Editor** — the N-PAMP document editor (the Independent Submission author of
  record). Assigns NEP numbers, opens/extends the review window, judges rough
  consensus, and makes the `Accepted`/`Rejected` and `Final` determinations. On
  the IETF side, the Independent Submissions Editor and the RFC Editor process
  (RFC 4846) remain the ultimate authority over the published draft/RFC text;
  the NEP process governs *this repository's* path up to that submission.
- **Reviewers** — anyone participating under the `nep` label, per
  `CODE_OF_CONDUCT.md`: critique text and design on the technical merits.

## Backwards / Wire Compatibility

Restated for the record: none. This Process NEP is additive to the repository
and changes no wire behavior, no registry, no vector, and no pin. See §8.

## Reference Implementation

Not applicable to a Process NEP; see §9. The process artifacts (this document,
`process/`, the `nep` label) are the deliverable, which is why this NEP is
`Active` and not `Final`.

## Conformance Vectors

Not applicable to a Process NEP; see §10. Conformance is structural and
inspectable, not machine-graded, because this document defines no wire behavior.

## Security Considerations

A change-management process has one real security property: it must not let a
security-relevant change slip in **without security review or without evidence**.
This NEP addresses that in three ways. (1) Every Standards Track NEP MUST carry a
Security Considerations section (§11.7) and MUST reach rough consensus in
`Review` before `Accepted`, so a security-affecting change is argued on its merits
(RFC 7282) rather than merged silently. (2) The §6 Final gate forbids a
security-relevant normative change from being presented as `Final` — i.e. as
something a deployer may rely on — until it is both implemented and graded by
non-circular vectors, closing the gap where a "specified but unbuilt, untested"
security mechanism is mistaken for a working one. (3) The §7 firewall check keeps
High/Sovereign implementation internals and other controlled material out of the
public record, so publishing a NEP never discloses sealed high-assurance
material — it discloses identifiers and Standard-profile behavior only.

The process does not itself defend the protocol; the protocol's security lives in
the draft and its companions. This NEP defends the *integrity of how changes to
that security get made*.

## Firewall / Controlled-Material Check

This document contains: no controlled or sealed material (no controlled
cryptographic extensions, no High/Sovereign high-assurance implementation material
— it refers to High/Sovereign only as public profile *names/code points*, which the
repository already publishes); no private downstream product or vendor-internal
names; no absolute local filesystem paths (all links are repository-relative);
and no dependency on any non-public specification or artifact. The only named
identity is the public IETF author of record, Shawn Sammartano, BubbleFish
Technologies, Inc. **Firewall check: clean.**

## Considered Alternatives

- **Do nothing; keep only ADRs + PRs.** Rejected: an ADR is decision-scale, not
  proposal-scale. Large, wire-affecting, or new-companion changes need one
  reviewable container with motivation, alternatives, an implementation, and
  vectors — and a status a consumer can trust. The ADR log remains, underneath.
- **Adopt the IETF working-group process wholesale.** Rejected: N-PAMP is an
  **Independent Submission** (RFC 4846), a single-editor stream, not a
  working-group document. A WG-style vote/quorum would misrepresent how this repo
  actually decides; `CONTRIBUTING.md` already states acceptance is an editorial
  decision. NEP keeps the editor final and uses rough consensus (RFC 7282) as
  input, not as a binding vote.
- **Copy PEP/KEP verbatim.** Rejected in part: PEP's Steering Council and KEP's
  SIG/Production-Readiness-Review bodies assume multiple governing bodies this
  project does not have. NEP keeps the parts that fit — the numbered lifecycle,
  the fixed sections, and above all the **implementation-and-tests-before-Final**
  gate — and drops the multi-body governance.
- **Let `Accepted` be the terminal state (no `Final`).** Rejected: that would
  erase the very distinction this repository is built on — agreed design versus
  built-and-graded reality. The `Accepted → Final` step, gated on a reference
  implementation and non-circular vectors, is the point of the whole process.

## Decision Record Links

On adoption, this NEP is recorded in the three layers of `CONTRIBUTING.md`: an
ADR in [`decisions/`](../decisions/) recording the decision to adopt a NEP
process (Considered Options: ADR-only / full IETF WG process / PEP-KEP-adapted
NEP), a change-log bullet in the draft appendix noting the addition of the
`process/` directory, and the `nep`-labelled issue/PR in which it was adopted.

---

## NEP template

Copy this into `process/NEP-NNNN-slug.md` to start a new NEP.

```markdown
# NEP-NNNN — <Title>

| | |
|---|---|
| **NEP** | NNNN |
| **Title** | <Title> |
| **Author** | <Name, affiliation, contact> |
| **Type** | Standards Track | Informational | Process |
| **Status** | Draft |
| **Created** | YYYY-MM-DD |
| **Requires** | <NEP-NNNN, or —> |
| **Supersedes** | <NEP-NNNN, or —> |
| **Discussion** | <issue/PR link>, label `nep` |

The key words MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT,
RECOMMENDED, MAY, and OPTIONAL are to be interpreted as described in BCP 14
(RFC 2119, RFC 8174).

## Abstract
<One paragraph: what this NEP changes and why.>

## Motivation
<The problem, the forces in tension, why the current design is insufficient.>

## Specification
<The full normative change, in the target document's style, precise enough that
an independent implementer needs no further design decisions. Use BCP 14
keywords for requirements. This text is what merges into the target document on
Accepted.>

## Backwards / Wire Compatibility
<Effect on interoperating peers; additive vs. wire-major; migration; new ALPN
identifier if wire-major.>

## Reference Implementation
<Plan, then link, to the working reference implementation under impl/.
REQUIRED to exist and be merged before Final. (Standards Track)>

## Conformance Vectors
<Plan, then link, to the machine-gradable, non-circular vectors/KATs that grade
this behavior; how they are pinned. REQUIRED to exist, be pinned, and pass CI
before Final. (Standards Track)>

## Security Considerations
<New attack surface; downgrade/replay/nonce/authentication effects; mitigations.>

## Firewall / Controlled-Material Check
<Explicit statement: no sealed identifiers, no High/Sovereign implementation
internals, no private product names, no absolute local paths, no non-public
dependency. Reviewer sign-off. State "clean" or "not clean — do not proceed".>

## Considered Alternatives
<Options weighed and why not chosen. Feeds the ADR's Considered Options.>

## Decision Record Links
<ADR number(s) in decisions/, the change-log bullet, and the issue/PR.
Populated on Accepted.>
```

---

## References (primary sources consulted)

- **RFC 2026** — *The Internet Standards Process — Revision 3.* BCP 9. The
  editorial-nit vs. normative-change distinction and the standards-track lifecycle
  N-PAMP's change tiers echo.
- **RFC 4846** — *Independent Submissions to the RFC Editor.* Establishes the
  single-editor Independent Submission stream N-PAMP is offered through; the
  basis for the NEP process being editor-final rather than working-group-vote.
- **RFC 7282** — *On Consensus and Humming in the IETF.* "Consensus is when
  everyone is sufficiently satisfied with the chosen solution, such that they no
  longer have specific objections to it." The basis for §5.2 rough-consensus
  review (objections addressed on merits, not counted).
- **RFC 8126** — *Guidelines for Writing an IANA Considerations Section in RFCs.*
  BCP 26. The Specification-Required policy (Expert Review + a stable, clear,
  technically-sound public specification) that governs single additive
  registrations (§3.2) versus range/policy changes that need a NEP (§2.5).
- **RFC 8174 / RFC 2119** — BCP 14 requirement keywords, used throughout.
- **Python PEP 1** — *PEP Purpose and Guidelines.* The status set (Draft /
  Accepted / Final / Rejected / Withdrawn / Active), the type set (Standards
  Track / Informational / Process), and the load-bearing rule "the reference
  implementation must be completed before any PEP is given status 'Final'"
  (§6a).
- **Rust RFC process** (`rust-lang/rfcs` `README`) — the "substantial change"
  trigger (§2), the Final Comment Period (§5.2), the `NNNN-title.md` convention,
  the template sections, and the separation of an *accepted* RFC from its
  *implementation* tracking ("being 'active' is not a rubber stamp").
- **Kubernetes KEP process** (`kubernetes/enhancements` `keps/README`) — the
  numbered-directory convention, the "non-trivial change" trigger, and the
  graduation gate that "the graduation criteria must include conformance tests …
  all GA endpoints must be hit by conformance tests" — the direct precedent for
  §6b (machine-gradable vectors before `Final`).

*N-PAMP™ and BubbleFish™ are trademarks of BubbleFish Technologies, Inc.*
