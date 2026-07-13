# N-PAMP Project Governance

This document describes **how the N-PAMP project is governed**: who holds which
role, how decisions are made and recorded, how a normative change to the protocol
differs from an editorial one, how the repository relates to the IETF submission
that is the protocol's source of truth, how code points are assigned, how
conformance gates the word "done," and how maintainership changes hands.

It is deliberately **lightweight and honest**. N-PAMP is a small-team
specification effort, not a large standards body; this document describes the
governance that actually exists rather than a committee that does not. A small
project is best served by a governance model matched to its size — the pattern
recommended for early-stage open specifications — with the process written down
so a new contributor knows exactly how to engage.

This document does **not** replace [`CONTRIBUTING.md`](CONTRIBUTING.md), which
already defines the day-to-day change mechanics (the ADR/MADR record process, the
issue/PR labels, the draft build-and-lint steps, and the licensing of
contributions). Governance references that process; it does not restate or
override it. Where this document and `CONTRIBUTING.md` appear to differ,
`CONTRIBUTING.md` is authoritative for mechanics and this document is
authoritative for authority — who decides, and on what basis.

Community conduct is governed by [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md); the
private reporting path for a design weakness is [`SECURITY.md`](SECURITY.md).

---

## 1. What is being governed

This repository is the **public reference home** of N-PAMP: the Internet-Draft
(`draft-bubblefish-npamp`, currently preparing draft-02, offered through the IETF
Independent Submission stream), the normative companion specifications and
per-channel interface references, the machine-readable code-point registries, the
conformance corpus and standards-anchored KATs, the cross-implementation
conformance harness, and the ten reference implementations.

The governed artifacts fall into three tiers, and the governance weight scales
with the tier:

| Tier | Artifact | Governs what | Change weight |
|---|---|---|---|
| **Normative wire** | The Internet-Draft, the core spec extracts, the companion specifications, the code-point registries | What an implementation MUST do on the wire | Heaviest — see [§4](#4-normative-vs-editorial-changes) and [§6](#6-code-point-governance) |
| **Conformance oracle** | The pinned vector corpus, the KATs, the schemas, the harness | What "conforms" means and how it is graded | Heavy — see [§7](#7-conformance-gates-done) |
| **Reference & tooling** | The ten implementations, quickstarts, scripts, CI, docs | How the protocol is demonstrated and tested | Ordinary open-source change |

The **draft is the source of truth**; everything else exists to conform to it or
to demonstrate it (repository README, "Why you can trust this"). Governance
therefore concentrates its ceremony on the normative-wire tier and stays out of
the way of ordinary reference-implementation work.

---

## 2. Roles

N-PAMP uses a small, explicit set of roles. It does not claim a steering
committee, a working group, or an elected board — none exists, and inventing one
in a document would be dishonest.

### 2.1 Author / Editor

**Shawn Sammartano, BubbleFish Technologies, Inc.** is the document author and
editor. This is the same identity that appears on the Internet-Draft and in
[`CITATION.cff`](CITATION.cff); it is the single public identity of the project.

The Author/Editor holds final authority over normative content, consistent with
the Independent Submission stream, in which the document represents the author's
work and the author retains editorial control (RFC 4846). Concretely, the
Author/Editor:

- decides whether a proposed **normative** change is accepted, after the
  rough-consensus process of [§3](#3-how-decisions-are-made);
- owns the draft text and its submission to the Independent Submissions Editor;
- assigns code points within the registries' managed ranges ([§6](#6-code-point-governance));
- is the tie-breaker of last resort when discussion does not converge; and
- maintains the decision record so that every substantive choice is traceable.

This is a benevolent-single-editor model, which is the honest description of a
project this size. The tie-breaker authority is a backstop, not the normal path:
the normal path is that objections are addressed on their technical merits
([§3](#3-how-decisions-are-made)) and the outcome is obvious before anyone has to
invoke authority.

### 2.2 Maintainers

**Maintainers** hold commit access and keep the repository healthy: they review
and merge pull requests, triage and label issues, run and maintain the CI gates,
cut draft-revision tags, and shepherd reference-implementation and tooling
changes. A maintainer may accept any **editorial** or **reference/tooling** change
on their own judgment. A maintainer may **not** unilaterally land a **normative**
change; those follow [§3](#3-how-decisions-are-made) and [§4](#4-normative-vs-editorial-changes)
and require Author/Editor acceptance.

The current maintainer set is recorded in [`MAINTAINERS.md`](MAINTAINERS.md) (or,
until that file exists, is the Author/Editor alone). Adding and removing
maintainers is [§8](#8-adding-and-removing-maintainers).

### 2.3 Contributors

**Contributors** are everyone who opens an issue or a pull request, reviews a
change, reports a security weakness, or proposes a code-point registration.
Contribution does not require any status; it requires following
[`CONTRIBUTING.md`](CONTRIBUTING.md) and [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md).
By contributing you agree to the licensing terms in `CONTRIBUTING.md` (Apache-2.0
for repository code and original content; BCP 78 / `ipr: trust200902` for
Internet-Draft text).

Contributors have real influence: a technical objection from any contributor is
weighed on its merits, not on the contributor's status ([§3](#3-how-decisions-are-made)).

### 2.4 Designated experts

Two IANA registrations tied to N-PAMP are governed **outside** this project by
IANA's own process: the ALPN identifier `n-pamp/2` (Expert Review, RFC 7301) and
the provisional `npamp` URI scheme (First Come First Served, RFC 7595). The
project does not appoint those experts and cannot assign those values itself; it
supplies the registration templates and the citing draft. This is stated so no
reader mistakes the project's internal registries ([§6](#6-code-point-governance))
for the IANA-managed identifiers.

---

## 3. How decisions are made

N-PAMP decisions are made by **rough consensus**, in the IETF sense (RFC 7282),
scaled to a small project — **not** by majority vote. The distinction is load-
bearing:

- **Issues are addressed, not counted.** A decision is ready when the technical
  objections raised against it have been *addressed* — considered and answered —
  not when a headcount favors one side. An unaddressed, sound technical objection
  blocks consensus even if only one person raised it; conversely, an objection
  that has been genuinely answered does not block, even if its author remains
  unpersuaded (RFC 7282 §3, §6).
- **No voting, no vote-stuffing.** Because the question is "are there outstanding
  technical objections?" and not "how many people are on each side?", the process
  is immune to headcount manipulation (RFC 7282 §6). The project runs no polls
  and counts no votes.
- **Discussion happens in the open**, on the issue or pull request. The label
  taxonomy of `CONTRIBUTING.md` (`design` vs `editorial`, plus
  `needs-discussion` / `has-consensus` / `proposal-ready`, per RFC 8874 practice)
  is the discussion trail.
- **The Author/Editor is the backstop.** If a `design`-labeled discussion does not
  converge in a reasonable time, the Author/Editor makes the call and records the
  reasoning in an ADR. This mirrors the small-project pattern where a benevolent
  editor resolves a stalled discussion rather than leaving the protocol
  undecided, and it is consistent with the Independent Submission stream's single
  approving authority (RFC 4846).

Every `design`-labeled issue that reaches consensus produces the **three
artifacts** `CONTRIBUTING.md` already requires: (1) a closing comment recording
the resolution, (2) a numbered **MADR 4.0 Architecture Decision Record** in
[`decisions/`](decisions/), and (3) a change-log bullet in the draft's change
appendix and in [`CHANGELOG.md`](CHANGELOG.md). Governance adds no fourth
artifact and changes none of these three — it only states *who* has the authority
to declare that consensus was reached (the Author/Editor, for normative content).

> **Why an ADR, not just a merge.** The project's stated value is that every spec
> decision is *traceable* — what was decided, why, which alternatives were weighed,
> and how the decision is verified ([ADR-0001](decisions/0001-record-architecture-decisions.md)).
> A merge without an ADR loses the "why." The ADR is the durable record; the merge
> is just the mechanics.

---

## 4. Normative vs. editorial changes

The single most important governance distinction in this project is **normative
vs. editorial**, because it determines both the process weight and the
compatibility contract. `CONTRIBUTING.md` requires every change to be labeled one
or the other; this section defines the boundary and the consequence.

### 4.1 What makes a change normative

A change is **normative** if it affects what a conforming implementation does *on
the wire* or *at a security boundary*. This includes, at minimum:

- the 36-octet frame header geometry, the magic value, the header CRC, the
  reserved octets, or the version octet;
- the channel registry, the frame-type number space, or the TLV number space;
- any handshake flight, transcript construction, key-schedule stage, or
  authentication check;
- the profile parameter rows (KEM, signatures, KDF hash, diversification,
  downgrade rules);
- any cryptographic-suite code point or its construction (for example the
  ML-KEM-first combiner order, [ADR-0005](decisions/0005-align-x25519mlkem768-combiner-to-ml-kem-first.md));
- a companion specification's `MUST` / `MUST NOT` / `SHALL` behavior; and
- any code-point **assignment** or policy change in [`registries/`](registries/).

A change is **editorial** if it cannot change any of the above: wording,
formatting, examples, non-normative prose, typo fixes, added cross-references,
and improvements to informative worked examples. Reference-implementation and
tooling changes that do not alter the wire contract are **ordinary open-source
changes** and are neither of the two spec categories, though a change to an
implementation that reveals a *spec* ambiguity should open a `design` issue.

If a change is on the boundary, it is treated as **normative** until shown
otherwise. Misclassifying a normative change as editorial is the failure this
distinction exists to prevent.

### 4.2 Process by class

| Class | Who may accept | Process | Record produced |
|---|---|---|---|
| **Editorial** | Any maintainer | Ordinary PR review; label `editorial`; leave the draft at 0 errors / 0 flaws under `idnits` (`CONTRIBUTING.md`) | Merge + `CHANGELOG.md` bullet |
| **Normative** | Author/Editor only, after rough consensus ([§3](#3-how-decisions-are-made)) | Label `design`; open the discussion; reach rough consensus; Author/Editor accepts | Closing comment **+ MADR ADR + change-log bullet** (all three) |
| **Reference / tooling** | Any maintainer | Ordinary PR review; must keep CI green ([§7](#7-conformance-gates-done)) | Merge + `CHANGELOG.md` bullet where user-visible |

> **Proposal-scale changes are carried by a NEP.** A normative change that is
> large or structural — a new companion specification, a new or repurposed
> channel, a new Bridge carriage class, or any wire-affecting change to the header
> geometry, number spaces, handshake, profiles, or suites — is proposed as an
> **N-PAMP Enhancement Proposal** ([`process/NEP-0000-nep-process.md`](process/NEP-0000-nep-process.md)).
> A NEP runs the same rough-consensus process ([§3](#3-how-decisions-are-made)) and
> produces the same three-layer record (ADR + change-log + labels); it adds one
> gate this project treats as non-negotiable: a Standards Track NEP **MUST NOT**
> reach *Final* until a working reference implementation and machine-gradable,
> non-circular conformance vectors exist for it ([§7](#7-conformance-gates-done)).
> A single additive registration in an existing *Specification Required* range does
> **not** need a NEP — it follows the code-point procedure of [§6.2](#62-how-a-code-point-is-assigned).

### 4.3 Wire-compatibility consequence

A normative change carries a **compatibility class**, per `CONTRIBUTING.md`
("Code-point stability"):

- **Additive** — registering a new value in an existing number space (for
  example a new AEAD or signature suite) is a value addition. It does not change
  the wire layout and does not bump the wire major version.
- **Major** — any change to the 36-octet header geometry, the magic value, the
  header CRC, the channel registry, the frame-type number space, or the TLV
  number space is a wire-incompatible change. It requires a new wire major
  version and therefore a **new ALPN identifier** (for example `n-pamp/3`), since
  the digit in the ALPN label equals the value carried in the frame header's
  `Ver` field.

The Author/Editor MUST state the compatibility class in the ADR for any normative
change, so a downstream implementer can tell an additive registration from a
breaking one at a glance.

---

## 5. Relationship to the IETF / ISE submission track

N-PAMP is offered through the IETF **Independent Submission** stream
(Informational). Two facts govern how this repository relates to that track, and
they are the reason the governance here is deliberately modest.

1. **The draft is the source of truth; the repository is the working area.** The
   normative specification is the Internet-Draft. The registries, companion
   specs, vectors, and implementations in this repository exist to *express* and
   *conform to* that draft — they are not an independent source of authority. When
   the repository and the published draft disagree, the draft wins, and the
   repository is corrected to match (or the draft is revised, deliberately, via
   [§3](#3-how-decisions-are-made)–[§4](#4-normative-vs-editorial-changes)).

2. **Final normative authority on the *track* is not the repository's to grant.**
   Under the Independent Submission stream (RFC 4846), an independent-stream
   document is *not* an IETF-consensus document; it represents the author's work,
   the author retains editorial control, and the decision to publish rests with
   the Independent Submissions Editor (ISE) after independent review, not with a
   working group. Opening an issue or pull request here is the right first step,
   and consensus here is real and recorded — but acceptance of a normative change
   into the *submitted draft* is a deliberate editorial act by the Author/Editor,
   and publication as an RFC is the ISE's decision. This repository governs the
   working area up to that boundary and makes no claim past it.

The practical upshot: this project can and does run a real, traceable decision
process for its own working area, without pretending to be a chartered IETF
working group. The three-layer record (ADR + in-draft change log + labeled
issue/PR trail) is exactly the "traceable rationale" practice IETF GitHub usage
recommends (RFC 8874), applied to an independent submission.

---

## 6. Code-point governance

The eight registries under [`registries/`](registries/) carry the protocol's
public code points. Their governance follows **RFC 8126** (the IANA-registration-
policy vocabulary), applied to the project's own managed number spaces. Two
things are true at once and must not be confused:

- The **project-internal** registries (channels, frame types, TLV tags, profiles,
  KEM, AEAD, signatures, bridge protocol IDs) are managed *here*, by the
  Author/Editor, under the policies each registry states.
- The **IANA-managed** identifiers tied to N-PAMP (the ALPN `n-pamp/2` under
  Expert Review; the `npamp` URI scheme under First Come First Served) are
  managed by **IANA**, not by this project ([§2.4](#24-designated-experts)).

### 6.1 The three assignment bands

Each registry with a managed number space partitions it into the standard RFC
8126 bands. Using the Bridge Protocol Identifier registry
([`registries/bridge_protocol_ids.csv`](registries/bridge_protocol_ids.csv)) as
the worked example, the bands are:

| Band | Policy (RFC 8126) | Who assigns | What it means |
|---|---|---|---|
| **Managed / assigned** (e.g. `0x01`–`0x0F`) | **Specification Required** (RFC 8126 §4.6) | Author/Editor, via the companion registry procedure | A permanent, readily available public specification with enough detail for interoperable independent implementations is required before a value is assigned; the assignment is recorded and MUST NOT be reassigned. |
| **Experimental** (e.g. `0x10`–`0x7F`) | **Experimental Use** (RFC 8126 §4.2) | No one — unregistered | Usable without registration for experiments; carries no guaranteed cross-domain meaning; MUST NOT be emitted toward a peer without out-of-band agreement. IANA/the project record nothing here. |
| **Private use** (e.g. `0x80`–`0xFF`) | **Private Use** (RFC 8126 §4.1) | No one — unregistered | Usable inside a single administrative domain without registration; never assigned by this registry; MUST NOT be emitted toward a peer outside that domain. |

The exact numeric boundaries differ per registry and are authoritative **in the
registry CSV**, not here; this table shows the *policy shape* every registry
follows. The reserved null identifier (`0x00` in the bridge registry) is not
assignable.

### 6.2 How a code point is assigned

1. Open an issue proposing the registration, labeled `design` (a code-point
   assignment is normative, [§4.1](#41-what-makes-a-change-normative)).
2. Provide the **Specification Required** material: a stable, public description
   detailed enough for two independent implementations to interoperate — for a
   bridge mapping, this is the mapping document written against the foreign
   protocol's own published specification; for a suite, the construction and its
   standards anchor.
3. Reach rough consensus ([§3](#3-how-decisions-are-made)); the Author/Editor
   assigns the next value in the managed band and records an ADR plus the CSV row.
4. If no specification is ready yet, the proposer uses the **experimental** band
   by out-of-band agreement, or the **private-use** band within one domain — no
   registration, and no standards meaning claimed. This is the honest path for
   work in progress and is why the mapping index marks several `protocol_id`
   values `PROVISIONAL` rather than fabricating a standards code point.

### 6.3 Stability guarantee

An assigned value in a managed band is **stable within a wire major version** and
MUST NOT be reassigned. Changing the *layout* of a number space (as opposed to
adding a value to it) is a major-version change ([§4.3](#43-wire-compatibility-consequence)).

---

## 7. Conformance gates "done"

A change to the normative-wire or oracle tier is not "done" when it merges; it is
"done" when the **conformance gates** are green and, for a normative change, the
oracle has been updated to cover it. The conformance classes are defined
normatively in the companion specification
[`spec/companion/55_conformance_requirements.md`](spec/companion/55_conformance_requirements.md)
(NPAMP-CONFORM); governance only states how they gate the project.

### 7.1 The conformance classes

| Class | Grades | Machine-gradable today | Oracle |
|---|---|---|---|
| **W** — wire primitives | Frame header, CRC32C, TLV, AEAD, HKDF, profile-acceptance invariants | **Yes** | The pinned 255-vector corpus |
| **H** — handshake (Standard profile) | The 1.5-RTT handshake: transcript, key schedule, Finished, CertVerify, KEM wire order | **Yes** | The five standards-anchored KATs |
| **B** — bridge / companion | NPAMP-BRIDGE and each claimed carriage class / mapping | **No** — specification-audited only | Each document's own `§Conformance` clause |

These oracles are **non-circular by construction**: every expected value derives
from an external authority (NIST/FIPS, the RFC series, Project Wycheproof, the
Castagnoli polynomial) and never from an N-PAMP implementation under test, so a
bug shared across implementations cannot silently pass.

### 7.2 The gating rule

- **Every push and pull request** runs the CI workflow: schema validation, the Go
  reference adapter against the embedded corpus (any `MUST` failure exits
  non-zero), the pin-drift gate (`scripts/verify-pins.ps1` recomputes every
  SHA-256 in `PIN.json` / `MANIFEST.sha256`), and the Rust and Swift reference
  builds. A red gate blocks merge.
- **A normative change that adds or alters wire behavior is not complete until
  its oracle exists.** If the change is in a class that is machine-gradable
  (W or H), a corresponding vector or KAT MUST be added and pinned in the same
  or an immediately following change; a normative change that leaves its behavior
  ungraded is an open coverage gap that MUST be recorded (NPAMP-CONFORM §8), not
  silently shipped.
- **A conformance *claim* is honest about scope.** Per NPAMP-CONFORM §9, a claim
  names its class(es), its profile scope (Standard for the current public oracle
  set), and the corpus/KAT SHA-256 it was graded against, and MUST NOT overstate
  coverage — a Class W pass is not a handshake or bridge claim, and no class may
  be claimed for the High or Sovereign profile on the basis of the public oracle
  set. Governance adopts this as the project's definition of "verified": a
  capability is verified when a pinned, non-circular oracle grades it green, and
  is otherwise recorded as self-attested or as a coverage gap.

The effect is that "done" for the protocol means **graded green by an independent
oracle**, not "the author says it works." That is the gate, and it is
intentionally stricter than a passing build.

---

## 8. Adding and removing maintainers

Maintainership is granted for **sustained, high-quality contribution and
demonstrated good judgment about the normative/editorial boundary**, not for a
single change. The process is deliberately simple because the team is small.

### 8.1 Adding a maintainer

1. An existing maintainer (or the Author/Editor) nominates the candidate in an
   issue labeled `governance`, citing the candidate's track record.
2. The existing maintainers and the Author/Editor discuss by rough consensus
   ([§3](#3-how-decisions-are-made)); an unaddressed, sound objection blocks the
   addition.
3. The **Author/Editor confirms** the addition (final authority, [§2.1](#21-author--editor)).
4. The change is recorded: the candidate is added to
   [`MAINTAINERS.md`](MAINTAINERS.md), granted commit access, and the decision is
   noted in the `governance` issue. A governance-role change of this weight also
   gets an ADR, so the roster's history is traceable like every other decision.

### 8.2 Stepping down or removal

- **Voluntary step-down.** A maintainer may step down at any time by opening a
  `governance` issue or a pull request removing themselves from `MAINTAINERS.md`.
  Commit access is revoked; the step-down is recorded. No justification is
  required and none is asked for.
- **Inactivity.** A maintainer who has been inactive for an extended period
  (default: **twelve months** with no reviews, merges, or triage) may be moved to
  *emeritus* in `MAINTAINERS.md` by the Author/Editor, after a good-faith attempt
  to reach them. Emeritus status is honorary; commit access lapses and is
  restored on request if the person returns to active contribution.
- **For cause.** A maintainer may be removed for a serious or sustained violation
  of [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md), or for repeatedly landing
  normative changes without the process of [§4](#4-normative-vs-editorial-changes).
  Removal for cause is the Author/Editor's decision, recorded in a `governance`
  issue and an ADR.

### 8.3 Succession of the Author/Editor role

The Author/Editor role is tied to the public author identity of the Internet-
Draft and cannot be transferred by a repository action alone: transferring it
would require re-authorship of the submitted draft on the IETF Datatracker and
the Independent Submissions Editor's involvement, which is outside this
repository's control. Should the Author/Editor become unavailable, the maintainers
may keep the repository, the reference implementations, and the conformance oracle
running (editorial and tooling tiers) under this document; a change to the
*normative draft authorship* is an ISE-track action, not a repository merge. This
limit is stated so no reader assumes the repository can hand off the standards-
track identity by itself.

---

## 9. Changing this document

This GOVERNANCE.md is itself governed. A change to it is a `governance`-labeled
change: proposed in a pull request, discussed by rough consensus, confirmed by
the Author/Editor, and — because it is a substantive decision about how the
project runs — recorded with an ADR. Editorial fixes to this document (typos,
broken links, clarified wording that does not change who decides what) are
ordinary editorial changes ([§4](#4-normative-vs-editorial-changes)).

---

## Precedents

This governance model was written against, and is consistent with, the following
primary sources (consulted directly, not from memory):

- **RFC 7282 — "On Consensus and Humming in the IETF."** The rough-consensus
  model of [§3](#3-how-decisions-are-made): issues are *addressed, not counted*;
  an unaddressed sound objection blocks consensus regardless of headcount; no
  voting.
- **RFC 8126 — "Guidelines for Writing an IANA Considerations Section in RFCs."**
  The registration-policy vocabulary of [§6](#6-code-point-governance):
  Specification Required (§4.6), Experimental Use (§4.2), Private Use (§4.1), and
  the Expert Review / First Come First Served policies of the IANA-managed
  identifiers.
- **RFC 4846 — "Independent Submissions to the RFC Editor."** The
  repository-vs-submission relationship of [§5](#5-relationship-to-the-ietf--ise-submission-track):
  an independent-stream document is not an IETF-consensus document, the author
  retains editorial control, and the Independent Submissions Editor is the
  approving authority.
- **RFC 8874 — "Working Group GitHub Usage Guidance."** The traceable
  issue/PR-label discussion trail and rationale-capture practice that
  `CONTRIBUTING.md` already implements and this document references.
- **PEP 1 — "PEP Purpose and Guidelines."** The author-champion vs.
  editors-do-not-judge-merits vs. final-approving-authority separation of roles
  ([§2](#2-roles)), and the requirement that a decision be recorded with its
  rationale.
- **CNCF project-governance templates and the open-source "minimum viable
  governance" / benevolent-single-editor pattern.** The justification for a
  *lightweight, honest, size-matched* governance model with a written
  maintainer-add/step-down process ([§8](#8-adding-and-removing-maintainers)),
  rather than an invented steering committee.

---

*N-PAMP is developed by Shawn Sammartano, BubbleFish Technologies, Inc. See
[`CONTRIBUTING.md`](CONTRIBUTING.md) for how to contribute,
[`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md) for community standards, and
[`SECURITY.md`](SECURITY.md) for reporting a design weakness.*
