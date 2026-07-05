---
status: "accepted"
date: 2026-06-22
decision-makers: [BubbleFish Technologies, Inc.]
consulted: []
informed: []
---

# Record N-PAMP architecture decisions as MADR 4.0 ADRs

## Context and Problem Statement

N-PAMP's worth as a protocol depends on its spec decisions being **traceable** — a durable
record of *what* was decided, *why*, *which alternatives were weighed*, and *how the
decision is verified*. The prior development left rationale scattered across chat history,
design docs, and code comments, none of which survives as a queryable decision log. How
should we record protocol design decisions so the history is permanent and reviewable?

## Decision Drivers

* The owner's explicit priority: "a history of how we made N-PAMP spec decisions."
* Protocol design weighs alternatives (codepoints, constructions, profiles) — the
  *options considered* must be part of the record, not only the verdict.
* Must be greppable, diffable, and survive across sessions and tools.
* Should match recognized industry practice so future contributors recognize it.

## Considered Options

* **MADR 4.0** (Markdown Any Decision Records) — adds Decision Drivers, Considered Options,
  Pros/Cons, and a Confirmation step on top of Nygard.
* **Michael Nygard's original 5-section ADR** (Title/Status/Context/Decision/Consequences).
* **Prose design docs + GitHub issue threads only** (no structured ADR log).

## Decision Outcome

Chosen option: **MADR 4.0**, because protocol decisions are option-selection problems and
MADR is the only candidate that records the *alternatives weighed and how the decision is
confirmed* — exactly the history the owner wants. ADRs live in `decisions/NNNN-title.md`
(4-digit sequence, lowercase-dashed verb phrase). Status lifecycle:
`proposed → accepted → (deprecated | superseded by NNNN)`.

### Consequences

* Good, because every substantive decision leaves a permanent, structured, reviewable record.
* Good, because the Confirmation field forces each decision to name how it is verified.
* Bad, because MADR is heavier than bare Nygard; trivial/editorial choices should NOT get an
  ADR (only substantive decisions per `CONTRIBUTING.md`), or the log becomes noise.

### Confirmation

Presence of this file and `template.md`; `CONTRIBUTING.md` codifies the rule that every
`design`-consensus decision produces an ADR. Reviewable by inspection of `decisions/`.

## Pros and Cons of the Options

### MADR 4.0
* Good, because it captures Considered Options + Pros/Cons + Confirmation.
* Good, because it is a maintained, recognized convention (adr.github.io/madr).
* Neutral, because it requires more authoring effort per record.

### Nygard 5-section
* Good, because minimal and well-known.
* Bad, because it records only the decision and context — not the alternatives weighed.

### Prose docs + issues only
* Good, because zero added structure.
* Bad, because rationale is not durable, not greppable, and decays as issues are closed.

## More Information

ADR convention: Michael Nygard, "Documenting Architecture Decisions" (2011); MADR 4.0 at
adr.github.io/madr. IETF rationale-capture practice: RFC 8874 (WG GitHub usage). See
`CONTRIBUTING.md` for the three-layer decision-history mechanism.
