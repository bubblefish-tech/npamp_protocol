---
status: "accepted"
date: 2026-06-22
decision-makers: [BubbleFish Technologies, Inc.]
consulted: []
informed: []
---

# Open/public editions publish only the public-draft primitives; controlled extensions are excluded

## Context and Problem Statement

The N-PAMP lineage includes a set of **controlled cryptographic extensions** that are
maintained under access control and are **not** for public release. Earlier development
mixed these with the publishable protocol, which risked leaking controlled material into
open-source products and public artifacts. What is published, and what is held private?

## Decision Drivers

* Controlled cryptographic extensions must never appear in any open-source consuming product
  or in the public draft / public repo.
* The public draft must still be a complete, implementable, standalone specification.
* The boundary must be enforceable mechanically, not by vigilance alone.

## Considered Options

* **Publish only the public-draft primitives; maintain controlled extensions separately, out of
  scope for this repository**, enforced by a mechanical exclusion scan.
* Publish everything (rejected on confidentiality grounds).
* Keep everything private (rejected — defeats the goal of a public reference protocol).

## Decision Outcome

Chosen option: **publish only the public-draft primitives.** Everything required to
implement the public N-PAMP draft (the hybrid post-quantum KEM, the standard AEAD, the
standard signature and KDF families, the wire format, the profiles as defined in the public
draft) lives in this open reference repository. The controlled cryptographic extensions
are maintained separately, out of scope for this repository, and are excluded
from every open-source consumer by a mechanical exclusion scan that fails the build on a
controlled-identifier match.

### Consequences

* Good, because the public draft is complete and implementable while controlled material
  stays out of public release by construction (maintained separately, out of scope here).
* Good, because the exclusion is mechanically enforced (a scan), not dependent on reviewer memory.
* Bad, because contributors must know which work is out of scope for this repository; mis-filing a
  controlled artifact into the public slice is a real risk the scan must catch.

### Confirmation

A controlled-identifier exclusion scan runs in CI for every consuming product and SHOULD run
in this repository; it fails loud on a match. Consuming-product editions are verified to
contain none of the controlled identifiers.

## Pros and Cons of the Options

### Publish public-draft primitives only; controlled extensions private + scanned
* Good, because confidentiality is structural + mechanically enforced.
* Neutral, because it requires a maintained exclusion identifier list.
* Bad, because it splits the crypto surface across a public/controlled boundary.

### Publish everything
* Bad, because it discloses controlled material. Rejected.

### Keep everything private
* Bad, because there would be no public reference protocol. Rejected.

## More Information

Mechanical enforcement pattern: an identifier-precise exclusion scan (allows public draft
codepoints, forbids the controlled-extension identifiers). Related: ADR-0003 (the public
draft's three profiles share one construction — open-edition products implement the Standard
row only).
