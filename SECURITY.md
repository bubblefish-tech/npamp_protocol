# Security Policy

This repository contains a protocol **specification**, not a deployed service.
"Security issues" here means weaknesses in the protocol design or its
description: for example, a downgrade path, a missing authentication binding, a
replay or nonce-reuse hazard, or an ambiguity that would lead independent
implementers to build something insecure.

## Reporting a vulnerability

Please report suspected security issues **privately** by email to:

    npamp-editor@bubblefish.sh

Use a clear subject line (for example, `N-PAMP security: <short summary>`) and
include:

- the section of the draft involved (and the draft revision, e.g. `-00`);
- a description of the weakness and the assumptions it requires;
- an attack scenario or proof-of-concept, if you have one; and
- any suggested mitigation.

Please do **not** open a public issue for an unfixed security weakness.

## What to expect

- Acknowledgement of your report within a reasonable time.
- Coordinated handling: we will work with you on an assessment and, where a
  specification change is warranted, a revised draft. We ask for a coordinated
  disclosure window (target: up to 90 days) before public discussion of an
  unmitigated design weakness.
- Credit in the document's acknowledgements if you wish.

## Scope

In scope: the N-PAMP wire format, channel architecture, profile negotiation,
key schedule, and cryptographic-suite descriptions as specified in the
Internet-Draft in this repository.

Out of scope: third-party implementations, deployments, or services that use
N-PAMP. Report those to their respective maintainers.
