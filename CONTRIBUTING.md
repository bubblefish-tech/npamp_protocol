# Contributing to N-PAMP

Thank you for your interest in N-PAMP. This repository hosts a protocol
**specification** (an IETF Internet-Draft) plus its IANA registration material.
Contributions are welcome under the terms below.

## Ways to contribute

- **Report an issue** with the specification: an ambiguity, an inconsistency,
  a security concern, or an editorial problem. Use the issue templates under
  `.github/ISSUE_TEMPLATE/`.
- **Propose a change** by opening a pull request against the draft source.

Please separate **normative** changes (anything that affects what an
implementation must do on the wire) from **editorial** changes (wording,
formatting, examples). Label them accordingly.

## Editing the draft

The specification source is the kramdown-rfc Markdown file
`draft-bubblefish-npamp-00.md`. Before opening a pull request:

1. Keep the source **ASCII-only**. Non-ASCII characters cause author-tool
   warnings; the only acceptable non-ASCII is what the renderer itself injects.
2. Render and lint locally:

   ```sh
   gem install kramdown-rfc
   pip install xml2rfc
   kramdown-rfc draft-bubblefish-npamp-00.md > draft-bubblefish-npamp-00.xml
   xml2rfc draft-bubblefish-npamp-00.xml --text --html
   idnits draft-bubblefish-npamp-00.txt
   ```

   or use the hosted tools at <https://author-tools.ietf.org/>.

3. A pull request should leave the draft at **0 errors / 0 flaws** under idnits.

## How normative changes are decided

This document is offered through the IETF **Independent Submission** stream.
Normative changes are ultimately the responsibility of the document author /
editor and, where applicable, the Independent Submissions Editor and IETF
review process. Opening an issue or pull request is the right first step;
acceptance of a normative change is a deliberate editorial decision, not an
automatic merge.

## Code-point stability

The wire format is intended to be stable within a wire major version. Proposals
that change the 36-octet header geometry, the magic value, the header CRC, the
channel registry, the frame-type number space, or the TLV number space are
**major-version** changes and will be treated as such (a new ALPN identifier,
e.g. `n-pamp/3`). Additive registrations (for example a new suite identifier)
are value additions, not layout changes.

## Licensing of contributions

By submitting a contribution you agree that:

- your contribution to the repository's code and original content is provided
  under the **Apache License 2.0** (the repository's license); and
- your contribution to the **Internet-Draft / RFC text** is provided under the
  IETF Trust's Legal Provisions (BCP 78), consistent with the draft's
  `ipr: trust200902` attribute and with BCP 78 / BCP 79.

## Conduct

All participation is governed by [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
