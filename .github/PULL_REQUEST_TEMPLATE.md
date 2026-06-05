# Pull request

**What does this change?**
A one-line summary.

**Type of change**
- [ ] Editorial (wording, formatting, examples): no change to wire behavior
- [ ] Normative (changes what an implementation must do on the wire)

**If normative, confirm wire-stability intent**
- [ ] This change does NOT alter the 36-octet header geometry, the magic value,
      the header CRC, the channel registry, the frame-type number space, or the
      TLV number space (i.e., it stays within wire major version 2), OR
- [ ] This change intentionally proposes a new wire major version (and a new
      ALPN identifier such as `n-pamp/3`), and says so explicitly.

**Author-tool checks**
- [ ] The draft renders with kramdown-rfc + xml2rfc without errors.
- [ ] `idnits` reports 0 errors and 0 flaws.
- [ ] The source remains ASCII-only.

**Related issue**
Closes #...

**Licensing**
- [ ] I agree my contribution is provided under Apache-2.0 (repo content) and,
      for the draft/RFC text, under the IETF Trust's Legal Provisions (BCP 78),
      consistent with `ipr: trust200902`.
