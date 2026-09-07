# IETF hackathon prep checklist (N-PAMP)

This checklist is for the maintainer targeting an IETF hackathon session for
the interop milestone. It is honest about which parts require the maintainer's own
registration and attendance ("event-gated") versus what this repository already
provides.

## 1. Facts about IETF hackathons (primary-sourced 2026-09-06)

- **Format:** IETF hackathons are, verbatim, "free to attend and open to
  everyone" and are explicitly "collaborative events, not competitions" —
  <https://www.ietf.org/how/runningcode/hackathons/> (retrieved 2026-09-06).
  Their stated purpose is to "advance the pace and relevance of IETF standards
  activities by bringing the speed and collaborative spirit of open source
  development into the IETF" and to "encourage developers and subject matter
  experts to collaborate and develop utilities, ideas, sample code and
  solutions that show practical implementations of IETF standards" (same
  source). Past hackathons have covered "DNS, FD.io/VPP, HTTP 2.0, NETVC,
  OpenDaylight, ONAP, RiOT, QUIC, TLS 1.3, WebRTC, YANG/NETCONF/RESTCONF, and
  many others" — a protocol at N-PAMP's stage (an active Internet-Draft with
  reference implementations) is squarely the kind of project these events are
  for.
- **Next scheduled event:** IETF 127 Hackathon, **14–15 November 2026
  (Saturday–Sunday)**, held both online and in San Francisco —
  <https://www.ietf.org/meeting/hackathons/127-hackathon/> (retrieved
  2026-09-06). Both onsite and remote participation are supported, with
  separate registration/attendee lists for each.
- **How a project gets added:** project sign-up happens on the **Hackathon
  wiki**, which requires an IETF Datatracker login to edit. The site's own
  guidance (quoted verbatim): *"Don't see anything that interests you? Then
  add your preferred project to the list, sign up as its champion and show up
  to work on it."* There is no separate "submission" process beyond adding the
  project to the wiki and showing up — no code-of-conduct sign-off, repository
  format requirement, or team-size rule was published on the pages retrieved
  this session.
- **Staying informed:** subscribe to the IETF Hackathon mailing list; monitor
  the hackathon wiki as the event approaches for other registered projects
  (potential interop partners) and their champions' contact info.
- **Re-verify before acting:** hackathon logistics (exact dates, wiki URL
  pattern `wiki.ietf.org/en/meeting/<N>/hackathon`, registration portal) are
  per-meeting and change every cycle. Re-check the current hackathon page
  before registering — do not rely on this document's dates once the 127
  meeting has passed.

## 2. Before the event (maintainer action + Claude-buildable prep)

- [ ] **(maintainer)** Subscribe to the IETF Hackathon mailing list.
- [ ] **(maintainer)** Create/confirm an IETF Datatracker login (needed to
      edit the hackathon wiki).
- [ ] **(maintainer)** Register N-PAMP as a hackathon project on the current
      meeting's Hackathon wiki page, naming a champion (the maintainer or a
      designee) and linking to `https://github.com/bubblefish-tech/npamp_protocol`.
      Suggested project blurb (edit freely): *"N-PAMP — a binary,
      post-quantum, multi-channel wire protocol for authenticated
      agent-to-agent communication. Bring your own implementation of the
      1.5-RTT handshake (spec/10) and record layer; we'll interop-test it live
      against our Go and Rust reference stacks."*
- [ ] **(maintainer)** Decide onsite vs. remote participation and register
      accordingly on the meeting's registration portal.
- [x] **(built this session)** A third-party-runnable interop kit exists:
      `hackathon/run-against-peer.sh` + `hackathon/THIRD-PARTY-QUICKSTART.md`
      — point any independent implementation at our Go or Rust reference
      stack over a real address, no repo checkout required on the peer's side
      beyond the published module/crate.
- [x] **(built this session)** A results template exists:
      `hackathon/IMPLEMENTATION-STATUS-TEMPLATE.md` (RFC 7942/BCP 205-shaped).
- [ ] **(maintainer, optional)** Skim the current hackathon wiki's project list
      shortly before the event for other projects that might make a plausible
      interop partner (e.g. another post-quantum transport, an agent-protocol
      project that could carry N-PAMP as its underlay).
- [ ] **(maintainer)** Bring: a laptop with a Go toolchain (matching
      `impl/go/go.mod`'s declared version) and a Rust toolchain (stable
      channel) pre-installed and this repository pre-cloned (hackathon Wi-Fi
      is not reliable for a fresh `git clone` + toolchain install on the day).

## 3. During the event

- [ ] Find (or recruit) a genuinely independent interop partner — someone
      running an N-PAMP implementation this project did not author. Per §1,
      the hackathon is explicitly non-competitive/collaborative, so this is a
      normal, expected activity, not a special favor to ask.
- [ ] Run `hackathon/run-against-peer.sh` in whichever role your partner's
      implementation needs (see `THIRD-PARTY-QUICKSTART.md` for the exact
      commands and the networking fallbacks for a NAT'd venue network).
- [ ] For every direction tested, fill in a row of
      `IMPLEMENTATION-STATUS-TEMPLATE.md` Part B **immediately**, including
      FAIL rows with the exact error text — a failed interop attempt with a
      recorded cause is more valuable to the spec than an unrecorded one.
- [ ] If a genuine spec ambiguity or defect surfaces (either side's behavior
      was defensible but the two sides disagreed), record it under Part A
      "Implementation experience" for both implementations and file a tracked
      issue against the draft/spec — this is exactly the "running code informs
      the standard" feedback loop the hackathon exists to produce (§1).
- [ ] Note whether any High/Sovereign-profile (post-quantum ML-DSA-87 /
      SecP384r1MLKEM1024) peer was available; if not, record that gap
      explicitly in Part C rather than silently only testing Standard.

## 4. After the event

- [ ] Fill in `IMPLEMENTATION-STATUS-TEMPLATE.md` Part C (session summary).
- [ ] Copy the filled-in template into a dated results file (e.g.
      `hackathon/results/ietf-127-hackathon.md`) so it is never overwritten by
      the next event's blank template.
- [ ] If the hackathon holds a closing demo/report-out session, present the
      interop results there (per §1's "running code" framing, a live
      demonstration is the natural way to report a hackathon's outcome; no
      specific demo-format requirement was found on the pages retrieved this
      session — re-check the current meeting's hackathon page for whether one
      is expected).
- [ ] Decide, with the maintainer, whether/how to reference the results in the
      Internet-Draft's Implementation Status considerations or in project
      communications — this is a publication decision reserved for the
      maintainer (see the project's public-vs-internal engineering-surface
      policy); this kit does not make that call.
- [ ] Record the interop milestone as fully "event-complete" in
      the project's internal task tracker only once a real
      third-party interop row exists in a dated results file — the checkbox
      state this session lands with reflects only the Claude-buildable kit,
      not event attendance.

## 5. Grading provenance for this kit

- The kit's own claim — "our Go and Rust reference stacks interoperate live,
  through this kit's wrapper" — was graded in this session by running
  `hackathon/run-against-peer.sh` for both directions against the other
  stack's existing binary (see this session's commit message for the captured
  output).
- The kit's Stage-3 conformance check reuses the exact commands already graded
  in CI: `go test -C impl/go ./... -count=1` (`.github/workflows/
  conformance.yml`, job `impl-go`) and `cargo test --manifest-path
  impl/rust/Cargo.toml` (`.github/workflows/interop.yml`'s dependency chain
  and `.github/workflows/conformance.yml`'s `rust` job).
- The IETF-hackathon facts in §1 were retrieved live this session from
  `ietf.org`/`wiki.ietf.org` (URLs cited above); they are **not** from
  training-data memory, per this project's research-discipline rules, and
  they are dated so a future reader knows to re-verify before relying on them.
