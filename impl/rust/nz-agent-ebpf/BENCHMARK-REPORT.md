# BENCHMARK-REPORT — `nz-agent-ebpf` (honest non-race benchmark)

This is the live, measured record for this benchmark's own methodology requirement ("the
acceleration figure SHALL be measured on a non-`-race` build ... measured number reported
without rounding"). Every number below was read directly off a live run of
`loader/src/bin/bench_splice.rs`, `--release`, on this session's own WSL2 host — nothing here
is estimated, interpolated, or carried over from a different build.

## Measurement conditions (named hardware/kernel)

- **Host**: `ShawnS-A16-TUF`
- **CPU**: AMD Ryzen 7 7735HS with Radeon Graphics, 8 logical CPUs (per `/proc/cpuinfo`), first
  core reporting 3193.908 MHz at read time
- **Memory**: 24611036 kB total (`/proc/meminfo` `MemTotal`)
- **Kernel**: `6.6.87.2-microsoft-standard-WSL2 #1 SMP PREEMPT_DYNAMIC Thu Jun 5 18:30:46 UTC
  2025 x86_64` (WSL2; `uname -a` / `/proc/version`)
- **Build**: `cargo build --release --bin bench_splice` — Rust has no `-race`/TSan-equivalent
  instrumentation this build enables; `--release` is the honest analog this crate's own
  discipline uses (no debug assertions, no sanitizer/instrumentation), printed verbatim in the
  harness's own `conditions:` line every run so a reader never has to guess.
- Every run below was rebuilt-then-run with the source unchanged (the same `target/release/bench_splice`
  binary), executed as root (`wsl -u root`) for the SPLICE arm's `CAP_BPF` requirement.

## What is actually compared (read this before the numbers — flagged, not decided)

**This benchmark's own stated methodology calls for "non-`-race` iptables-baseline vs eBPF path."**
`bench_splice.rs`, as built (by earlier work, unmodified by this run), does NOT compare
against an `iptables`/`TPROXY` baseline. Its own header comment is explicit about what it
actually measures — quoting verbatim:

> BASELINE (userspace proxy copy): leg_a and leg_b are the accepted/client ends of two SEPARATE
> loopback TCP connections... A dedicated proxy thread does read(leg_a's peer) ->
> write(leg_b's peer) for every message... This is the "naive userspace proxy copy" the task
> asks to compare against.

So the comparison actually built and run is **userspace-proxy-copy vs eBPF sockmap splice**, not
**iptables-REDIRECT/TPROXY vs eBPF**. Both are real, honest baselines for a splice-style fast
path, but they are not the same baseline the stated methodology names, and
`DatapathStrategy::IptablesTproxy` (`nz-agent/src/datapath.rs`) is a REAL strategy this crate's
selector ladder already models — an `iptables`-arm harness reusing `capture::IptablesCapture`'s
rule construction is buildable, but is a separate piece of work, not something this
run-the-harness-and-record pass silently substitutes or decides on its own authority.

**FLAGGED, NOT DECIDED HERE: is a literal `iptables`-baseline arm required to
close this methodology gap, or does the userspace-proxy-copy baseline already built satisfy the intent (both
measure "the cost of NOT having a kernel-resident fast path")?**

Two further, smaller gaps against the stated methodology, also flagged rather than silently
patched:

- **"TCP_CRR/TCP_STREAM/P50/P99"**: this is netperf's own test-type vocabulary (`TCP_CRR` =
  connect-request-response rate; `TCP_STREAM` = bulk one-way throughput). `bench_splice.rs`
  measures neither literally — it times a request/response round trip over an
  ALREADY-ESTABLISHED connection, repeated N times, and reports P50/P95/P99 latency plus
  msg/s and MiB/s throughput. This is a real, honest latency/throughput measurement in the SAME
  spirit as `TCP_CRR`/`TCP_STREAM`, but it is not netperf and does not use those two named test
  modes.
- **"steering cost separated from PQC-handshake cost"**: `bench_splice.rs` never establishes an
  N-PAMP session at all (no KEM, no handshake, no AEAD) — every number below is PURE steering
  cost, trivially "separated" from a PQC-handshake cost that was never measured in the same run.
  The design doc's phrasing may have intended a harness that ALSO measures a full handshake and
  reports what fraction of end-to-end latency each part is; that comparison is not built here.

None of the three gaps above were closed by this task (out of scope for "run the bench harness
and record" as instructed) — they are recorded so the maintainer can decide, not silently
absorbed as "close enough."

## Measured results (verbatim, no rounding beyond what the harness itself prints)

### Run 1 — default config (n=5000, warmup=300, payload=64B)

```
BASELINE (userspace proxy copy): n=5000 payload=64B  min=53.55us mean=84.03us p50=78.35us p95=114.71us p99=157.76us max=1391.37us  throughput=11901 msg/s 0.726 MiB/s
SPLICE   (eBPF sockmap fast path): n=5000 payload=64B  min=3.00us mean=3.12us p50=3.04us p95=3.11us p99=3.88us max=27.69us  throughput=320818 msg/s 19.581 MiB/s
RESULT: splice mean latency is 0.04x the baseline mean latency (3.12us vs 84.03us) -- FASTER than the userspace-proxy-copy path
```

### Run 2 — same config, immediate re-run

```
BASELINE (userspace proxy copy): n=5000 payload=64B  min=57.71us mean=87.36us p50=82.78us p95=116.62us p99=149.98us max=1774.24us  throughput=11446 msg/s 0.699 MiB/s
SPLICE   (eBPF sockmap fast path): n=5000 payload=64B  min=3.03us mean=3.19us p50=3.06us p95=3.55us p99=4.14us max=83.66us  throughput=313588 msg/s 19.140 MiB/s
RESULT: splice mean latency is 0.04x the baseline mean latency (3.19us vs 87.36us) -- FASTER than the userspace-proxy-copy path
```

### Run 3 — same config, immediate re-run

```
BASELINE (userspace proxy copy): n=5000 payload=64B  min=53.07us mean=89.74us p50=79.81us p95=133.08us p99=200.96us max=2085.68us  throughput=11143 msg/s 0.680 MiB/s
SPLICE   (eBPF sockmap fast path): n=5000 payload=64B  min=2.97us mean=3.09us p50=3.00us p95=3.05us p99=3.94us max=45.67us  throughput=323344 msg/s 19.735 MiB/s
RESULT: splice mean latency is 0.03x the baseline mean latency (3.09us vs 89.74us) -- FASTER than the userspace-proxy-copy path
```

### Run 4 — larger sample (`BENCH_ITERATIONS=20000 BENCH_WARMUP=500`, payload=64B)

```
BASELINE (userspace proxy copy): n=20000 payload=64B  min=37.09us mean=91.22us p50=83.59us p95=130.53us p99=183.60us max=621.09us  throughput=10963 msg/s 0.669 MiB/s
SPLICE   (eBPF sockmap fast path): n=20000 payload=64B  min=3.06us mean=3.37us p50=3.16us p95=3.67us p99=6.71us max=401.49us  throughput=296545 msg/s 18.100 MiB/s
RESULT: splice mean latency is 0.04x the baseline mean latency (3.37us vs 91.22us) -- FASTER than the userspace-proxy-copy path
```

### Run 5 — larger payload (`BENCH_PAYLOAD_SIZE=1024`, n=5000)

```
BASELINE (userspace proxy copy): n=5000 payload=1024B  min=56.66us mean=85.00us p50=81.64us p95=108.78us p99=146.67us max=766.22us  throughput=11765 msg/s 11.489 MiB/s
SPLICE   (eBPF sockmap fast path): n=5000 payload=1024B  min=3.03us mean=3.18us p50=3.07us p95=3.09us p99=4.21us max=58.14us  throughput=314696 msg/s 307.321 MiB/s
RESULT: splice mean latency is 0.04x the baseline mean latency (3.18us vs 85.00us) -- FASTER than the userspace-proxy-copy path
```

## Reading the numbers honestly

- Across 5 runs (3 default-config repeats, one 4x-larger sample, one 16x-larger payload), the
  SPLICE arm's mean latency is consistently lower than the BASELINE arm's mean latency on this
  host by a baseline-mean/splice-mean ratio of 84.03/3.12=26.9x (run 1), 87.36/3.19=27.4x (run
  2), 89.74/3.09=29.0x (run 3), 91.22/3.37=27.1x (run 4), and 85.00/3.18=26.7x (run 5) — the
  harness's own printed figure is the inverse (splice-mean/baseline-mean, "0.03x"-"0.04x"). This
  report makes no claim about any other benchmark ratio measured elsewhere in this program; the
  above five ratios are the only numbers this report certifies.
- The SPLICE arm's `max` latency is noisy across runs (27.69us / 83.66us / 45.67us / 401.49us /
  58.14us) — consistent with occasional OS scheduling jitter on a shared WSL2 VM, not a
  systematic slowdown (p50/p95/p99 stay tight and consistent across all 5 runs).
- The SPLICE arm's sanity check (`bench_splice.rs`'s own "confirm the redirect actually fires
  before timing anything" gate) passed on every run; no numbers
  here were collected from a datapath that silently failed to redirect.
- Throughput scales as expected with payload size: MiB/s roughly 16x higher at 1024B than at 64B
  for the SPLICE arm (19.581 -> 307.321), consistent with a fixed per-message overhead dominating
  at small payload sizes.

## What this report does NOT cover (honest scope)

- No `iptables`-baseline arm (see the flagged gap above).
- No `TCP_CRR`/`TCP_STREAM` netperf-mode measurement (see the flagged gap above).
- No PQC-handshake-cost comparison in the same run (see the flagged gap above) — every number in
  this report is pure kernel-splice-vs-userspace-proxy steering cost, with zero N-PAMP session
  establishment measured.
- Single-host measurement only (this session's WSL2 VM). No cross-host/bare-metal-Linux
  reproduction was performed.
- Payload sizes tested: 64B (default) and 1024B. No sweep across a wider size range or under
  concurrent/multi-connection load.
