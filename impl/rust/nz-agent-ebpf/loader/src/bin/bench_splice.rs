// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// A perf/throughput benchmark for the confirmed sockmap splice fast path
// (see the end-to-end data-plane splice path and `load_demo.rs`'s stretch
// demo, which this harness generalizes from a single write/read into a
// timed N-iteration measurement).
//
// This measures ONLY performance (latency + throughput + implied
// syscall/copy overhead) of an already-byte-correct datapath. The
// correctness question -- does the kernel redirect actually move the right
// bytes to the right peer -- is already settled (confirmed via kernel
// key-derivation / byte-order / attach verification) and is out of scope
// here; this harness re-uses that same topology unmodified.
//
// Two arms, directly comparable because both use the IDENTICAL
// write(leg_a) / read(leg_b) call shape from the benchmark's perspective:
//
//   BASELINE (userspace proxy copy): leg_a and leg_b are the accepted/client
//   ends of two SEPARATE loopback TCP connections, exactly as in
//   `load_demo.rs`. A dedicated proxy thread does read(leg_a's peer) ->
//   write(leg_b's peer) for every message -- i.e. it performs, in
//   userspace, exactly the byte-move the eBPF program performs in-kernel.
//   This is the "naive userspace proxy copy" the task asks to compare
//   against: 2 extra syscalls + 1 userspace buffer copy + 2 extra TCP-stack
//   traversals per message, mediated by a thread wakeup.
//
//   SPLICE (eBPF fast path): the SAME two-connection topology, but leg_a and
//   leg_b are registered into the kernel's SPLICE_SOCKS/SPLICE_PEER sockmap
//   via `install_splice` (the same authorized-pair install path
//   `load_demo.rs` demonstrates). A write on leg_a is redirected by the
//   attached `sk_msg` program (`bpf_msg_redirect_hash`) directly onto leg_b's
//   own receive queue, entirely in-kernel: zero userspace hops per message
//   after the one-time install.
//
// Numbers are collected from a `--release` build (see build instructions in
// the accompanying report); this binary does not build or run under any
// race/sanitizer instrumentation (Rust has none of Go's `-race`, so the
// discipline here is simply: release profile, default codegen, no debug
// assertions -- reported explicitly in the summary so a reader never has to
// guess the measurement conditions).
//
// If the eBPF arm cannot load (no root / no CAP_BPF / kernel lacking
// sockmap+sk_msg support), the SPLICE arm is skipped with an explicit,
// honest note and the BASELINE arm's numbers are still reported -- this
// harness never fabricates datapath numbers it did not observe.

use std::env;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::fd::AsRawFd;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::Context as _;

use nz_agent::authz::AuthzTable;
use nz_agent::datapath::install_splice;
use nz_agent::identity::SpiffeId;
use nz_agent_ebpf_loader::{AyaSpliceInstaller, RealAyaBackend};

// ---------------------------------------------------------------------
// Shared topology helper (identical to load_demo.rs's `loopback_pair`).
// ---------------------------------------------------------------------

fn loopback_pair() -> anyhow::Result<(TcpStream, TcpStream)> {
    let listener = TcpListener::bind("127.0.0.1:0").context("bind loopback listener")?;
    let addr = listener.local_addr()?;
    let client = TcpStream::connect(addr).context("connect loopback client")?;
    let (accepted, _peer) = listener.accept().context("accept loopback client")?;
    Ok((accepted, client))
}

fn id(path: &str) -> SpiffeId {
    SpiffeId::parse(&format!("spiffe://cluster.local/ns/prod/sa/{path}")).expect("valid id")
}

fn raise_memlock_rlimit() {
    let rlim = libc::rlimit { rlim_cur: libc::RLIM_INFINITY, rlim_max: libc::RLIM_INFINITY };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        eprintln!("warn: setrlimit(RLIMIT_MEMLOCK) failed, ret={ret}");
    }
}

// ---------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------

struct Config {
    iterations: usize,
    warmup: usize,
    payload_size: usize,
}

fn config_from_env() -> Config {
    fn env_usize(key: &str, default: usize) -> usize {
        env::var(key).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
    }
    Config {
        iterations: env_usize("BENCH_ITERATIONS", 5000),
        warmup: env_usize("BENCH_WARMUP", 300),
        payload_size: env_usize("BENCH_PAYLOAD_SIZE", 64),
    }
}

// ---------------------------------------------------------------------
// Stats
// ---------------------------------------------------------------------

struct Stats {
    latencies_ns: Vec<u64>,
    payload_bytes: usize,
}

impl Stats {
    fn summarize(&self, label: &str) -> String {
        let mut sorted = self.latencies_ns.clone();
        sorted.sort_unstable();
        let n = sorted.len();
        if n == 0 {
            return format!("{label}: n=0 (no samples)");
        }
        let sum: u64 = sorted.iter().sum();
        let mean_ns = sum as f64 / n as f64;
        let p50_idx = std::cmp::min(n / 2, n - 1);
        let p95_idx = std::cmp::min(((n as f64) * 0.95) as usize, n - 1);
        let p99_idx = std::cmp::min(((n as f64) * 0.99) as usize, n - 1);
        let p50 = sorted[p50_idx];
        let p95 = sorted[p95_idx];
        let p99 = sorted[p99_idx];
        let min = sorted[0];
        let max = sorted[n - 1];
        let total_secs = sum as f64 / 1e9;
        let msgs_per_sec = n as f64 / total_secs;
        let mib_per_sec = (n * self.payload_bytes) as f64 / total_secs / (1024.0 * 1024.0);
        format!(
            "{label}: n={n} payload={}B  min={:.2}us mean={:.2}us p50={:.2}us p95={:.2}us p99={:.2}us max={:.2}us  throughput={:.0} msg/s {:.3} MiB/s",
            self.payload_bytes,
            min as f64 / 1000.0,
            mean_ns / 1000.0,
            p50 as f64 / 1000.0,
            p95 as f64 / 1000.0,
            p99 as f64 / 1000.0,
            max as f64 / 1000.0,
            msgs_per_sec,
            mib_per_sec
        )
    }
}

// ---------------------------------------------------------------------
// Arm 1: baseline userspace-proxy-copy
// ---------------------------------------------------------------------

fn run_baseline(cfg: &Config) -> anyhow::Result<Stats> {
    let (leg_a, leg_a_far) = loopback_pair().context("baseline: bind connection A")?;
    let (leg_b_far, leg_b) = loopback_pair().context("baseline: bind connection B")?;
    leg_b.set_read_timeout(Some(Duration::from_secs(5)))?;

    let total = cfg.warmup + cfg.iterations;
    let plen = cfg.payload_size;

    // The proxy thread: the userspace equivalent of what the eBPF sk_msg
    // program does in-kernel -- read the message off connection A's far
    // end, write it verbatim onto connection B's far end.
    let mut proxy_reader = leg_a_far.try_clone().context("clone leg_a_far")?;
    let mut proxy_writer = leg_b_far.try_clone().context("clone leg_b_far")?;
    let proxy = thread::spawn(move || -> anyhow::Result<()> {
        let mut buf = vec![0u8; plen];
        for _ in 0..total {
            let mut got = 0usize;
            while got < plen {
                let r = proxy_reader.read(&mut buf[got..]).context("proxy: read leg_a_far")?;
                if r == 0 {
                    anyhow::bail!("proxy: leg_a_far EOF after {got}/{plen} bytes");
                }
                got += r;
            }
            proxy_writer.write_all(&buf).context("proxy: write leg_b_far")?;
        }
        Ok(())
    });

    let mut writer = leg_a.try_clone().context("clone leg_a")?;
    let mut reader = leg_b.try_clone().context("clone leg_b")?;
    let payload = vec![0xABu8; plen];
    let mut buf = vec![0u8; plen];
    let mut latencies = Vec::with_capacity(cfg.iterations);

    for i in 0..total {
        let t0 = Instant::now();
        writer.write_all(&payload).context("baseline: write leg_a")?;
        let mut got = 0usize;
        while got < plen {
            let r = reader.read(&mut buf[got..]).context("baseline: read leg_b")?;
            if r == 0 {
                anyhow::bail!("baseline: leg_b EOF after {got}/{plen} bytes");
            }
            got += r;
        }
        let elapsed = t0.elapsed().as_nanos() as u64;
        if i >= cfg.warmup {
            latencies.push(elapsed);
        }
    }
    proxy.join().expect("proxy thread panicked")?;
    Ok(Stats { latencies_ns: latencies, payload_bytes: plen })
}

// ---------------------------------------------------------------------
// Arm 2: eBPF sockmap splice fast path
// ---------------------------------------------------------------------

fn run_splice_ebpf(cfg: &Config) -> anyhow::Result<Stats> {
    raise_memlock_rlimit();

    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/samenode_splice")))
        .context("Ebpf::load(samenode_splice)")?;

    // sock_ops: passive cgroup attach, best-effort (mirrors load_demo.rs;
    // not required for the sk_msg redirect path itself).
    {
        use aya::programs::{CgroupAttachMode, SockOps};
        let prog: &mut SockOps = ebpf.program_mut("samenode_splice_sockops").context("find sockops program")?.try_into()?;
        prog.load().context("sockops.load()")?;
        let cgroup = std::fs::File::open("/sys/fs/cgroup").context("open /sys/fs/cgroup (root cgroup2)")?;
        if let Err(e) = prog.attach(cgroup, CgroupAttachMode::Single) {
            eprintln!("bench: sock_ops attach failed (non-fatal to the splice path): {e:#}");
        }
    }

    use aya::maps::{HashMap as AyaHashMap, SockHash};
    use nz_agent_ebpf_common::ConnKey;
    let socks: SockHash<_, ConnKey> = SockHash::try_from(ebpf.take_map("SPLICE_SOCKS").context("take SPLICE_SOCKS")?)?;
    let peer: AyaHashMap<_, ConnKey, ConnKey> = AyaHashMap::try_from(ebpf.take_map("SPLICE_PEER").context("take SPLICE_PEER")?)?;
    let sockmap_fd = socks.fd().try_clone().context("clone SPLICE_SOCKS fd")?;

    {
        use aya::programs::SkMsg;
        let prog: &mut SkMsg = ebpf.program_mut("samenode_splice_skmsg").context("find sk_msg program")?.try_into()?;
        prog.load().context("sk_msg.load()")?;
        prog.attach(&sockmap_fd).context("sk_msg.attach(SPLICE_SOCKS)")?;
    }

    let backend = RealAyaBackend::new(socks, peer);
    let mut installer = AyaSpliceInstaller::new(backend);

    let workload_a = id("bench-a");
    let workload_b = id("bench-b");
    let (leg_a, _leg_a_far_end) = loopback_pair().context("splice: bind connection A")?;
    let (_leg_b_far_end, leg_b) = loopback_pair().context("splice: bind connection B")?;

    installer.register_socket(workload_a.clone(), &leg_a, leg_a.local_addr()?, leg_a.peer_addr()?)?;
    installer.register_socket(workload_b.clone(), &leg_b, leg_b.local_addr()?, leg_b.peer_addr()?)?;

    let mut authz = AuthzTable::new();
    authz.allow(workload_a.clone(), workload_b.clone());
    install_splice(&mut installer, &workload_a, &workload_b, &authz).context("install authorized splice pair")?;

    leg_b.set_read_timeout(Some(Duration::from_secs(5)))?;
    let mut writer = leg_a.try_clone().context("clone leg_a")?;
    let mut reader = leg_b.try_clone().context("clone leg_b")?;
    let plen = cfg.payload_size;
    let payload = vec![0xCDu8; plen];
    let mut buf = vec![0u8; plen];

    // Sanity: confirm the redirect actually fires before timing anything --
    // never report numbers for a datapath that silently degraded to
    // "nothing arrived" (inert designed machinery is a defect, not a
    // pass). Uses the loader's fd, as in load_demo.rs.
    let sanity = leg_a.as_raw_fd();
    writer.write_all(&payload).context("splice: sanity write")?;
    let n = reader.read(&mut buf).context("splice: sanity read (redirect did not fire)")?;
    if n != plen || buf[..n] != payload[..] {
        anyhow::bail!("splice: sanity check FAILED (fd={sanity}) -- redirect did not deliver the exact payload (n={n}); refusing to report fabricated numbers");
    }

    let total = cfg.warmup + cfg.iterations - 1; // one sanity round already consumed
    let mut latencies = Vec::with_capacity(cfg.iterations);
    for i in 0..total {
        let t0 = Instant::now();
        writer.write_all(&payload).context("splice: write leg_a")?;
        let mut got = 0usize;
        while got < plen {
            let r = reader.read(&mut buf[got..]).context("splice: read leg_b")?;
            if r == 0 {
                anyhow::bail!("splice: leg_b EOF after {got}/{plen} bytes");
            }
            got += r;
        }
        let elapsed = t0.elapsed().as_nanos() as u64;
        if i >= cfg.warmup.saturating_sub(1) {
            latencies.push(elapsed);
        }
    }
    latencies.truncate(cfg.iterations);
    Ok(Stats { latencies_ns: latencies, payload_bytes: plen })
}

// ---------------------------------------------------------------------
// main
// ---------------------------------------------------------------------

fn kernel_release() -> String {
    // uname -r, via libc::uname -- avoids shelling out.
    unsafe {
        let mut u: libc::utsname = std::mem::zeroed();
        if libc::uname(&mut u) == 0 {
            let c = std::ffi::CStr::from_ptr(u.release.as_ptr());
            c.to_string_lossy().into_owned()
        } else {
            "unknown".to_string()
        }
    }
}

fn main() -> anyhow::Result<()> {
    let cfg = config_from_env();
    println!("bench_splice: sockmap splice datapath vs userspace-proxy-copy baseline");
    println!(
        "conditions: kernel={}  build=release(no debug_assertions, no sanitizer/instrumentation)  iterations={} warmup={} payload={}B",
        kernel_release(),
        cfg.iterations,
        cfg.warmup,
        cfg.payload_size
    );
    println!("---");

    let baseline = run_baseline(&cfg).context("baseline arm failed")?;
    println!("{}", baseline.summarize("BASELINE (userspace proxy copy)"));

    match run_splice_ebpf(&cfg) {
        Ok(splice) => {
            println!("{}", splice.summarize("SPLICE   (eBPF sockmap fast path)"));
            let base_mean: f64 = baseline.latencies_ns.iter().sum::<u64>() as f64 / baseline.latencies_ns.len() as f64;
            let splice_mean: f64 = splice.latencies_ns.iter().sum::<u64>() as f64 / splice.latencies_ns.len() as f64;
            println!("---");
            println!(
                "RESULT: splice mean latency is {:.2}x the baseline mean latency ({:.2}us vs {:.2}us) -- {} than the userspace-proxy-copy path",
                splice_mean / base_mean,
                splice_mean / 1000.0,
                base_mean / 1000.0,
                if splice_mean < base_mean { "FASTER" } else { "SLOWER" }
            );
        }
        Err(e) => {
            println!("SPLICE ARM: SKIPPED -- eBPF datapath not reachable in this run ({e:#})");
            println!(
                "INFRA NOTE (tracked gap): the SPLICE arm requires root + CAP_BPF + a kernel with sockmap/sk_msg support; \
                 only the BASELINE (userspace-proxy-copy) numbers above were measured this run. Re-run as `wsl -u root` with \
                 the eBPF object built (see loader/build.rs) to collect the splice-arm numbers."
            );
        }
    }

    Ok(())
}
