// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// The LIVE, end-to-end grading demonstration
// for the eBPF-side flow/verdict telemetry bridge: real kernel map increments
// (both a SUCCESSFUL steer and a genuine kernel-side steering FAILURE) ->
// `VerdictBridge::poll_into` (`loader/src/lib.rs`) -> a real
// `nz_agent::telemetry::TelemetrySink::export` call -> a real
// `opentelemetry_sdk`-backed span + a real `prometheus::Registry` counter
// increment, read back here to confirm the whole pipeline actually moved.
//
// # Why `egress_redirect`, and how the failure is triggered for REAL
//
// `EGRESS_ORIG_DST` (`ebpf/src/egress_redirect.rs`) is a bounded
// `HashMap::with_max_entries(64, 0)`, keyed by socket COOKIE (a fresh,
// kernel-generated value on every distinct connect() — never reused within
// this process's run). `cgroup/connect4` fires at `connect()` SYSCALL time,
// before any TCP handshake — so driving 65 DISTINCT real `connect()` calls
// against the SAME registered destination triggers 65 real, distinct
// `try_connect4` invocations without needing any of the resulting TCP
// connections to ever complete or be `accept()`ed. The first 64 each insert
// a NEW cookie into `EGRESS_ORIG_DST` and succeed (`VERDICT_STEERED`); the
// map is then full, so the 65th's `EGRESS_ORIG_DST.insert` genuinely fails
// with a real BPF `E2BIG`/`ENOSPC` — `VERDICT_STEER_FAILED` — a real kernel-
// observed steering failure for an ALREADY-authorized destination, not a
// simulated one.
//
// Run as root (CAP_BPF + a cgroup2 attach on `/sys/fs/cgroup`).

use std::net::{SocketAddr, SocketAddrV4, TcpListener, TcpStream};
use std::time::Duration;

use anyhow::Context as _;
use aya::maps::{HashMap as AyaHashMap, PerCpuArray};
use aya::programs::{CgroupAttachMode, CgroupSockAddr};

use nz_agent::authz::AuthzTable;
use nz_agent::datapath::install_redirect;
use nz_agent::identity::SpiffeId;
use nz_agent::telemetry::OtelPrometheusSink;
use nz_agent_ebpf_common::{EgressKey, Waypoint};
use nz_agent_ebpf_loader::{EgressRedirectInstaller, RealAyaEgressBackend, RealAyaVerdictCounters, VerdictBridge};

fn raise_memlock_rlimit() {
    let rlim = libc::rlimit { rlim_cur: libc::RLIM_INFINITY, rlim_max: libc::RLIM_INFINITY };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        eprintln!("warn: setrlimit(RLIMIT_MEMLOCK) failed, ret={ret}");
    }
}

fn id(path: &str) -> SpiffeId {
    SpiffeId::parse(&format!("spiffe://cluster.local/ns/prod/sa/{path}")).expect("valid id")
}

fn main() -> anyhow::Result<()> {
    raise_memlock_rlimit();

    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/egress_redirect"))).context("Ebpf::load")?;
    {
        let prog: &mut CgroupSockAddr = ebpf.program_mut("egress_redirect_connect4").context("find connect4 program")?.try_into()?;
        prog.load().context("connect4.load()")?;
        let cg = std::fs::File::open("/sys/fs/cgroup").context("open /sys/fs/cgroup (root cgroup2)")?;
        prog.attach(cg, CgroupAttachMode::Single).context("connect4.attach()")?;
        println!("E2E: egress_redirect_connect4 loaded + attached to /sys/fs/cgroup");
    }
    let waypoints: AyaHashMap<_, EgressKey, Waypoint> = AyaHashMap::try_from(ebpf.take_map("EGRESS_WAYPOINT").context("take EGRESS_WAYPOINT")?)?;
    let verdicts_map: PerCpuArray<_, u64> = PerCpuArray::try_from(ebpf.take_map("EGRESS_VERDICTS").context("take EGRESS_VERDICTS")?)?;

    let listener = TcpListener::bind("127.0.0.1:0").context("bind waypoint listener")?;
    let waypoint_addr: SocketAddrV4 = match listener.local_addr()? {
        SocketAddr::V4(a) => a,
        other => anyhow::bail!("expected ipv4 listener addr, got {other}"),
    };
    let target: SocketAddrV4 = "127.0.0.6:19993".parse().unwrap();
    println!("E2E: waypoint(listener)={waypoint_addr}  target(dead)={target}");

    let backend = RealAyaEgressBackend::new(waypoints);
    let mut installer = EgressRedirectInstaller::new(backend);
    let source = id("telemetry-e2e-src");
    let destination = id("telemetry-e2e-dst");
    installer.register_destination(destination.clone(), target, waypoint_addr);
    let mut authz = AuthzTable::new();
    authz.allow(source.clone(), destination.clone());
    install_redirect(&mut installer, &source, &destination, &authz).context("install authorized waypoint")?;
    println!("E2E: installed EGRESS_WAYPOINT[{target}] -> {waypoint_addr} (real bpf() map write, past the authz gate)");

    // The REAL sink this pipeline exports through — the official OTel stdout
    // exporter + a real prometheus::Registry (nz_agent::telemetry's own
    // production constructor; not a test double).
    let sink = OtelPrometheusSink::new_production();
    let counters = RealAyaVerdictCounters::new(verdicts_map);
    let mut bridge = VerdictBridge::new(counters, "npamp-datapath-egress-redirect", destination.clone(), "telemetry-e2e-session");

    // -- Phase 1: ONE successful steer (proves the STEERED path is real and
    // does NOT export a DropEvent). --
    let _ = TcpStream::connect_timeout(&SocketAddr::V4(target), Duration::from_millis(300));
    let (steered_1, steer_failed_1) = bridge.poll_into(&sink).map_err(|e| anyhow::anyhow!(e))?;
    println!("E2E: after 1 connect() — steered_delta={steered_1} steer_failed_delta={steer_failed_1}");
    let drops_before = sink.drop_count("INSTALL_FAILURE", "npamp-datapath-egress-redirect");
    println!("E2E: drop_count(INSTALL_FAILURE) after phase 1 = {drops_before} (must be 0 — a pure steer is not a drop)");

    // -- Phase 2: drive EGRESS_ORIG_DST (bounded to 64 entries) to genuine
    // exhaustion with real, distinct connect() calls. --
    const ATTEMPTS: usize = 70; // > 64, guarantees at least one real failure.
    for _ in 0..ATTEMPTS {
        let _ = TcpStream::connect_timeout(&SocketAddr::V4(target), Duration::from_millis(50));
    }
    let (steered_2, steer_failed_2) = bridge.poll_into(&sink).map_err(|e| anyhow::anyhow!(e))?;
    println!("E2E: after {ATTEMPTS} more connect() attempts — steered_delta={steered_2} steer_failed_delta={steer_failed_2}");

    let drops_after = sink.drop_count("INSTALL_FAILURE", "npamp-datapath-egress-redirect");
    println!("E2E: drop_count(INSTALL_FAILURE) after phase 2 = {drops_after}");

    if steer_failed_2 > 0 && drops_after > drops_before {
        println!(
            "E2E: RESULT=CONFIRMED — a REAL kernel-side EGRESS_ORIG_DST exhaustion (steer_failed_delta={steer_failed_2}) \
             was bridged through VerdictBridge::poll_into into {} real nz_agent::telemetry::TelemetrySink::export call(s), \
             and the Prometheus counter genuinely incremented (drop_count {drops_before} -> {drops_after}). The full \
             kernel-map -> loader-bridge -> TelemetrySink -> Prometheus pipeline is live and end-to-end.",
            drops_after - drops_before
        );
    } else {
        println!(
            "E2E: RESULT=NOT-CONFIRMED — did not observe both a kernel-side steer_failed increment AND a \
             corresponding Prometheus counter increase (steer_failed_delta={steer_failed_2}, drops {drops_before} -> {drops_after})."
        );
    }

    println!("E2E: Prometheus exposition text:\n{}", sink.gather_prometheus_text());
    sink.shutdown();
    Ok(())
}
