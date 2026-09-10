// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// A MAP-LEVEL demonstration for `tc_fallback`: adds the
// `clsact` qdisc to `lo`, loads+attaches the `tc_fallback` classifier
// program on ingress, then uses `TcFallbackInstaller<RealAyaTcBackend>` --
// the SAME code path a live `nz-agent` would use -- to (1) install an
// authz-APPROVED flow waypoint and (2) attempt a DENIED one. Prints enough
// for `bpftool prog show` + `bpftool map show`/`map dump` (run from the SAME
// `wsl` invocation) to independently confirm kernel-side residency.
//
// This is a MAP-LEVEL demo only: it does NOT send a real packet matching the
// registered flow and therefore does NOT witness the kernel's own header
// parse + DNAT rewrite + checksum fixups actually firing -- that is left
// to the live end-to-end test (`tc_fallback_e2e.rs`).

use std::net::SocketAddrV4;

use anyhow::Context as _;
use aya::maps::HashMap as AyaHashMap;
use aya::programs::{tc, SchedClassifier, TcAttachType};

use nz_agent::authz::AuthzTable;
use nz_agent::datapath::install_redirect;
use nz_agent::identity::SpiffeId;
use nz_agent_ebpf_common::{TcFlowKey, Waypoint};
use nz_agent_ebpf_loader::{waypoint_of, RealAyaTcBackend, TcFallbackInstaller};

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

fn key_hex(k: TcFlowKey) -> String {
    let mut bytes = Vec::with_capacity(16);
    bytes.extend_from_slice(&k.src_ip.to_ne_bytes());
    bytes.extend_from_slice(&k.dst_ip.to_ne_bytes());
    bytes.extend_from_slice(&k.src_port.to_ne_bytes());
    bytes.extend_from_slice(&k.dst_port.to_ne_bytes());
    bytes.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(" ")
}

fn waypoint_hex(w: Waypoint) -> String {
    let mut bytes = Vec::with_capacity(8);
    bytes.extend_from_slice(&w.waypoint_ip.to_ne_bytes());
    bytes.extend_from_slice(&w.waypoint_port.to_ne_bytes());
    bytes.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(" ")
}

fn main() -> anyhow::Result<()> {
    raise_memlock_rlimit();

    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/tc_fallback"))).context("Ebpf::load")?;
    println!("DEMO: eBPF object loaded into userspace representation: OK");

    match tc::qdisc_add_clsact("lo") {
        Ok(()) => println!("DEMO: qdisc_add_clsact(lo): OK"),
        Err(e) => println!("DEMO: qdisc_add_clsact(lo) non-fatal (already attached?): {e:#}"),
    }
    {
        let prog: &mut SchedClassifier = ebpf.program_mut("tc_fallback").context("find classifier program")?.try_into()?;
        prog.load().context("classifier.load()")?;
        prog.attach("lo", TcAttachType::Ingress).context("classifier.attach(lo, Ingress)")?;
        println!("DEMO: classifier program.load()+attach(lo, Ingress): OK");
    }

    let waypoints: AyaHashMap<_, TcFlowKey, Waypoint> = AyaHashMap::try_from(ebpf.take_map("TC_WAYPOINTS").context("take TC_WAYPOINTS map")?)?;
    println!("DEMO: took TC_WAYPOINTS map: OK");

    let backend = RealAyaTcBackend::new(waypoints);
    let mut installer = TcFallbackInstaller::new(backend);

    // ================= (1) an authz-APPROVED flow =================
    let source = id("workload-tc-src");
    let destination = id("workload-tc-dst");
    let src_addr: SocketAddrV4 = "10.0.0.1:5000".parse().unwrap();
    let dst_addr: SocketAddrV4 = "93.184.216.34:443".parse().unwrap();
    let waypoint_addr: SocketAddrV4 = "127.0.0.1:15006".parse().unwrap();

    installer.register_flow(destination.clone(), src_addr, dst_addr, waypoint_addr);
    let key = installer.key_of(&destination).expect("registered");
    println!("DEMO: registered tc flow key={} ({src_addr} -> {dst_addr})", key_hex(key));

    let mut authz = AuthzTable::new();
    authz.allow(source.clone(), destination.clone());
    let token = install_redirect(&mut installer, &source, &destination, &authz).context("install authorized tc flow waypoint")?;
    println!("DEMO: ALLOWED flow installed: source={} destination={} -- real bpf() HashMap::insert performed", token.source(), token.destination());
    println!("DEMO: bpftool-verifiable: TC_WAYPOINTS should hold key [{}] -> waypoint [{}]", key_hex(key), waypoint_hex(waypoint_of(waypoint_addr)));

    // ================= (2) a DENIED flow =================
    let source_denied = id("workload-tc-src-denied");
    let destination_denied = id("workload-tc-dst-denied");
    let denied_dst_addr: SocketAddrV4 = "203.0.113.9:443".parse().unwrap();
    installer.register_flow(destination_denied.clone(), src_addr, denied_dst_addr, waypoint_addr);
    let denied_key = installer.key_of(&destination_denied).expect("registered");
    let empty_authz = AuthzTable::new(); // no allow(): DENIED
    match install_redirect(&mut installer, &source_denied, &destination_denied, &empty_authz) {
        Ok(_) => anyhow::bail!("BUG: a denied flow installed -- the deny invariant was violated"),
        Err(e) => println!("DEMO: DENIED flow correctly refused: {e}"),
    }
    println!("DEMO: bpftool-verifiable: TC_WAYPOINTS must NOT contain key [{}] (registered but never installed)", key_hex(denied_key));

    println!("DEMO: READY -- sleeping 8s for external bpftool inspection of TC_WAYPOINTS/prog list/filter list");
    std::thread::sleep(std::time::Duration::from_secs(8));
    println!("DEMO: exiting; programs/maps detach on drop");
    Ok(())
}
