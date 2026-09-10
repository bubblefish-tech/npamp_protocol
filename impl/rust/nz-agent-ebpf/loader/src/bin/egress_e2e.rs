// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// Egress END-TO-END witness (the CgroupRedirect rung's live counterpart).
// Unlike `egress_redirect_demo` (map-level only), this performs a REAL
// `connect()` to a DEAD target that carries a registered waypoint, and confirms
// the kernel's `egress_redirect_connect4` program actually rewrote the
// destination to a live listener — empirically settling the
// `bpf_sock_addr::user_port` low-16-bit network byte-order the map-level demo
// could not (see that demo's header for the honest-scope caveats).
//
// Discriminator: the target (127.0.0.5:19998) has NOTHING listening, so WITHOUT
// a correct redirect `connect()` is refused; WITH a correct redirect the kernel
// steers it to the waypoint listener, which then accepts. Run as root
// (cgroup2 attach + CAP_BPF).

use std::net::{SocketAddr, SocketAddrV4, TcpListener, TcpStream};
use std::sync::mpsc;
use std::time::Duration;

use anyhow::Context as _;
use aya::maps::HashMap as AyaHashMap;
use aya::programs::{CgroupAttachMode, CgroupSockAddr};

use nz_agent::authz::AuthzTable;
use nz_agent::datapath::install_redirect;
use nz_agent::identity::SpiffeId;
use nz_agent_ebpf_common::{EgressKey, Waypoint};
use nz_agent_ebpf_loader::{EgressRedirectInstaller, RealAyaEgressBackend};

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
    let orig_dst: AyaHashMap<_, u64, EgressKey> = AyaHashMap::try_from(ebpf.take_map("EGRESS_ORIG_DST").context("take EGRESS_ORIG_DST")?)?;

    // The live waypoint: a real listener the redirect must steer to.
    let listener = TcpListener::bind("127.0.0.1:0").context("bind waypoint listener")?;
    let waypoint_addr: SocketAddrV4 = match listener.local_addr()? {
        SocketAddr::V4(a) => a,
        other => anyhow::bail!("expected ipv4 listener addr, got {other}"),
    };
    // A DEAD target: nothing listens here, so WITHOUT a correct redirect a
    // connect() is refused; WITH one, it lands on the waypoint listener.
    let target: SocketAddrV4 = "127.0.0.5:19998".parse().unwrap();
    println!("E2E: waypoint(listener)={waypoint_addr}  target(dead, nothing listening)={target}");

    // Install the authorized waypoint via the SAME seam a live nz-agent uses.
    let backend = RealAyaEgressBackend::new(waypoints);
    let mut installer = EgressRedirectInstaller::new(backend);
    let source = id("e2e-src");
    let destination = id("e2e-dst");
    installer.register_destination(destination.clone(), target, waypoint_addr);
    let mut authz = AuthzTable::new();
    authz.allow(source.clone(), destination.clone());
    install_redirect(&mut installer, &source, &destination, &authz).context("install authorized waypoint")?;
    println!("E2E: installed EGRESS_WAYPOINT[{target}] -> {waypoint_addr} (real bpf() map write, past the authz gate)");

    // Accept on the waypoint listener in a thread. Send the moment a
    // connection ARRIVES — do NOT read first: the client never writes any
    // bytes, so a blocking read would hang forever and mask a successful
    // accept (the connection reaching the listener IS the proof we want).
    let (tx, rx) = mpsc::channel();
    let accept_thread = std::thread::spawn(move || match listener.accept() {
        Ok((_s, peer)) => {
            tx.send(Ok(peer)).ok();
        }
        Err(e) => {
            tx.send(Err(e.to_string())).ok();
        }
    });

    // The REAL connect() to the dead target — intercepted by connect4, which
    // must rewrite the destination to the waypoint if the byte-order is right.
    let conn = TcpStream::connect_timeout(&SocketAddr::V4(target), Duration::from_secs(3));
    match conn {
        Ok(s) => {
            println!("E2E: connect() to the DEAD target SUCCEEDED (peer_addr={:?}) — the connect4 redirect fired", s.peer_addr());
            match rx.recv_timeout(Duration::from_secs(3)) {
                Ok(Ok(peer)) => println!(
                    "E2E: RESULT=CONFIRMED — the waypoint listener accepted a connection from {peer}; \
                     the egress connect4 redirect + bpf_sock_addr::user_port low-16-bit byte-order are EMPIRICALLY correct"
                ),
                other => println!("E2E: RESULT=INCONCLUSIVE — connect succeeded but the listener accept did not fire: {other:?}"),
            }
        }
        Err(e) => {
            println!(
                "E2E: RESULT=NOT-CONFIRMED — connect() to the dead target was NOT redirected (err: {e}); \
                 the kernel key-derivation / byte-order / attach did not steer it"
            );
        }
    }

    let n = orig_dst.iter().count();
    println!("E2E: EGRESS_ORIG_DST now holds {n} entry/entries (>=1 confirms the kernel program ran try_connect4 and stashed the original dst)");
    let _ = accept_thread.join();
    Ok(())
}
