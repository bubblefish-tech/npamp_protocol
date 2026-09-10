// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// `inbound_lookup`'s live END-TO-END witness (the live counterpart
// `inbound_lookup_demo.rs` itself says it lacks: "does NOT dial a real
// connection ... does NOT witness the kernel's own bpf_sk_assign actually
// steering a live inbound SYN"). Unlike that map-level demo, this performs a
// REAL `connect()` to a DEAD address (nothing bound there) that has been
// registered in `INBOUND_LISTEN`, and confirms the kernel's
// `inbound_lookup_select` program actually assigned delivery to the real
// listener — empirically settling `InboundKey`'s byte order (`dest_ip`
// network order, `dest_port` HOST order — the asymmetric convention
// `nz_agent_ebpf_loader::inbound_key_of` documents but which was, before this
// binary, confirmed only against the uapi struct comment, never against a
// live kernel).
//
// Discriminator: the destination (127.0.0.1:19996) has NOTHING bound to it —
// no `bind()`, no `listen()` — so WITHOUT a correct `sk_lookup` assignment a
// `connect()` there is refused (ECONNREFUSED, the kernel finds no matching
// socket and no assignment was made); WITH a correct assignment the kernel
// delivers the SYN to the registered listener transparently (the packet's
// own header is never rewritten — `bpf_sk_assign` operates purely at the
// socket-lookup layer — so the reply is still addressed as coming FROM
// 127.0.0.1:19996 from the client's point of view, and the handshake
// completes normally). Run as root (CAP_BPF + a netns `sk_lookup` attach).

use std::net::{SocketAddr, SocketAddrV4, TcpListener, TcpStream};
use std::sync::mpsc;
use std::time::Duration;

use anyhow::Context as _;
use aya::maps::{PerCpuArray, SockHash};
use aya::programs::SkLookup;

use nz_agent::authz::AuthzTable;
use nz_agent::datapath::install_redirect;
use nz_agent::identity::SpiffeId;
use nz_agent_ebpf_common::InboundKey;
use nz_agent_ebpf_loader::{InboundLookupInstaller, RealAyaInboundBackend};

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

    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/inbound_lookup"))).context("Ebpf::load")?;
    {
        let prog: &mut SkLookup = ebpf.program_mut("inbound_lookup_select").context("find sk_lookup program")?.try_into()?;
        prog.load().context("sk_lookup.load()")?;
        let netns = std::fs::File::open("/proc/self/ns/net").context("open /proc/self/ns/net")?;
        prog.attach(netns).context("sk_lookup.attach(netns)")?;
        println!("E2E: inbound_lookup_select loaded + attached to this process's netns");
    }
    let listeners: SockHash<_, InboundKey> = SockHash::try_from(ebpf.take_map("INBOUND_LISTEN").context("take INBOUND_LISTEN")?)?;
    let verdicts: PerCpuArray<_, u64> = PerCpuArray::try_from(ebpf.take_map("INBOUND_VERDICT").context("take INBOUND_VERDICT")?)?;

    // The REAL listener the redirect must steer to — bound to an unrelated
    // ephemeral port, never to the dead target itself.
    let agent_listener = TcpListener::bind("127.0.0.1:0").context("bind agent listener")?;
    let agent_addr: SocketAddrV4 = match agent_listener.local_addr()? {
        SocketAddr::V4(a) => a,
        other => anyhow::bail!("expected ipv4 listener addr, got {other}"),
    };
    // A DEAD destination: nothing is bound here at all. Without a correct
    // sk_lookup assignment, connecting here is refused outright.
    let dest: SocketAddrV4 = "127.0.0.1:19996".parse().unwrap();
    println!("E2E: agent_listener(real)={agent_addr}  dest(dead, nothing bound)={dest}");

    // Install the authorized inbound listener via the SAME seam a live
    // nz-agent uses — same code path as inbound_lookup_demo.rs.
    let backend = RealAyaInboundBackend::new(listeners);
    let mut installer = InboundLookupInstaller::new(backend);
    let source = id("e2e-peer-any");
    let destination = id("e2e-svc-inbound");
    installer.register_listener(destination.clone(), &agent_listener, dest);
    let mut authz = AuthzTable::new();
    authz.allow(source.clone(), destination.clone());
    install_redirect(&mut installer, &source, &destination, &authz).context("install authorized inbound listener")?;
    println!("E2E: installed INBOUND_LISTEN[{dest}] -> fd (real bpf() SockHash::insert, past the authz gate)");

    // Accept on the real listener in a thread. Send the moment a connection
    // ARRIVES — do NOT read first (the client never writes any bytes).
    let (tx, rx) = mpsc::channel();
    let accept_thread = std::thread::spawn(move || match agent_listener.accept() {
        Ok((_s, peer)) => {
            tx.send(Ok(peer)).ok();
        }
        Err(e) => {
            tx.send(Err(e.to_string())).ok();
        }
    });

    // The REAL connect() to the dead destination — the kernel's sk_lookup
    // hook decides, per-packet, which live socket receives this SYN.
    let conn = TcpStream::connect_timeout(&SocketAddr::V4(dest), Duration::from_secs(3));
    match conn {
        Ok(s) => {
            println!("E2E: connect() to the DEAD destination SUCCEEDED (local={:?}) — the sk_lookup assignment fired", s.local_addr());
            match rx.recv_timeout(Duration::from_secs(3)) {
                Ok(Ok(peer)) => println!(
                    "E2E: RESULT=CONFIRMED — the real listener accepted a connection from {peer}; \
                     inbound_lookup_select's bpf_sk_assign + InboundKey byte order (dest_ip network-order, \
                     dest_port HOST-order) are EMPIRICALLY correct"
                ),
                other => println!("E2E: RESULT=INCONCLUSIVE — connect succeeded but the listener accept did not fire: {other:?}"),
            }
        }
        Err(e) => {
            println!(
                "E2E: RESULT=NOT-CONFIRMED — connect() to the dead destination was NOT steered (err: {e}); \
                 the kernel key-derivation / byte-order / attach did not assign it"
            );
        }
    }

    // The kernel-side verdict counters, read as a corroborating
    // diagnostic: a nonzero `steered` proves `INBOUND_LISTEN`'s
    // `redirect_sk_lookup` matched this exact destination (a genuine
    // ENOENT/no-match is never counted — see the kernel program's own
    // module docs).
    let steered: u64 = verdicts.get(&0, 0)?.iter().sum();
    let steer_failed: u64 = verdicts.get(&1, 0)?.iter().sum();
    println!("E2E: INBOUND_VERDICT — steered={steered} steer_failed={steer_failed}");

    let _ = accept_thread.join();
    Ok(())
}
