// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// `tc_fallback`'s live END-TO-END witness (the live counterpart
// `tc_fallback_demo.rs` itself says it lacks: "does NOT send a real packet
// matching the registered flow and therefore does NOT witness the kernel's
// own header parse + DNAT rewrite + checksum fixups actually firing"). Sends
// a REAL SYN on `lo` for a flow registered in `TC_WAYPOINTS`, and confirms
// the kernel's own socket-delivery layer received it addressed to the
// WAYPOINT rather than the original (dead) destination.
//
// # Why this is a DESTINATION-REWRITE witness, not a full-handshake witness
// (a genuine finding, not a stub)
//
// Unlike `egress_redirect` (rewrites `ctx.user_ip4`/`user_port` on the
// CONNECTING SOCKET'S OWN STATE before the handshake starts) and
// `inbound_lookup` (`bpf_sk_assign` changes only which LOCAL SOCKET receives
// a packet, never the packet's own header bytes), `tc_fallback` mutates the
// packet's IP/TCP header IN PLACE at the TC-ingress layer, downstream of
// where the CLIENT's own connecting socket already recorded its expected
// peer (`dest`, the ORIGINAL destination) at `connect()` time. Reading
// `ebpf/src/tc_fallback.rs`'s own source (this session) confirms it rewrites
// ONLY `IP_DST_OFFSET`/`TCP_DST_PORT_OFFSET` — there is no reverse (SNAT)
// rewrite of the WAYPOINT's reply traffic back to look like it came from
// `dest`, and no conntrack integration. So the client's own `SYN_SENT`
// socket state (keyed by its own local port + the ORIGINAL destination) will
// not recognize a reply whose source is the waypoint's real address, and the
// handshake will not complete end-to-end purely from the CLIENT socket's
// point of view — a genuine, documented limitation of this fixed one-way-DNAT
// sub-unit, not a bug this e2e is expected to paper over.
//
// What CAN be, and IS, empirically confirmed here: whether the rewrite fires
// at all, and whether it lands the packet at the REAL waypoint listener. The
// PRIMARY witness is an independent raw `AF_PACKET` capture on `lo` for a
// genuine TCP SYN+ACK sent FROM the waypoint's own port back to the client's
// (fixed, not ephemeral) source port — proof the waypoint's own TCP stack
// received the rewritten SYN and replied to it as a legitimate new
// connection. `/proc/net/tcp`'s SYN_RECV state was tried FIRST and abandoned
// as the confirmation signal: iterating on this e2e on this exact host
// showed the packet capture DOES observe a real waypoint-sent SYN+ACK while
// NO SYN_RECV row ever appears in `/proc/net/tcp` OR `ss -tan` for it — this
// kernel answers the SYN via stateless SYN cookies, which record no
// request_sock at all, so absence of a SYN_RECV row is not evidence of
// anything and `/proc/net/tcp` is kept here only as a secondary, honestly
// labeled diagnostic. This settles `TcFlowKey`'s byte-order key derivation
// against a live kernel (previously grounded only against the wire format,
// per RFC 791/793, never witnessed against an actual redirected packet).
//
// Run as root (CAP_BPF + a `clsact` qdisc attach on `lo`).

use std::ffi::CString;
use std::io::Read;
use std::net::{SocketAddrV4, TcpListener};
use std::os::fd::FromRawFd;
use std::time::{Duration, Instant};

use anyhow::Context as _;
use aya::maps::{HashMap as AyaHashMap, PerCpuArray};
use aya::programs::{tc, SchedClassifier, TcAttachType};

use nz_agent::authz::AuthzTable;
use nz_agent::datapath::install_redirect;
use nz_agent::identity::SpiffeId;
use nz_agent_ebpf_common::{TcFlowKey, Waypoint};
use nz_agent_ebpf_loader::{RealAyaTcBackend, TcFallbackInstaller};

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

/// Builds a `libc::sockaddr_in` for `addr`, following the SAME byte-order
/// convention this crate's own key-derivation functions already use
/// (`u32::from_ne_bytes(ip.octets())` — see `egress_key_of`/`tc_flow_key_of`
/// in `loader/src/lib.rs`): copying the octets via native-endian reproduces
/// network byte order in the stored bytes, which is exactly what
/// `sockaddr_in::sin_addr`/`sin_port` require.
fn sockaddr_in_of(addr: SocketAddrV4) -> libc::sockaddr_in {
    libc::sockaddr_in {
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: addr.port().to_be(),
        sin_addr: libc::in_addr { s_addr: u32::from_ne_bytes(addr.ip().octets()) },
        sin_zero: [0; 8],
    }
}

/// Opens a real (not `std::net`-constructed) TCP socket EXPLICITLY bound to
/// `src` before connecting to `dst` — needed so this binary can register the
/// exact `TcFlowKey` the kernel will independently recompute BEFORE the SYN
/// is sent (an ephemeral, OS-chosen source port would not be knowable in
/// advance). Non-blocking: this call returns as soon as the SYN is queued
/// (`EINPROGRESS`), or immediately with a real connect error — this e2e does
/// not need (and, per the module docs, does not expect) the connection to
/// ever reach `ESTABLISHED`.
fn raw_connect_from(src: SocketAddrV4, dst: SocketAddrV4) -> std::io::Result<std::net::TcpStream> {
    unsafe {
        let fd = libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_NONBLOCK, 0);
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let reuse: libc::c_int = 1;
        let _ = libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_REUSEADDR,
            (&reuse as *const libc::c_int).cast::<libc::c_void>(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
        let src_sa = sockaddr_in_of(src);
        if libc::bind(fd, (&src_sa as *const libc::sockaddr_in).cast::<libc::sockaddr>(), std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t) != 0 {
            let e = std::io::Error::last_os_error();
            libc::close(fd);
            return Err(e);
        }
        let dst_sa = sockaddr_in_of(dst);
        let ret = libc::connect(fd, (&dst_sa as *const libc::sockaddr_in).cast::<libc::sockaddr>(), std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t);
        if ret != 0 {
            let errno = std::io::Error::last_os_error();
            if errno.raw_os_error() != Some(libc::EINPROGRESS) {
                libc::close(fd);
                return Err(errno);
            }
        }
        Ok(std::net::TcpStream::from_raw_fd(fd))
    }
}

/// Pure parse of `/proc/net/tcp`-shaped text: returns the raw hex state code
/// of the row whose LOCAL port equals `local_port`. Format grounded against
/// this host's own `/proc/net/tcp` output, read directly this session:
/// `LOCAL_IP_HEX:PORT_HEX REMOTE_IP_HEX:PORT_HEX STATE_HEX ...`, port printed
/// as a plain big-endian 4-hex-digit value (e.g. a real bound port 34567 =
/// 0x8707 appeared as exactly `:8707`). Separated from the file read so it is
/// unit-testable without a live `/proc/net/tcp`.
fn parse_tcp_state_of(content: &str, local_port: u16) -> Option<String> {
    let local_hex = format!(":{local_port:04X}");
    for line in content.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 4 {
            continue;
        }
        if fields[1].ends_with(&local_hex) {
            return Some(fields[3].to_string());
        }
    }
    None
}

/// Reads the raw hex state code of the row matching `local_port` (this
/// process's own connecting socket) — used purely for diagnostic printing.
fn proc_net_tcp_state_of(local_port: u16) -> std::io::Result<Option<String>> {
    let mut buf = String::new();
    std::fs::File::open("/proc/net/tcp")?.read_to_string(&mut buf)?;
    Ok(parse_tcp_state_of(&buf, local_port))
}

/// `TCP_SYN | TCP_ACK` flag bits (RFC 793 §3.1: byte 13 of the TCP header,
/// bit 1 = SYN, bit 4 = ACK).
const TCP_SYN: u8 = 0x02;
const TCP_ACK: u8 = 0x10;

/// Pure predicate over one already-captured Ethernet+IPv4+TCP frame (the
/// SAME 14/20/20-byte fixed-offset layout `ebpf/src/tc_fallback.rs` itself
/// parses — see this file's own module docs for the grounding capture that
/// confirmed loopback frames really carry a standard 14-byte fake-Ethernet
/// header with a correct `ETH_P_IP` ethertype): true iff `frame` is a real
/// IPv4/TCP `SYN+ACK` whose source port is `waypoint_port` and destination
/// port is `client_port`. Separated from the live `AF_PACKET` read loop so
/// the parsing logic itself is unit-testable without a live capture socket.
fn is_syn_ack_from_waypoint(frame: &[u8], waypoint_port: u16, client_port: u16) -> bool {
    if frame.len() < 54 {
        return false; // too short for Eth(14) + IPv4(20) + TCP(20, no options).
    }
    let ethertype = (u16::from(frame[12]) << 8) | u16::from(frame[13]);
    if ethertype != 0x0800 {
        return false;
    }
    let protocol = frame[14 + 9];
    if protocol != 6 {
        return false; // not TCP
    }
    let tcp_off = 14 + 20;
    let src_port = (u16::from(frame[tcp_off]) << 8) | u16::from(frame[tcp_off + 1]);
    let dst_port = (u16::from(frame[tcp_off + 2]) << 8) | u16::from(frame[tcp_off + 3]);
    let flags = frame[tcp_off + 13];
    src_port == waypoint_port && dst_port == client_port && (flags & (TCP_SYN | TCP_ACK)) == (TCP_SYN | TCP_ACK)
}

/// An INDEPENDENT end-to-end witness of the DNAT rewrite, deliberately
/// separate from `TC_VERDICTS` (the kernel-side counter, read further
/// below in `main`): a raw `AF_PACKET`/`SOCK_RAW` capture on `lo` that looks
/// for a real TCP `SYN+ACK` sent FROM the waypoint's own port BACK to the
/// client's fixed source port. The kernel program's own counter proves the
/// classifier's INTERNAL logic ran to completion; this capture proves the
/// REST OF THE KERNEL (the waypoint's TCP stack) actually treated the
/// rewritten packet as a legitimate new connection attempt and replied —
/// the two are independently-computed signals (2026-08-28 lesson: a
/// self-report from the mechanism under test is not, by itself, the F3
/// end-to-end proof). Returns the first matching frame's arrival instant
/// relative to `start`, if one is captured before `deadline`.
fn capture_syn_ack_from_waypoint(waypoint_port: u16, client_port: u16, deadline: Instant) -> anyhow::Result<Option<Duration>> {
    const ETH_P_ALL_BE: u16 = 0x0003u16.to_be(); // htons(ETH_P_ALL)
    let start = Instant::now();
    unsafe {
        let fd = libc::socket(libc::AF_PACKET, libc::SOCK_RAW, i32::from(ETH_P_ALL_BE));
        if fd < 0 {
            anyhow::bail!("socket(AF_PACKET, SOCK_RAW) failed: {}", std::io::Error::last_os_error());
        }
        let ifname = CString::new("lo").unwrap();
        let ifindex = libc::if_nametoindex(ifname.as_ptr());
        if ifindex == 0 {
            libc::close(fd);
            anyhow::bail!("if_nametoindex(lo) failed: {}", std::io::Error::last_os_error());
        }
        let mut sll: libc::sockaddr_ll = std::mem::zeroed();
        sll.sll_family = libc::AF_PACKET as u16;
        sll.sll_protocol = ETH_P_ALL_BE;
        sll.sll_ifindex = ifindex as i32;
        if libc::bind(fd, (&sll as *const libc::sockaddr_ll).cast::<libc::sockaddr>(), std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t) != 0 {
            let e = std::io::Error::last_os_error();
            libc::close(fd);
            anyhow::bail!("bind(AF_PACKET, lo) failed: {e}");
        }
        let mut buf = [0u8; 128];
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                libc::close(fd);
                return Ok(None);
            }
            let tv = libc::timeval { tv_sec: remaining.as_secs() as libc::time_t, tv_usec: i64::from(remaining.subsec_micros()) as _ };
            let _ = libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_RCVTIMEO, (&tv as *const libc::timeval).cast::<libc::c_void>(), std::mem::size_of::<libc::timeval>() as libc::socklen_t);
            let n = libc::recv(fd, buf.as_mut_ptr().cast::<libc::c_void>(), buf.len(), 0);
            if n < 0 {
                continue; // timeout/interrupt — keep polling until deadline.
            }
            let frame = &buf[..n as usize];
            if is_syn_ack_from_waypoint(frame, waypoint_port, client_port) {
                libc::close(fd);
                return Ok(Some(start.elapsed()));
            }
        }
    }
}

fn main() -> anyhow::Result<()> {
    raise_memlock_rlimit();

    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/tc_fallback"))).context("Ebpf::load")?;

    match tc::qdisc_add_clsact("lo") {
        Ok(()) => println!("E2E: qdisc_add_clsact(lo): OK"),
        Err(e) => println!("E2E: qdisc_add_clsact(lo) non-fatal (already attached?): {e:#}"),
    }
    {
        let prog: &mut SchedClassifier = ebpf.program_mut("tc_fallback").context("find classifier program")?.try_into()?;
        prog.load().context("classifier.load()")?;
        prog.attach("lo", TcAttachType::Ingress).context("classifier.attach(lo, Ingress)")?;
        println!("E2E: tc_fallback classifier loaded + attached (lo, Ingress)");
    }
    let waypoints: AyaHashMap<_, TcFlowKey, Waypoint> = AyaHashMap::try_from(ebpf.take_map("TC_WAYPOINTS").context("take TC_WAYPOINTS")?)?;
    let verdicts: PerCpuArray<_, u64> = PerCpuArray::try_from(ebpf.take_map("TC_VERDICTS").context("take TC_VERDICTS")?)?;

    // The real waypoint listener the DNAT rewrite must steer the packet
    // toward. Bound to a fresh ephemeral port so it is disjoint from the
    // fixed src/dst ports chosen below.
    let waypoint_listener = TcpListener::bind("127.0.0.1:0").context("bind waypoint listener")?;
    let waypoint_addr: SocketAddrV4 = match waypoint_listener.local_addr()? {
        std::net::SocketAddr::V4(a) => a,
        other => anyhow::bail!("expected ipv4 listener addr, got {other}"),
    };

    // A FIXED source port (must be known before the SYN is sent, so the
    // TcFlowKey can be registered ahead of time) and a DEAD destination
    // (nothing bound there — distinct from egress_e2e's 19998 and
    // inbound_lookup_e2e's 19996 so all three e2e binaries can run
    // independently without port collision).
    let src: SocketAddrV4 = "127.0.0.1:45201".parse().unwrap();
    let dst: SocketAddrV4 = "127.0.0.1:19995".parse().unwrap();
    println!("E2E: src(fixed)={src}  dst(dead, nothing bound)={dst}  waypoint(real listener)={waypoint_addr}");

    let backend = RealAyaTcBackend::new(waypoints);
    let mut installer = TcFallbackInstaller::new(backend);
    let source = id("e2e-tc-src");
    let destination = id("e2e-tc-dst");
    installer.register_flow(destination.clone(), src, dst, waypoint_addr);
    let mut authz = AuthzTable::new();
    authz.allow(source.clone(), destination.clone());
    install_redirect(&mut installer, &source, &destination, &authz).context("install authorized tc flow waypoint")?;
    println!("E2E: installed TC_WAYPOINTS[{src} -> {dst}] -> {waypoint_addr} (real bpf() map write, past the authz gate)");

    // Start the INDEPENDENT raw-packet witness BEFORE firing the SYN, so it
    // cannot miss the waypoint's reply. Runs on its own thread; joined below
    // after the SYN is sent.
    let deadline = Instant::now() + Duration::from_secs(3);
    let capture_thread = std::thread::spawn(move || capture_syn_ack_from_waypoint(waypoint_addr.port(), src.port(), deadline));

    // Give the capture socket a moment to bind before the SYN goes out.
    std::thread::sleep(Duration::from_millis(100));

    // Fire the real SYN. Its outcome (refused/timeout/reset from the CLIENT's
    // own point of view) is NOT the thing under test — see the module docs.
    let client = raw_connect_from(src, dst);
    match &client {
        Ok(_) => println!("E2E: raw connect() from {src} to {dst} issued (non-blocking; SYN queued or already resolved)"),
        Err(e) if e.raw_os_error() == Some(libc::ECONNREFUSED) => println!("E2E: raw connect() got immediate ECONNREFUSED (expected if delivered straight to the dead port unrewritten)"),
        Err(e) => println!("E2E: raw connect() returned an error before any wait: {e}"),
    }

    let capture_result = capture_thread.join().expect("capture thread must not panic")?;

    // /proc/net/tcp is read too, but ONLY as an honestly-labeled SECONDARY
    // signal: this kernel's TCP stack may answer the waypoint's SYN via
    // stateless SYN cookies, which record NO request_sock/SYN_RECV row at
    // all even when the SYN-ACK genuinely went out — so its ABSENCE here is
    // not proof of anything (a discovered fact, not an assumption: this
    // exact host DID show a real waypoint-sent SYN+ACK in an independent raw
    // capture inspected while iterating on this e2e, with no matching
    // SYN_RECV row ever appearing under `/proc/net/tcp` or `ss -tan`).
    let client_state = proc_net_tcp_state_of(src.port())?;

    match capture_result {
        Some(elapsed) => {
            println!(
                "E2E: RESULT=CONFIRMED — an independent raw AF_PACKET capture on `lo` observed a real TCP SYN+ACK \
                 sent FROM the waypoint's own port {} back to the client's fixed source port {} ({elapsed:?} after \
                 the SYN was issued). The SYN, addressed by the client to the DEAD destination {dst}, was rewritten \
                 by tc_fallback's DNAT (checksum fixups + header stores) and delivered to the REAL waypoint listener, \
                 whose own TCP stack treated it as a legitimate new connection and replied. TcFlowKey's byte-order \
                 key derivation is EMPIRICALLY confirmed against a live kernel — independent of, and stronger than, \
                 this program's own TC_VERDICTS self-report (read below).",
                waypoint_addr.port(),
                src.port()
            );
        }
        None => {
            println!(
                "E2E: RESULT=NOT-CONFIRMED — no SYN+ACK from the waypoint's port {} to the client's port {} was \
                 observed on `lo` within 3s. Client-side /proc/net/tcp state: {client_state:?} (02=SYN_SENT means \
                 the SYN never reached a socket that recognized it) — the DNAT rewrite did not land the packet at \
                 the waypoint.",
                waypoint_addr.port(),
                src.port()
            );
        }
    }
    println!(
        "E2E: NOTE — per the module docs, the client's OWN connecting socket does not itself reach ESTABLISHED \
         even when the rewrite is fully confirmed: it still expects a reply FROM {dst} (the original destination), \
         so a correctly-addressed SYN+ACK from the waypoint's port {} is not recognized by the client's SYN_SENT \
         socket and the 3-way handshake does not complete end-to-end from the client's point of view — a genuine, \
         documented limitation of this one-way (no reverse/SNAT) DNAT rung, observed client-side state: {client_state:?}.",
        waypoint_addr.port()
    );

    // Bonus/tertiary signal only — per the module docs, a full 3-way
    // handshake completing at the WAYPOINT's own accept() is NOT expected
    // for this rung (no reverse/SNAT translation exists), so this is
    // reported honestly either way, never treated as the pass/fail criterion.
    waypoint_listener.set_nonblocking(true).ok();
    match waypoint_listener.accept() {
        Ok((_s, peer)) => println!("E2E: BONUS — waypoint_listener.accept() also completed from {peer} (full handshake succeeded; not required by this rung's design)"),
        Err(e) => println!("E2E: waypoint_listener.accept() did not complete (expected per this rung's known one-way-DNAT limitation): {e}"),
    }

    // The kernel-side verdict counters, read here purely as a diagnostic
    // corroborating (or refuting) the /proc/net/tcp confirmation above: sum
    // both cpus'-worth of VERDICT_STEERED (index 0) and VERDICT_STEER_FAILED
    // (index 1) — a nonzero total proves `TC_WAYPOINTS.get` found this exact
    // flow's key; a zero total means the packet never matched at all (a
    // key-derivation/byte-order miss, not a rewrite failure).
    let steered: u64 = verdicts.get(&0, 0)?.iter().sum();
    let steer_failed: u64 = verdicts.get(&1, 0)?.iter().sum();
    println!("E2E: TC_VERDICTS — steered={steered} steer_failed={steer_failed} (total matches against TC_WAYPOINTS={})", steered + steer_failed);

    drop(client);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a synthetic 54-byte Eth(14)+IPv4(20)+TCP(20) frame with the
    /// EXACT layout this host's own `lo` interface was observed emitting
    /// this session (a standard 14-byte fake-Ethernet header, all-zero MACs,
    /// `ETH_P_IP` at offset 12; a 20-byte IPv4 header, IHL=5, protocol=TCP;
    /// a 20-byte TCP header) — the fixture `is_syn_ack_from_waypoint` is
    /// tested against, independent of any live capture.
    fn synth_frame(src_port: u16, dst_port: u16, flags: u8) -> Vec<u8> {
        let mut f = vec![0u8; 54];
        f[12] = 0x08;
        f[13] = 0x00; // ETH_P_IP
        f[14] = 0x45; // version 4, IHL 5
        f[14 + 9] = 6; // IPPROTO_TCP
        let tcp = 14 + 20;
        f[tcp] = (src_port >> 8) as u8;
        f[tcp + 1] = (src_port & 0xff) as u8;
        f[tcp + 2] = (dst_port >> 8) as u8;
        f[tcp + 3] = (dst_port & 0xff) as u8;
        f[tcp + 13] = flags;
        f
    }

    #[test]
    fn matches_a_real_syn_ack_from_the_waypoint_to_the_client() {
        let frame = synth_frame(45379, 45201, TCP_SYN | TCP_ACK);
        assert!(is_syn_ack_from_waypoint(&frame, 45379, 45201));
    }

    #[test]
    fn rejects_a_plain_syn_not_an_ack() {
        // Mutation-witness target: if the ACK-bit check is dropped, this
        // frame (the CLIENT's own outbound SYN, not the waypoint's reply)
        // would be wrongly accepted.
        let frame = synth_frame(45379, 45201, TCP_SYN);
        assert!(!is_syn_ack_from_waypoint(&frame, 45379, 45201));
    }

    #[test]
    fn rejects_wrong_port_pair() {
        let frame = synth_frame(9999, 45201, TCP_SYN | TCP_ACK);
        assert!(!is_syn_ack_from_waypoint(&frame, 45379, 45201));
    }

    #[test]
    fn rejects_non_tcp_protocol() {
        let mut frame = synth_frame(45379, 45201, TCP_SYN | TCP_ACK);
        frame[14 + 9] = 17; // UDP
        assert!(!is_syn_ack_from_waypoint(&frame, 45379, 45201));
    }

    #[test]
    fn rejects_non_ip_ethertype() {
        let mut frame = synth_frame(45379, 45201, TCP_SYN | TCP_ACK);
        frame[12] = 0x86;
        frame[13] = 0xdd; // ETH_P_IPV6
        assert!(!is_syn_ack_from_waypoint(&frame, 45379, 45201));
    }

    #[test]
    fn rejects_a_frame_too_short_to_hold_a_tcp_header() {
        let frame = synth_frame(45379, 45201, TCP_SYN | TCP_ACK);
        assert!(!is_syn_ack_from_waypoint(&frame[..40], 45379, 45201));
    }

    #[test]
    fn parses_the_matching_local_port_row_state() {
        let content = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
                        \x20\x203: 0100007F:8707 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 58170 1\n";
        assert_eq!(parse_tcp_state_of(content, 34567).as_deref(), Some("0A"));
    }

    #[test]
    fn returns_none_for_an_unmatched_port() {
        let content = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
                        \x20\x203: 0100007F:8707 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 58170 1\n";
        assert_eq!(parse_tcp_state_of(content, 1), None);
    }

    #[test]
    fn sockaddr_in_of_reproduces_the_established_octet_convention() {
        // Matches nz_agent_ebpf_loader::egress_key_of's own established
        // convention (u32::from_ne_bytes(ip.octets())) — a mutation-witness
        // for a byte-order regression in this e2e's own raw-socket helper.
        let addr: SocketAddrV4 = "127.0.0.1:80".parse().unwrap();
        let sa = sockaddr_in_of(addr);
        assert_eq!(sa.sin_family, libc::AF_INET as libc::sa_family_t);
        assert_eq!(sa.sin_port, 80u16.to_be());
        assert_eq!(sa.sin_addr.s_addr, u32::from_ne_bytes([127, 0, 0, 1]));
    }
}
