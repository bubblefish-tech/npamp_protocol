//! Live N-PAMP interop CLIENT (raw TCP).
//!
//! Connects to an N-PAMP server, completes the client side of the 1.5-RTT
//! mutually-authenticated handshake (binding spec/10) via `npamp::session::Session`,
//! sends one AEAD-protected application frame on the Memory channel, and verifies
//! the server's echo. Interoperates with either this crate's interop_server example
//! (Rust<->Rust) or the Go reference harness impl/go/cmd/npamp-interop -role server
//! (Go<->Rust) — the two-interoperable-implementations unlock.
//!
//! At `--profile standard` (the default) this drives `Session::dial` — the
//! original Ed25519-only entry point, byte-unchanged. At `--profile high` /
//! `--profile sovereign` this drives the multi-profile entry point
//! `Session::dial_with_profiles` (spec/05_profiles.md; draft-00 section 6)
//! instead, offering exactly the requested profile and authenticating with a
//! freshly generated ML-DSA-87 identity — the SAME entry point
//! `session.rs`'s own `#[cfg(test)]` module drives over an in-memory pipe,
//! run here for the first time over a real loopback `TcpStream`.
//!
//!   cargo run --example interop_client -- 127.0.0.1:47700 --profile standard
//!   cargo run --example interop_client -- 127.0.0.1:47700 --profile high
//!   cargo run --example interop_client -- 127.0.0.1:47700 --profile sovereign
//!
//! Exit code 0 iff the handshake completes AND the server echo byte-matches the
//! sent payload. Transport: raw TCP (the handshake is transport-agnostic; the Go
//! SDK's TLS transport binding is not exercised here — see `npamp::session` docs).

use npamp::mldsa87;
use npamp::session::{self, Session};
use std::net::TcpStream;
use std::process::exit;

const APP_FRAME_TYPE: u16 = 0x0120; // application-defined frame type
const CHAN_MEMORY: u16 = npamp::CHAN_MEMORY;

/// The three profiles `Session::dial_with_profiles`/`Session::accept_with_profiles`
/// negotiate (spec/05_profiles.md). Standard still runs through the original
/// `Session::dial`/`Session::accept` pair — this enum only selects which entry
/// point + identity material this example builds, never a new wire behavior.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Profile {
    Standard,
    High,
    Sovereign,
}

impl Profile {
    fn parse(s: &str) -> Option<Self> {
        match s {
            "standard" => Some(Profile::Standard),
            "high" => Some(Profile::High),
            "sovereign" => Some(Profile::Sovereign),
            _ => None,
        }
    }

    /// The TLV_PROFILE_OFFER / TLV_PROFILE_SELECT wire byte this profile negotiates as
    /// (`session::PROFILE_STANDARD`/`PROFILE_HIGH`/`PROFILE_SOVEREIGN`).
    fn wire_byte(self) -> u8 {
        match self {
            Profile::Standard => session::PROFILE_STANDARD,
            Profile::High => session::PROFILE_HIGH,
            Profile::Sovereign => session::PROFILE_SOVEREIGN,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Profile::Standard => "standard",
            Profile::High => "high",
            Profile::Sovereign => "sovereign",
        }
    }
}

fn main() {
    let mut addr = "127.0.0.1:47700".to_string();
    let mut profile = Profile::Standard;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        if arg == "--profile" {
            let val = args.next().unwrap_or_default();
            profile = match Profile::parse(&val) {
                Some(p) => p,
                None => {
                    eprintln!("interop_client: unknown --profile {val:?} (expected standard|high|sovereign)");
                    exit(1);
                }
            };
        } else {
            addr = arg;
        }
    }

    let mut stream = match TcpStream::connect(&addr) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("interop_client: connect {addr}: {e}");
            exit(1);
        }
    };
    println!("interop_client: connected to {addr}");
    println!("interop_client: offering profile={}", profile.name());

    let identity = session::generate_identity();
    println!("interop_client: identity ed25519 = {}", hex8(&identity.verifying_key().to_bytes()));

    // Standard runs the original Session::dial (byte-unchanged); High/Sovereign
    // runs the multi-profile entry point with a freshly generated ML-DSA-87
    // long-term identity — required (fail-closed inside dial_with_profiles) for
    // either non-Standard profile.
    let mldsa_identity = if profile != Profile::Standard {
        let id = mldsa87::Identity::generate();
        println!("interop_client: identity ml-dsa-87 = {}", hex8(id.public_key_bytes()));
        Some(id)
    } else {
        None
    };

    let sess = match profile {
        Profile::Standard => Session::dial(&mut stream, &identity, None),
        Profile::High | Profile::Sovereign => Session::dial_with_profiles(
            &mut stream,
            &identity,
            mldsa_identity.as_ref(),
            &[profile.wire_byte()],
            None,
            None,
        ),
    };
    let sess = match sess {
        Ok(s) => s,
        Err(e) => {
            eprintln!("interop_client: handshake failed: {e}");
            exit(1);
        }
    };

    // dial_with_profiles offered exactly one profile, so a completed handshake
    // proves the server negotiated that SAME profile (offered_profiles.contains
    // check inside dial_with_profiles rejects any other selection) — and
    // kem_group_for_profiles forces SecP384r1MLKEM1024 (0x11ed) whenever High or
    // Sovereign is offered, so peer_identity_mldsa87() being populated is live
    // proof both the KEM group and the ML-DSA-87 CertVerify negotiated as
    // expected for the requested profile, not merely that SOME handshake completed.
    match sess.peer_identity_mldsa87() {
        Some(peer_mldsa) => println!(
            "interop_client: handshake OK — profile={} negotiated KEM SecP384r1MLKEM1024 (0x11ed) + ML-DSA-87 CertVerify; authenticated server ml-dsa-87 = {} ({} octets)",
            profile.name(),
            hex8(peer_mldsa),
            peer_mldsa.len()
        ),
        None => println!(
            "interop_client: handshake OK — profile=standard; authenticated server ed25519 = {}",
            hex8(&sess.peer_identity())
        ),
    }

    // Send one application frame on the Memory channel (seq 0).
    let payload = b"hello from the rust interop client";
    if let Err(e) = sess.send(&mut stream, CHAN_MEMORY, APP_FRAME_TYPE, 0, payload) {
        eprintln!("interop_client: send data frame: {e}");
        exit(1);
    }
    println!("interop_client: sent {} octets on the Memory channel", payload.len());

    // Read the server's echo (server->client, seq 0) and verify byte-equality.
    let (channel, ftype, echo) = match sess.recv(&mut stream, 0) {
        Ok(x) => x,
        Err(e) => {
            eprintln!("interop_client: recv echo: {e}");
            exit(1);
        }
    };
    println!(
        "interop_client: recv echo channel=0x{channel:04x} type=0x{ftype:04x} payload={:?}",
        String::from_utf8_lossy(&echo)
    );

    if echo != payload {
        eprintln!("interop_client: FAIL — echo did not match sent payload");
        exit(1);
    }
    println!("interop_client: PASS — live N-PAMP handshake + data frame round-trip verified (profile={})", profile.name());
}

fn hex8(b: &[u8]) -> String {
    b.iter().take(8).map(|x| format!("{x:02x}")).collect()
}
