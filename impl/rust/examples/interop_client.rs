//! Live N-PAMP interop CLIENT (raw TCP).
//!
//! Connects to an N-PAMP server, completes the client side of the 1.5-RTT
//! mutually-authenticated handshake (binding spec/10) via `npamp::session::Session`,
//! sends one AEAD-protected application frame on the Memory channel, and verifies
//! the server's echo. Interoperates with either this crate's interop_server example
//! (Rust<->Rust) or the Go reference harness impl/go/cmd/npamp-interop -role server
//! (Go<->Rust) — the two-interoperable-implementations unlock.
//!
//! At `--profile standard` (the default) this drives `Session::dial`. At
//! `--profile high` / `--profile sovereign` this drives the multi-profile entry
//! point `Session::dial_with_profiles` (spec/05_profiles.md; draft-00 section 6),
//! which this crate answers with `NoSuiteForProfile`: only the Standard profile is
//! implemented, so the example reports the refusal and exits 1 before any
//! handshake byte is sent.
//!
//!   cargo run --example interop_client -- 127.0.0.1:47700 --profile standard
//!
//! Exit code 0 iff the handshake completes AND the server echo byte-matches the
//! sent payload. Transport: raw TCP (the handshake is transport-agnostic; the Go
//! SDK's TLS transport binding is not exercised here — see `npamp::session` docs).

use npamp::session::{self, Session};
use std::net::TcpStream;
use std::process::exit;

const APP_FRAME_TYPE: u16 = 0x0120; // application-defined frame type
const CHAN_MEMORY: u16 = npamp::CHAN_MEMORY;

/// The three profile code points (spec/05_profiles.md). Standard runs through
/// `Session::dial`; High and Sovereign are offered through
/// `Session::dial_with_profiles` and refused by this crate.
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

    let sess = match profile {
        Profile::Standard => Session::dial(&mut stream, &identity, None),
        Profile::High | Profile::Sovereign => {
            Session::dial_with_profiles(&mut stream, &identity, &[profile.wire_byte()], None)
        }
    };
    let sess = match sess {
        Ok(s) => s,
        Err(e) => {
            eprintln!("interop_client: handshake failed: {e}");
            exit(1);
        }
    };

    println!(
        "interop_client: handshake OK — profile=standard; authenticated server ed25519 = {}",
        hex8(&sess.peer_identity())
    );

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
