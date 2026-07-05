//! Runnable example: the draft-00 secure record layer, end to end.
//!
//! Composes the OPEN-protocol primitives this port provides — the HKDF key schedule, the
//! AES-256-GCM record layer, and the 36-octet frame codec — into one send -> receive round-trip
//! over an in-memory "wire". Mirrors the Go reference's Example_secureRecordLayer
//! (impl/go/example_test.go).
//!
//! The master secret is a fixed demo value; in a live session it is the handshake output (binding
//! spec/10 §5). Standard profile only (SHA-256, AES-256-GCM). Run from impl/rust:
//!
//!   cargo run --example secure_record_layer

use npamp::*;

/// Direction octet (draft-00 7.5): client-to-server = 0.
const DIR_CLIENT_TO_SERVER: u8 = 0;

fn main() {
    // 1. Key schedule: derive a per-(direction, channel, suite) traffic key + IV from the master
    //    secret. In a live session the master secret is the handshake output; here it is fixed.
    let master = [0x2Bu8; 32];
    let ts = derive_traffic_secret(&master, DIR_CLIENT_TO_SERVER, 0, AEAD_AES256_GCM, CHAN_MEMORY, true);
    let (key, iv) = derive_key_iv(&ts, true);

    // 2. Sender: seal an application payload into an AEAD-protected frame on the Memory channel.
    //    The AEAD associated data is the 21-octet header prefix, so the ciphertext is bound to the
    //    frame's type/channel/seq/length — a tampered header makes the open fail.
    let app_type: u16 = 0x0120; // application frame type (app-defined; this port is wire-only)
    let plaintext = b"hello over n-pamp";
    let seq: u64 = 0;
    let mut out = Frame { flags: FLAG_ENC, ftype: app_type, channel: CHAN_MEMORY, seq, ..Default::default() };
    let mut aad = [0u8; 21];
    out.header_prefix(&mut aad, (plaintext.len() + 16) as u32); // +16 = AES-256-GCM authentication tag
    out.payload = seal_aes256gcm(&key, &iv, seq, &aad, plaintext);
    let wire = out.marshal();

    // 3. ... the `wire` bytes travel over any transport (the consumer supplies TCP/TLS) ...

    // 4. Receiver: parse the frame (validates CRC32C/magic/version) and open the payload under the
    //    same key/seq and the reconstructed header-prefix AAD.
    let inc = Frame::unmarshal(&wire).expect("unmarshal");
    let mut raad = [0u8; 21];
    inc.header_prefix(&mut raad, inc.payload.len() as u32);
    let opened = open_aes256gcm(&key, &iv, inc.seq, &raad, &inc.payload).expect("aead open");

    println!("channel={} seq={} encrypted={}", inc.channel, inc.seq, inc.flags & FLAG_ENC != 0);
    println!("recovered: {}", String::from_utf8(opened.clone()).expect("utf8 plaintext"));
    assert_eq!(opened.as_slice(), &plaintext[..], "roundtrip mismatch");
}
