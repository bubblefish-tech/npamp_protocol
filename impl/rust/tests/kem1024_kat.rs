// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

// Needs the P-384/ML-KEM crates the `session` feature (default-on) enables; skip
// cleanly under `--no-default-features` instead of failing to compile.
#![cfg(feature = "session")]

// SecP384r1MLKEM1024 (KEM 0x11ed) KEM-wire + handshake-secret known-answer test.
// Mirrors the Go reference verifiers impl/go/kem1024_kat_test.go
// (TestKEMWireKAT1024, TestHandshakeSecret1024KAT) byte-for-byte, against the SAME
// RFC 5903 §8.2 anchor and the SAME hardcoded synthetic ML-KEM leg, so a
// cross-language diff of this file against the Go source is the byte-parity check:
// identical inputs in, identical hex asserted out.
//
// NON-CIRCULAR (F3): RFC 5903 §8.2 (384-Bit Random ECP Group / Group 20) is the
// published, standards-anchored secp384r1 ECDH known-answer vector — the expected
// public keys and the shared-secret x-coordinate come from the RFC, never from this
// implementation, the same role RFC 7748 §6.1 plays for kem_wire_kat.rs. The
// combined-secret ordering leg (ECDHE-first) and the HandshakeSecret1024 combiner
// leg are graded against an INDEPENDENT HKDF-Extract oracle (`hkdf::Hkdf`'s own
// `extract`, invoked directly by this test — never `npamp::kem1024::handshake_secret_1024`
// grading itself) over that RFC-anchored IKM.
//
// The ML-KEM-1024 leg is exercised by round-trip through the real code path
// (the `ml-kem` crate is itself a FIPS-203 conformant, test-vectored implementation);
// its NIST-ACVP (d, z, ek) anchor is Phase-4 corpus work, tracked, not silently absent
// — matching the Go reference test's documented scope.

use hkdf::Hkdf;
use p384::SecretKey as P384SecretKey;
use sha2::Sha384;

use npamp::kem1024::{self, KemClient1024, COMBINED_SECRET_SIZE_1024, KEM_CIPHERTEXT_SIZE_1024, KEM_SHARE_SIZE_1024, P384_PUBLIC_KEY_SIZE, P384_SHARED_SECRET_SIZE};

const RFC5903_P384_INITIATOR_PRIV: &str = "099F3C7034D4A2C699884D73A375A67F7624EF7C6B3C0F160647B67414DCE655E35B538041E649EE3FAEF896783AB194";
const RFC5903_P384_INITIATOR_X: &str = "667842D7D180AC2CDE6F74F37551F55755C7645C20EF73E31634FE72B4C55EE6DE3AC808ACB4BDB4C88732AEE95F41AA";
const RFC5903_P384_INITIATOR_Y: &str = "9482ED1FC0EEB9CAFC4984625CCFC23F65032149E0E144ADA024181535A0F38EEB9FCFF3C2C947DAE69B4C634573A81C";
const RFC5903_P384_RESPONDER_PRIV: &str = "41CB0779B4BDB85D47846725FBEC3C9430FAB46CC8DC5060855CC9BDA0AA2942E0308312916B8ED2960E4BD55A7448FC";
const RFC5903_P384_RESPONDER_X: &str = "E558DBEF53EECDE3D3FCCFC1AEA08A89A987475D12FD950D83CFA41732BC509D0D1AC43A0336DEF96FDA41D0774A3571";
const RFC5903_P384_RESPONDER_Y: &str = "DCFBEC7AACF3196472169E838430367F66EEBE3C6E70C416DD5F0C68759DD1FFF83FA40142209DFF5EAAD96DB9E6386C";
const RFC5903_P384_SHARED_X: &str = "11187331C279962D93D604243FD592CB9D0A926F422E47187521287E7156C5C4D603135569B9E9D09CF5D4A270F59746";

fn from_hex(s: &str) -> Vec<u8> {
    let b = s.as_bytes();
    assert!(b.len() % 2 == 0, "odd-length hex: {s}");
    let mut out = Vec::with_capacity(b.len() / 2);
    let mut i = 0;
    while i < b.len() {
        let hi = (b[i] as char).to_digit(16).expect("bad hex");
        let lo = (b[i + 1] as char).to_digit(16).expect("bad hex");
        out.push(((hi << 4) | lo) as u8);
        i += 2;
    }
    out
}

fn concat(a: &[u8], b: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(a.len() + b.len());
    out.extend_from_slice(a);
    out.extend_from_slice(b);
    out
}

/// Proves the SecP384r1MLKEM1024 (KEM 0x11ed) wire and shared-secret ordering is
/// ECDHE-first (P-384 first), matching RFC 10024 (formerly
/// draft-ietf-tls-ecdhe-mlkem) — the reverse of the X25519MLKEM768 order. The P-384
/// legs are anchored to RFC 5903 §8.2; the ordering legs are mutation-surviving
/// (reverting `SharedSecrets1024::combined` to ML-KEM-first fails them).
#[test]
fn kem_wire_kat_1024() {
    let i_priv = from_hex(RFC5903_P384_INITIATOR_PRIV);
    let r_priv = from_hex(RFC5903_P384_RESPONDER_PRIV);
    let i_pub_want = concat(&concat(&[0x04], &from_hex(RFC5903_P384_INITIATOR_X)), &from_hex(RFC5903_P384_INITIATOR_Y));
    let r_pub_want = concat(&concat(&[0x04], &from_hex(RFC5903_P384_RESPONDER_X)), &from_hex(RFC5903_P384_RESPONDER_Y));
    let girx_want = from_hex(RFC5903_P384_SHARED_X);

    // Leg 1 (RFC 5903 anchor): p384's ECDH reproduces the RFC public keys
    // (uncompressed 0x04||X||Y) and the shared-secret x-coordinate from the raw
    // private scalars — the wrong curve or a broken ECDH cannot reproduce these.
    let i_key = P384SecretKey::from_slice(&i_priv).expect("initiator private key");
    let r_key = P384SecretKey::from_slice(&r_priv).expect("responder private key");
    assert_eq!(
        p384::Sec1Point::from(i_key.public_key()).as_bytes(),
        i_pub_want.as_slice(),
        "initiator public key does not reproduce RFC 5903 §8.2 (0x04||gix||giy)"
    );
    assert_eq!(
        p384::Sec1Point::from(r_key.public_key()).as_bytes(),
        r_pub_want.as_slice(),
        "responder public key does not reproduce RFC 5903 §8.2 (0x04||grx||gry)"
    );
    let r_pub = p384::PublicKey::from_sec1_bytes(&r_pub_want).expect("responder public key");
    let ecdh_ss = p384::ecdh::diffie_hellman(i_key.to_nonzero_scalar(), r_pub.as_affine());
    assert_eq!(ecdh_ss.raw_secret_bytes().as_slice().len(), P384_SHARED_SECRET_SIZE);
    assert_eq!(
        ecdh_ss.raw_secret_bytes().as_slice(),
        girx_want.as_slice(),
        "secp384r1 ECDH shared secret does not reproduce RFC 5903 §8.2 girx (x-coordinate)"
    );

    // Build the real client with the RFC 5903 initiator P-384 key + a fixed
    // ML-KEM-1024 seed, so the KAT drives the production code path.
    let seed: [u8; 64] = std::array::from_fn(|j| j as u8);
    let client = KemClient1024::from_seed(&seed, &i_priv).expect("KemClient1024::from_seed");
    let share = client.kem_share();
    assert_eq!(share.len(), KEM_SHARE_SIZE_1024, "KEMShare length");

    // Leg 2 (wire order, KEMShare): ECDHE-first — secp384r1 pub (97) precedes the
    // ML-KEM-1024 ek (1568). Reverting to ek-first fails here.
    assert_eq!(
        &share[..P384_PUBLIC_KEY_SIZE],
        i_pub_want.as_slice(),
        "KEMShare does not begin with the secp384r1 public key (ECDHE-first wire order violated)"
    );

    // Leg 3 (server side, RFC 5903 responder key): the server encapsulates using
    // the RFC 5903 responder P-384 key; its ECDHE half MUST be the RFC girx.
    let (ct, server_ss) = kem1024::encapsulate_with(&share, &r_key).expect("encapsulate_with");
    assert_eq!(ct.len(), KEM_CIPHERTEXT_SIZE_1024, "KEMCiphertext length");
    assert_eq!(
        &ct[..P384_PUBLIC_KEY_SIZE],
        r_pub_want.as_slice(),
        "KEMCiphertext does not begin with the server secp384r1 public key (ECDHE-first wire order violated)"
    );
    assert_eq!(
        server_ss.ecdhe.as_slice(),
        girx_want.as_slice(),
        "server ECDHE shared secret does not reproduce RFC 5903 §8.2 girx"
    );

    // Leg 4 (client decapsulate): recover the same ECDHE secret + ML-KEM round-trip.
    let client_ss = client.shared_secrets(&ct).expect("client SharedSecrets");
    assert_eq!(
        client_ss.ecdhe.as_slice(),
        girx_want.as_slice(),
        "client-decapsulated ECDHE shared secret does not reproduce RFC 5903 §8.2 girx"
    );
    assert_eq!(client_ss.mlkem, server_ss.mlkem, "ML-KEM-1024 encapsulate/decapsulate round-trip mismatch");

    // Leg 5 (IKM order — the mutation-surviving core): the combined HKDF-Extract
    // IKM MUST be ECDHE_ss || ML-KEM_ss (P-384 first) and MUST NOT be the reverse
    // (the X25519MLKEM768-style ML-KEM-first order). Reverting kem1024's
    // `combined()` to ML-KEM-first fails both assertions.
    let combined = client_ss.combined();
    assert_eq!(combined.len(), COMBINED_SECRET_SIZE_1024, "combined secret length");
    assert_eq!(
        combined,
        concat(&girx_want, &client_ss.mlkem),
        "combined() is not ECDHE_ss || ML-KEM_ss (SecP384r1MLKEM1024 must be P-384-first)"
    );
    assert_ne!(
        combined,
        concat(&client_ss.mlkem, &girx_want),
        "combined() matches the ML-KEM-first IKM order (that is the 768 order, not SecP384r1MLKEM1024)"
    );
    assert_eq!(client_ss.combined(), server_ss.combined(), "client/server combined secret mismatch");

    println!("test result: ok — SecP384r1MLKEM1024 KEM-wire KAT (RFC 5903 §8.2 anchor + ECDHE-first wire order)");
}

/// Proves `kem1024::handshake_secret_1024` against an INDEPENDENT HKDF-Extract
/// oracle (this test's own `hkdf::Hkdf::<Sha384>::extract` call, never
/// `handshake_secret_1024` itself — F3 non-circularity) over the RFC 5903 §8.2
/// anchored ECDHE secret combined ECDHE-first with a fixed synthetic ML-KEM shared
/// secret. The ML-KEM leg's real encapsulate/decapsulate round trip is already
/// anchored by `kem_wire_kat_1024` above; this test isolates the
/// `handshake_secret_1024` combiner (HKDF-Extract, SHA-384, ECDHE-first ordering).
#[test]
fn handshake_secret_1024_kat() {
    let ecdhe_ss = from_hex(RFC5903_P384_SHARED_X); // RFC 5903 §8.2 anchor (48 octets)
    let mlkem_ss: Vec<u8> = (0..32u16).map(|i| (0xA0u16 + i) as u8).collect(); // fixed synthetic ML-KEM shared secret
    let ss = kem1024::SharedSecrets1024 { ecdhe: ecdhe_ss, mlkem: mlkem_ss.clone() };

    // Standard (SHA-384) profile combiner, both High and Sovereign (High=false,
    // Sovereign=false — both route through `standard = false` here since this
    // module's `standard` parameter selects the HASH, not the profile name).
    let got = kem1024::handshake_secret_1024(&ss, false).expect("handshake_secret_1024");
    assert_eq!(got.len(), 48, "handshake_secret_1024 is 48 octets (SHA-384 HashLen)");

    // Independent oracle: HKDF-Extract(salt = 48 zero octets, IKM = ECDHE_SS || ML-KEM_SS).
    let want = Hkdf::<Sha384>::extract(Some(&[0u8; 48]), &ss.combined()).0.to_vec();
    assert_eq!(got, want, "handshake_secret_1024 != HKDF-Extract(48 zero octets, ECDHE_SS || ML-KEM_SS)");

    // Mutation guard: the reversed (ML-KEM-first, X25519MLKEM768-style) IKM order
    // MUST NOT match. Reverting SharedSecrets1024::combined to ML-KEM-first fails this.
    let reversed_ikm = concat(&mlkem_ss, &from_hex(RFC5903_P384_SHARED_X));
    let reversed = Hkdf::<Sha384>::extract(Some(&[0u8; 48]), &reversed_ikm).0.to_vec();
    assert_ne!(
        got, reversed,
        "handshake_secret_1024 matches the ML-KEM-first IKM order (SecP384r1MLKEM1024 must be ECDHE-first)"
    );

    // Fail-closed guard: the Standard profile must never reach this combiner (it
    // uses derive_handshake_secret + SharedSecrets, not handshake_secret_1024).
    assert_eq!(
        kem1024::handshake_secret_1024(&ss, true),
        Err(kem1024::Error::StandardProfileForbidden),
        "handshake_secret_1024(standard=true) must be fail-closed"
    );

    println!("test result: ok — HandshakeSecret1024 combiner KAT (independent HKDF-Extract oracle, ECDHE-first)");
}
