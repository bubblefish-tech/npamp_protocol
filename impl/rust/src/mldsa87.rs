// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

//! ML-DSA-87 (FIPS 204, IANA TLS SignatureScheme 0x0906 — `crate::SIG_MLDSA87`)
//! CertVerify, the post-quantum signature scheme required at the High and
//! Sovereign profiles (spec/10 section 6.1). Mirrors
//! `impl/go/handshake.go`'s `SignCertVerifyMLDSA87`/`VerifyCertVerifyMLDSA87`
//! byte-for-byte: the SAME [`crate::handshake::cert_verify_signing_input`]
//! (64 x 0x20 || role context || 0x00 || transcript_hash) the Ed25519 CertVerify
//! signs (`crate::handshake::sign_cert_verify`), signed/verified in ML-DSA's
//! pure (non-prehashed) mode with an EMPTY ML-DSA context string — the N-PAMP
//! role/context separation already lives inside the signing input, so ML-DSA's
//! own context parameter is left unused to avoid a second, redundant
//! domain-separation mechanism (matching the Go reference's documented
//! rationale on `SignCertVerifyMLDSA87`).
//!
//! Signing is DETERMINISTIC (FIPS 204's optional deterministic variant, rnd
//! hardcoded to 32 zero octets — see the `ml-dsa` dependency comment in
//! `Cargo.toml`), matching the Go reference's `PrivateKey.SignDeterministic`
//! so a given (identity, role, transcript_hash) always produces the SAME
//! CertVerify value in both languages — the property the KAT in
//! `tests/mldsa87_certverify_kat.rs` exercises.
//!
//! Gated behind the `session` Cargo feature, like `kem1024.rs`: a consumer
//! building `--no-default-features` (the strict wire-format-only library)
//! drops this module, and its `ml-dsa` dependency, entirely.

use ml_dsa::{EncodedSignature, EncodedVerifyingKey, Keypair, MlDsa87, Signature, SigningKey, VerifyingKey};

use crate::handshake::cert_verify_signing_input;
use crate::SIG_MLDSA87;

/// FIPS 204 ML-DSA-87 public-key encoding size (`mldsa.MLDSA87PublicKeySize` in
/// the Go reference).
pub const PUBLIC_KEY_SIZE: usize = 2592;
/// FIPS 204 ML-DSA-87 signature encoding size (`mldsa.MLDSA87SignatureSize` in
/// the Go reference).
pub const SIGNATURE_SIZE: usize = 4627;

/// Errors from the ML-DSA-87 CertVerify operations. Named, not string-typed —
/// matching `kem1024::Error`'s convention — so a caller can match on the
/// failure class.
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    /// The peer's ML-DSA-87 public-key encoding is not [`PUBLIC_KEY_SIZE`] octets.
    PublicKeySize,
    /// `sign_deterministic` failed — cannot happen for a well-formed 32-octet
    /// seed and this module's fixed empty context (the crate's own signing
    /// path can only fail on a context longer than 255 octets), but is
    /// surfaced rather than `unwrap`ped/`expect`ed so a future crate-internal
    /// change cannot turn into a panic in this module.
    Sign,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let msg = match self {
            Error::PublicKeySize => "npamp: ML-DSA-87 public key is not 2592 octets",
            Error::Sign => "npamp: ML-DSA-87 CertVerify signing failed",
        };
        f.write_str(msg)
    }
}

impl std::error::Error for Error {}

/// Fills a fresh array with OS entropy (no rand_core trait plumbing), matching
/// `session.rs`'s and `kem1024.rs`'s own `os_random`.
fn os_random<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    getrandom::getrandom(&mut b).expect("OS CSPRNG");
    b
}

/// A long-term ML-DSA-87 identity: the deterministic FIPS 204 KeyGen_internal
/// signing key built from a 32-octet seed, plus its cached public-key
/// encoding (the [`Identity::public_key_bytes`] TLV 0x09 IdentityKey value
/// both AUTH frames carry at the High/Sovereign profiles). Mirrors the Go
/// reference's `Config.MLDSAIdentity *mldsa.PrivateKey` — a SEPARATE
/// long-term key from the Ed25519 `identity` parameter
/// `Session::dial_with_profiles`/`accept_with_profiles` also take, exactly as
/// the Go SDK's `Config` carries `Identity` (Ed25519) and `MLDSAIdentity`
/// (ML-DSA-87) as two independent fields.
pub struct Identity {
    signing_key: SigningKey<MlDsa87>,
    public_key_bytes: Vec<u8>,
}

impl Identity {
    /// Deterministically builds an ML-DSA-87 identity from its 32-octet seed
    /// (FIPS 204 Algorithm 6, ML-DSA.KeyGen_internal — see the `ml-dsa`
    /// dependency comment in `Cargo.toml`). Deterministic construction exists
    /// so standards-anchored known-answer vectors can drive the real code
    /// path; a live handshake normally uses [`Identity::generate`].
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let signing_key = SigningKey::<MlDsa87>::from_seed(&(*seed).into());
        let public_key_bytes = signing_key.verifying_key().encode().as_slice().to_vec();
        Self { signing_key, public_key_bytes }
    }

    /// Generates a fresh ML-DSA-87 long-term identity from OS entropy.
    pub fn generate() -> Self {
        Self::from_seed(&os_random::<32>())
    }

    /// The raw [`PUBLIC_KEY_SIZE`]-octet ML-DSA-87 public-key encoding — the
    /// TLV 0x09 IdentityKey value this identity's CertVerify signatures are
    /// verified against.
    pub fn public_key_bytes(&self) -> &[u8] {
        &self.public_key_bytes
    }
}

/// Produces the TLV 0x0A CertVerify value for the given role using ML-DSA-87:
/// SignatureScheme u16 (0x0906) || ML-DSA-87 signature over
/// [`crate::handshake::cert_verify_signing_input`]. `SignDeterministic` (rnd=0)
/// is used, not randomized signing, so the value is reproducible for
/// known-answer testing — mirroring the Go reference's `SignCertVerifyMLDSA87`
/// and this crate's own `sign_cert_verify` (Ed25519) deterministic convention.
pub fn sign_certverify_mldsa87(identity: &Identity, is_server: bool, transcript_hash: &[u8]) -> Result<Vec<u8>, Error> {
    let input = cert_verify_signing_input(is_server, transcript_hash);
    let sig = identity.signing_key.expanded_key().sign_deterministic(&input, &[]).map_err(|_| Error::Sign)?;
    let mut out = Vec::with_capacity(2 + SIGNATURE_SIZE);
    out.extend_from_slice(&SIG_MLDSA87.to_be_bytes());
    out.extend_from_slice(sig.encode().as_slice());
    Ok(out)
}

/// Checks a TLV 0x0A value against the peer's raw ML-DSA-87 public-key
/// encoding (`peer_pub_raw`, [`PUBLIC_KEY_SIZE`] octets), role, and transcript
/// hash. Rejects a signature scheme other than the negotiated ML-DSA-87
/// (0x0906), a wrong-length public key or signature, or — because the role
/// selects the context string — a server CertVerify presented as a client
/// one. Mirrors `VerifyCertVerifyMLDSA87` and this crate's own
/// `verify_cert_verify` (Ed25519). Fail-closed: any malformed input (a
/// truncated public key, a truncated or structurally invalid signature — a
/// bad hint weight, an oversized `z` coefficient — per FIPS 204's `Verify`
/// internal well-formedness checks) returns `false`, never panics.
pub fn verify_certverify_mldsa87(peer_pub_raw: &[u8], is_server: bool, transcript_hash: &[u8], value: &[u8]) -> bool {
    if peer_pub_raw.len() != PUBLIC_KEY_SIZE {
        return false;
    }
    if value.len() != 2 + SIGNATURE_SIZE {
        return false;
    }
    if u16::from_be_bytes([value[0], value[1]]) != SIG_MLDSA87 {
        return false;
    }
    let Ok(vk_enc) = EncodedVerifyingKey::<MlDsa87>::try_from(peer_pub_raw) else {
        return false;
    };
    let vk = VerifyingKey::<MlDsa87>::decode(&vk_enc);
    let Ok(sig_enc) = EncodedSignature::<MlDsa87>::try_from(&value[2..]) else {
        return false;
    };
    let Some(sig) = Signature::<MlDsa87>::decode(&sig_enc) else {
        return false;
    };
    let input = cert_verify_signing_input(is_server, transcript_hash);
    vk.verify_with_context(&input, &[], &sig)
}
