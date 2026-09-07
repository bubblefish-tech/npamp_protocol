// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

//! Dedicated PQ audit-seal key (decision-B residual (b) — pending maintainer
//! ratification): a cryptographically SEPARATE ML-DSA-87 key that seals
//! `nz-agent` audit records, distinct from the Ed25519 identity
//! `crate::identity::Svid` carries for N-PAMP session authentication.
//!
//! # Why a second key
//!
//! Today the only long-term key `nz-agent` provisions per workload is the
//! Ed25519 `SigningKey` in [`crate::identity::Svid`] — it authenticates that
//! workload's `npamp::session::Session` handshake. Reusing that SAME key to
//! also seal an audit record would collapse two distinct security purposes
//! ("prove who I am to a peer" and "attest what I recorded, to a verifier who
//! may check it long after the session is gone") onto one key, which is a
//! purpose-separation weakness: a compromise, rotation, or cryptanalytic
//! advance affecting one purpose then affects the other, and a party who only
//! needs to verify audit seals would otherwise need the workload's live
//! session-authentication key.
//!
//! This module provisions a SEPARATE [`AuditSealIdentity`] — its own ML-DSA-87
//! (FIPS 204, IANA TLS SignatureScheme 0x0906 — `npamp::SIG_MLDSA87`) signing
//! key, generated independently of any `Svid`/session identity, with no
//! functional relationship to it (not derived from it, not a function of it).
//! It builds on the SAME `ml-dsa` crate (RustCrypto) and the SAME
//! deterministic-seed / `sign_deterministic` (rnd=0) pattern the reference
//! library's [`npamp::mldsa87::Identity`] already uses for CertVerify — see
//! that module's docs for the primary-source grounding of the underlying FIPS
//! 204 algorithms — but is its own type, with its own signing-input domain
//! separator ([`AUDIT_SEAL_DOMAIN`], distinct from CertVerify's role-context
//! construction), because signing an audit record is a different operation
//! from signing a handshake transcript and MUST NOT share a signing-input
//! shape with it (two operations that could ever produce the same bytes under
//! the same key are a cross-protocol signature-confusion hazard). This crate
//! never edits the `npamp` reference library (see this crate's own
//! `Cargo.toml` header) — this module is entirely additive, in its own file,
//! and touches no existing session-identity code path.
//!
//! **Pending maintainer ratification.** This is the RECOMMENDED disposition
//! for the PQ-audit-seal signer key-provisioning residual: a dedicated key,
//! separate from the session-identity key, by design.

use ml_dsa::{EncodedSignature, EncodedVerifyingKey, Keypair, MlDsa87, Signature, SigningKey, VerifyingKey};

use npamp::SIG_MLDSA87;

/// FIPS 204 ML-DSA-87 public-key encoding size — matches
/// `npamp::mldsa87::PUBLIC_KEY_SIZE` (same parameter set, same encoding).
pub const PUBLIC_KEY_SIZE: usize = 2592;
/// FIPS 204 ML-DSA-87 signature encoding size — matches
/// `npamp::mldsa87::SIGNATURE_SIZE`.
pub const SIGNATURE_SIZE: usize = 4627;

/// Domain separator for the audit-seal signing input — deliberately distinct
/// from `npamp::handshake::cert_verify_signing_input`'s CertVerify shape (64
/// x 0x20 || role context || 0x00 || transcript hash), so an audit seal and a
/// CertVerify value can never collide as the same signed bytes even if a key
/// were (incorrectly) shared between the two purposes.
const AUDIT_SEAL_DOMAIN: &[u8] = b"N-PAMP-AGENT-AUDIT-SEAL-v1";

/// Errors from the audit-seal operations. Named per failure class, matching
/// `npamp::mldsa87::Error`'s convention.
#[derive(Debug, PartialEq, Eq)]
pub enum AuditSealError {
    /// No dedicated audit-seal key was provisioned. Fail-closed: this crate
    /// never emits an unsigned record dressed up as "sealed" — the caller
    /// gets an explicit error and must either provision a key or explicitly
    /// handle the absence.
    NoKey,
    /// `sign_deterministic` failed. Cannot happen for this module's
    /// fixed-shape signing input (see [`npamp::mldsa87::Error::Sign`]'s
    /// identical reasoning), surfaced rather than panicking so a future
    /// crate-internal change cannot turn into a panic here.
    Sign,
    /// The peer's ML-DSA-87 public-key encoding is not [`PUBLIC_KEY_SIZE`]
    /// octets — includes the case where a caller mistakenly passes a
    /// different key type's encoding (e.g. a 32-octet Ed25519
    /// session-identity public key) to a verifier expecting an audit-seal
    /// key.
    PublicKeySize,
}

impl core::fmt::Display for AuditSealError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let msg = match self {
            AuditSealError::NoKey => "nz-agent: no dedicated audit-seal key provisioned; refusing to seal (fail-closed)",
            AuditSealError::Sign => "nz-agent: audit-seal signing failed",
            AuditSealError::PublicKeySize => "nz-agent: audit-seal public key is not 2592 octets",
        };
        f.write_str(msg)
    }
}

impl std::error::Error for AuditSealError {}

/// Fills a fresh array with OS entropy — mirrors
/// `npamp::mldsa87`'s own `os_random` (same `getrandom` crate, same pattern).
fn os_random<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    getrandom::getrandom(&mut b).expect("OS CSPRNG");
    b
}

/// The dedicated PQ audit-seal identity: an ML-DSA-87 signing key provisioned
/// SEPARATELY from any `crate::identity::Svid`'s Ed25519 session-identity
/// key, plus its cached public-key encoding. Nothing in this type is derived
/// from, or a function of, a session identity — [`AuditSealIdentity::generate`]
/// draws fresh OS entropy independent of any other key material in the
/// process.
pub struct AuditSealIdentity {
    signing_key: SigningKey<MlDsa87>,
    public_key_bytes: Vec<u8>,
}

impl AuditSealIdentity {
    /// Deterministically builds an audit-seal identity from its 32-octet seed
    /// (FIPS 204 Algorithm 6, ML-DSA.KeyGen_internal). Deterministic
    /// construction exists so a known-answer test can drive the real code
    /// path; production provisioning uses [`AuditSealIdentity::generate`].
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let signing_key = SigningKey::<MlDsa87>::from_seed(&(*seed).into());
        let public_key_bytes = signing_key.verifying_key().encode().as_slice().to_vec();
        Self { signing_key, public_key_bytes }
    }

    /// Generates a fresh, independent audit-seal identity from OS entropy —
    /// the provisioning path a live `nz-agent` deployment uses. Independent
    /// of any session-identity key: no session material is read, mixed in,
    /// or otherwise consulted.
    pub fn generate() -> Self {
        Self::from_seed(&os_random::<32>())
    }

    /// The raw [`PUBLIC_KEY_SIZE`]-octet ML-DSA-87 public-key encoding — what
    /// a verifier checks a sealed audit record against.
    pub fn public_key_bytes(&self) -> &[u8] {
        &self.public_key_bytes
    }
}

/// A sealed audit record: the raw record bytes as sealed, plus the
/// SignatureScheme-tagged ML-DSA-87 signature over
/// [`audit_seal_signing_input`]`(record)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditSeal {
    pub record: Vec<u8>,
    pub signature: Vec<u8>,
}

fn audit_seal_signing_input(record: &[u8]) -> Vec<u8> {
    let mut input = Vec::with_capacity(AUDIT_SEAL_DOMAIN.len() + 1 + record.len());
    input.extend_from_slice(AUDIT_SEAL_DOMAIN);
    input.push(0x00);
    input.extend_from_slice(record);
    input
}

/// Seals `record` under the DEDICATED audit-seal `identity` — never the
/// session-identity key. Fail-closed by construction: `identity` is
/// `Option<&AuditSealIdentity>` because a caller (e.g. an `nz-agent` node
/// that has not been configured with an audit-seal key) may not have one
/// provisioned, and the absent case is a hard [`AuditSealError::NoKey`], not
/// a silently-unsigned record labeled sealed.
///
/// The returned signature is `SignatureScheme u16 (0x0906) || ML-DSA-87
/// signature over [`audit_seal_signing_input`]`(record)`` — the same
/// SignatureScheme-tag-then-signature shape `npamp::mldsa87`'s CertVerify
/// value uses, over a DIFFERENT (audit-seal-domain-separated) signing input,
/// so the two never collide as the same signed bytes.
pub fn seal_audit_record(identity: Option<&AuditSealIdentity>, record: &[u8]) -> Result<AuditSeal, AuditSealError> {
    let identity = identity.ok_or(AuditSealError::NoKey)?;
    let input = audit_seal_signing_input(record);
    let sig = identity.signing_key.expanded_key().sign_deterministic(&input, &[]).map_err(|_| AuditSealError::Sign)?;
    let mut signature = Vec::with_capacity(2 + SIGNATURE_SIZE);
    signature.extend_from_slice(&SIG_MLDSA87.to_be_bytes());
    signature.extend_from_slice(sig.encode().as_slice());
    Ok(AuditSeal { record: record.to_vec(), signature })
}

/// Checks an [`AuditSeal`]'s `signature` against the given raw ML-DSA-87
/// public-key encoding (`peer_pub_raw`, [`PUBLIC_KEY_SIZE`] octets) and
/// `record`. Rejects a signature scheme other than ML-DSA-87 (0x0906), a
/// wrong-length public key or signature (including a session-identity
/// Ed25519 key's 32-octet encoding — the length check alone fails it
/// closed), or a structurally invalid signature. Fail-closed: any malformed
/// input returns `false`, never panics.
pub fn verify_audit_seal(peer_pub_raw: &[u8], record: &[u8], signature: &[u8]) -> bool {
    if peer_pub_raw.len() != PUBLIC_KEY_SIZE {
        return false;
    }
    if signature.len() != 2 + SIGNATURE_SIZE {
        return false;
    }
    if u16::from_be_bytes([signature[0], signature[1]]) != SIG_MLDSA87 {
        return false;
    }
    let Ok(vk_enc) = EncodedVerifyingKey::<MlDsa87>::try_from(peer_pub_raw) else {
        return false;
    };
    let vk = VerifyingKey::<MlDsa87>::decode(&vk_enc);
    let Ok(sig_enc) = EncodedSignature::<MlDsa87>::try_from(&signature[2..]) else {
        return false;
    };
    let Some(sig) = Signature::<MlDsa87>::decode(&sig_enc) else {
        return false;
    };
    let input = audit_seal_signing_input(record);
    vk.verify_with_context(&input, &[], &sig)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seed(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    #[test]
    fn fails_closed_with_no_key() {
        let err = seal_audit_record(None, b"audit record: workload X reached destination Y").expect_err("must fail closed with no key");
        assert_eq!(err, AuditSealError::NoKey);
    }

    #[test]
    fn seals_and_verifies_under_the_dedicated_key() {
        let identity = AuditSealIdentity::from_seed(&seed(0x11));
        let record = b"audit record: capability grant issued";
        let seal = seal_audit_record(Some(&identity), record).expect("seal");
        assert_eq!(seal.record, record);
        assert!(verify_audit_seal(identity.public_key_bytes(), record, &seal.signature), "must verify under the dedicated key's own public key");
    }

    #[test]
    fn rejects_a_tampered_record() {
        let identity = AuditSealIdentity::from_seed(&seed(0x22));
        let seal = seal_audit_record(Some(&identity), b"original record").expect("seal");
        assert!(!verify_audit_seal(identity.public_key_bytes(), b"tampered record", &seal.signature));
    }

    #[test]
    fn rejects_verification_under_a_different_audit_seal_key() {
        let a = AuditSealIdentity::from_seed(&seed(0x33));
        let b = AuditSealIdentity::from_seed(&seed(0x44));
        let record = b"audit record sealed by a";
        let seal = seal_audit_record(Some(&a), record).expect("seal");
        assert!(!verify_audit_seal(b.public_key_bytes(), record, &seal.signature), "must not verify under an UNRELATED audit-seal key");
    }

    /// The core claim this residual exists to satisfy: the audit-seal key is
    /// a cryptographically SEPARATE key from the session-identity key.
    #[test]
    fn audit_seal_key_is_distinct_from_the_session_identity_key() {
        // The real session-identity key: `npamp::session::generate_identity`,
        // the exact constructor `crate::identity::StaticIdentitySource` uses
        // to mint each `Svid`'s Ed25519 key.
        let session_identity_key = npamp::session::generate_identity();
        let session_pub_bytes = session_identity_key.verifying_key().to_bytes(); // 32 octets, Ed25519

        let audit_identity = AuditSealIdentity::from_seed(&seed(0x55));
        let audit_pub_bytes = audit_identity.public_key_bytes(); // 2592 octets, ML-DSA-87

        // Different algorithm, different encoding size — not merely
        // "different bytes" by chance, but structurally a different key.
        assert_ne!(session_pub_bytes.len(), audit_pub_bytes.len());
        assert_eq!(audit_pub_bytes.len(), PUBLIC_KEY_SIZE);

        // Fail-closed cross-check: a seal produced under the dedicated
        // audit-seal key MUST NOT verify against the session-identity key's
        // public bytes — the length check alone must reject it, proving the
        // two key spaces are disjoint (an Ed25519 public key can never be
        // mistaken for an ML-DSA-87 one by this verifier).
        let record = b"audit record: sealed by the dedicated PQ key, never the session key";
        let seal = seal_audit_record(Some(&audit_identity), record).expect("seal");
        assert!(
            !verify_audit_seal(&session_pub_bytes, record, &seal.signature),
            "an audit seal produced by the dedicated key must NOT verify under the session-identity key"
        );
    }

    /// Independent provisioning: two calls to `generate()` produce
    /// unrelated keys (no shared/derived relationship), matching the "not
    /// derived from, not a function of, a session identity" design claim.
    #[test]
    fn generate_produces_independent_keys_across_calls() {
        let a = AuditSealIdentity::generate();
        let b = AuditSealIdentity::generate();
        assert_ne!(a.public_key_bytes(), b.public_key_bytes());
    }

    #[test]
    fn from_seed_is_deterministic_known_answer() {
        let a = AuditSealIdentity::from_seed(&seed(0x66));
        let b = AuditSealIdentity::from_seed(&seed(0x66));
        assert_eq!(a.public_key_bytes(), b.public_key_bytes());
        let record = b"deterministic KAT record";
        let seal_a = seal_audit_record(Some(&a), record).expect("seal a");
        let seal_b = seal_audit_record(Some(&b), record).expect("seal b");
        assert_eq!(seal_a.signature, seal_b.signature, "same seed + same record must produce the SAME seal (rnd=0 deterministic signing)");
    }
}
