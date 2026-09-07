// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

//! SecP384r1MLKEM1024 (KEM 0x11ed, `KEM_SECP384R1_MLKEM1024`) — the High/Sovereign
//! minimum hybrid KEM (registries/kem.csv; RFC 10024, formerly
//! draft-ietf-tls-ecdhe-mlkem). Mirrors `impl/go/kem1024.go` +
//! `impl/go/keyschedule.go`'s `HandshakeSecret1024` byte-for-byte: same wire sizes,
//! same ECDHE-first (P-384-first) ordering both on the wire and in the combined
//! shared secret, same fail-closed Standard-profile rejection.
//!
//! Unlike X25519MLKEM768 (ML-KEM-first "for historical reasons", `session.rs`'s
//! `KemClient`/`encapsulate`), the SecP* hybrid groups place the ECDHE component
//! FIRST — on the wire AND in the combined shared secret — per the FIPS-approved
//! ordering (NIST SP 800-56C Rev. 2) applied to this group's defining document.
//!
//! Sizes are per FIPS 203 (ML-KEM-1024) and the secp384r1 uncompressed point
//! encoding (SEC1, 0x04 || X || Y).

use kem::Decapsulate;
use ml_kem::array::Array;
use ml_kem::{Ciphertext, EncapsulateDeterministic, EncodedSizeUser, KemCore, MlKem1024};
use p384::ecdh;
use p384::{PublicKey as P384PublicKey, SecretKey as P384SecretKey};

/// secp384r1 uncompressed point size (0x04 || X || Y): 1 + 48 + 48, per SEC1 /
/// RFC 9846 section 4.3.8.2.
pub const P384_PUBLIC_KEY_SIZE: usize = 97;
/// secp384r1 ECDH shared secret size: the x-coordinate of the shared point as an
/// octet string.
pub const P384_SHARED_SECRET_SIZE: usize = 48;
/// FIPS 203 ML-KEM-1024 encapsulation-key (public key) encoded size.
const MLKEM1024_EK_LEN: usize = 1568;
/// FIPS 203 ML-KEM-1024 ciphertext encoded size.
const MLKEM1024_CT_LEN: usize = 1568;
/// FIPS 203 ML-KEM shared-key size (all parameter sets).
const MLKEM_SHARED_KEY_LEN: usize = 32;

/// TLV 0x07 value size for SecP384r1MLKEM1024: secp384r1 public key (97) ||
/// ML-KEM-1024 encapsulation key (1568), ECDHE-first.
pub const KEM_SHARE_SIZE_1024: usize = P384_PUBLIC_KEY_SIZE + MLKEM1024_EK_LEN; // 1665

/// TLV 0x08 value size for SecP384r1MLKEM1024: server secp384r1 public key (97) ||
/// ML-KEM-1024 ciphertext (1568), ECDHE-first.
pub const KEM_CIPHERTEXT_SIZE_1024: usize = P384_PUBLIC_KEY_SIZE + MLKEM1024_CT_LEN; // 1665

/// Raw HKDF-Extract IKM size: secp384r1 shared secret (48) || ML-KEM-1024 shared
/// secret (32), ECDHE-first.
pub const COMBINED_SECRET_SIZE_1024: usize = P384_SHARED_SECRET_SIZE + MLKEM_SHARED_KEY_LEN; // 80

type Ek1024 = <MlKem1024 as KemCore>::EncapsulationKey;
type Dk1024 = <MlKem1024 as KemCore>::DecapsulationKey;

/// Errors from the SecP384r1MLKEM1024 KEM operations. Named, not string-typed, so
/// a caller can match on the failure class the way the Go reference's sentinel
/// errors (`ErrKEMShare1024Size`, `ErrKEMCiphertext1024Size`,
/// `ErrHandshakeSecret1024StandardProfile`) allow.
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    /// KEMShare is not 1665 octets (secp384r1 pub || ML-KEM-1024 ek).
    KemShareSize,
    /// KEMCiphertext is not 1665 octets (server secp384r1 pub || ML-KEM-1024 ct).
    KemCiphertextSize,
    /// A secp384r1 private-key scalar was zero, out of range, or otherwise invalid.
    P384PrivateKey,
    /// A secp384r1 public-key encoding was malformed or the point at infinity.
    P384PublicKey,
    /// The secp384r1 ECDH result was the identity (all-zero) point — rejected the
    /// same way `crypto/ecdh`'s `ECDH` method rejects an invalid/identity result.
    P384IdentityResult,
    /// The ML-KEM-1024 `d || z` seed was not 64 octets.
    MlKemSeed,
    /// The ML-KEM-1024 encapsulation key encoding was malformed.
    MlKemEncapsulationKey,
    /// The ML-KEM-1024 ciphertext encoding was malformed.
    MlKemCiphertext,
    /// ML-KEM-1024 decapsulation failed structurally (wrong-length input; a
    /// corrupt ciphertext body instead yields a pseudorandom secret via FIPS 203
    /// implicit rejection, which is not an error here — it fails the Finished MAC
    /// later, per the Go reference's documented behavior).
    MlKemDecapsulate,
    /// ML-KEM-1024 encapsulation failed structurally.
    MlKemEncapsulate,
    /// `handshake_secret_1024` was called with the Standard profile.
    /// SecP384r1MLKEM1024 is the High/Sovereign minimum KEM
    /// (spec/05_profiles.md "Minimum KEM"); Standard uses X25519MLKEM768 and the
    /// 768 combiner instead. A Standard session that reached this call would be a
    /// protocol-layer bug upstream (KEM-group selection is profile-derived), so
    /// this is fail-closed rather than a silent fallback to the wrong
    /// combiner/hash.
    StandardProfileForbidden,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let msg = match self {
            Error::KemShareSize => "npamp: KEMShare is not 1665 octets (secp384r1 pub || ML-KEM-1024 ek)",
            Error::KemCiphertextSize => "npamp: KEMCiphertext is not 1665 octets (server secp384r1 pub || ML-KEM-1024 ct)",
            Error::P384PrivateKey => "npamp: secp384r1 private key",
            Error::P384PublicKey => "npamp: secp384r1 public key",
            Error::P384IdentityResult => "npamp: secp384r1 exchange produced the identity point",
            Error::MlKemSeed => "npamp: ML-KEM-1024 seed",
            Error::MlKemEncapsulationKey => "npamp: ML-KEM-1024 encapsulation key",
            Error::MlKemCiphertext => "npamp: ML-KEM-1024 ciphertext",
            Error::MlKemDecapsulate => "npamp: ML-KEM-1024 decapsulate",
            Error::MlKemEncapsulate => "npamp: ML-KEM-1024 encapsulate",
            Error::StandardProfileForbidden => {
                "npamp: handshake_secret_1024 called with the Standard profile (SecP384r1MLKEM1024 is High/Sovereign only, spec/05_profiles.md)"
            }
        };
        f.write_str(msg)
    }
}

impl std::error::Error for Error {}

/// Fills a fresh array with OS entropy (no rand_core trait plumbing), matching
/// `session.rs`'s `os_random`.
fn os_random<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    getrandom::getrandom(&mut b).expect("OS CSPRNG");
    b
}

/// Generates a fresh, valid secp384r1 private key from OS entropy via rejection
/// sampling: a uniformly random 48-octet string is invalid only if it is zero or
/// falls in the astronomically small [order, 2^384) tail, so this loop is bounded
/// and its exhaustion is a genuine CSPRNG or platform failure, not a normal path.
fn random_p384_secret_key() -> Result<P384SecretKey, Error> {
    for _ in 0..16 {
        let candidate = os_random::<48>();
        if let Ok(sk) = P384SecretKey::from_slice(&candidate) {
            return Ok(sk);
        }
    }
    Err(Error::P384PrivateKey)
}

/// The two component shared secrets of the SecP384r1MLKEM1024 hybrid KEM. There is
/// no hybrid-layer KDF: the key schedule's HKDF-Extract (`handshake_secret_1024`)
/// is the combiner, and its IKM is the ECDHE-first concatenation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SharedSecrets1024 {
    /// 48 octets, secp384r1 ECDH shared secret (x-coordinate).
    pub ecdhe: Vec<u8>,
    /// 32 octets, FIPS 203 ML-KEM-1024 shared secret.
    pub mlkem: Vec<u8>,
}

impl SharedSecrets1024 {
    /// Returns ECDHE_SS || ML-KEM_SS (80 octets), the raw IKM fed to HKDF-Extract.
    /// ECDHE-first (P-384 first) — the reverse of the X25519MLKEM768 order.
    pub fn combined(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.ecdhe.len() + self.mlkem.len());
        out.extend_from_slice(&self.ecdhe);
        out.extend_from_slice(&self.mlkem);
        out
    }
}

/// The client (initiator) side of the SecP384r1MLKEM1024 exchange: generates the
/// two component key pairs, publishes the KEMShare, and decapsulates the server's
/// KEMCiphertext.
pub struct KemClient1024 {
    mlkem_dk: Dk1024,
    mlkem_ek_bytes: Vec<u8>,
    p384_sk: P384SecretKey,
}

impl KemClient1024 {
    /// Generates a fresh client KEM state from a secure random source.
    pub fn generate() -> Result<Self, Error> {
        let seed = os_random::<64>();
        let p384_sk = random_p384_secret_key()?;
        Self::from_seed_and_key(&seed, p384_sk)
    }

    /// Builds a client KEM state from fixed key material: a 64-octet ML-KEM-1024
    /// seed in FIPS 203 "d || z" form and a secp384r1 private-key scalar (big-endian,
    /// as accepted by `p384::SecretKey::from_slice`). Deterministic construction
    /// exists so standards-anchored known-answer vectors can drive the real code
    /// path; live handshakes use [`KemClient1024::generate`].
    pub fn from_seed(mlkem_dz_seed: &[u8; 64], p384_private_key: &[u8]) -> Result<Self, Error> {
        let p384_sk = P384SecretKey::from_slice(p384_private_key).map_err(|_| Error::P384PrivateKey)?;
        Self::from_seed_and_key(mlkem_dz_seed, p384_sk)
    }

    fn from_seed_and_key(mlkem_dz_seed: &[u8; 64], p384_sk: P384SecretKey) -> Result<Self, Error> {
        let d = Array::try_from(&mlkem_dz_seed[..32]).map_err(|_| Error::MlKemSeed)?;
        let z = Array::try_from(&mlkem_dz_seed[32..]).map_err(|_| Error::MlKemSeed)?;
        let (dk, ek) = MlKem1024::generate_deterministic(&d, &z);
        Ok(KemClient1024 { mlkem_dk: dk, mlkem_ek_bytes: ek.as_bytes().as_slice().to_vec(), p384_sk })
    }

    /// Returns the TLV 0x07 value: secp384r1 public key (97) || ML-KEM-1024
    /// encapsulation key (1568), 1665 octets, ECDHE-first.
    pub fn kem_share(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(KEM_SHARE_SIZE_1024);
        out.extend_from_slice(p384::Sec1Point::from(self.p384_sk.public_key()).as_bytes());
        out.extend_from_slice(&self.mlkem_ek_bytes);
        out
    }

    /// Decapsulates a TLV 0x08 KEMCiphertext value (server secp384r1 public key
    /// (97) || ML-KEM-1024 ciphertext (1568)) into the two component shared
    /// secrets. A corrupt ML-KEM ciphertext body yields a pseudorandom secret via
    /// FIPS 203 implicit rejection (it fails the Finished MAC later, not here); an
    /// invalid or identity secp384r1 point is rejected with an error.
    pub fn shared_secrets(&self, kem_ciphertext: &[u8]) -> Result<SharedSecrets1024, Error> {
        if kem_ciphertext.len() != KEM_CIPHERTEXT_SIZE_1024 {
            return Err(Error::KemCiphertextSize);
        }
        let server_pub_bytes = &kem_ciphertext[..P384_PUBLIC_KEY_SIZE];
        let ct_bytes = &kem_ciphertext[P384_PUBLIC_KEY_SIZE..];
        let server_pub = P384PublicKey::from_sec1_bytes(server_pub_bytes).map_err(|_| Error::P384PublicKey)?;
        let shared = ecdh::diffie_hellman(self.p384_sk.to_nonzero_scalar(), server_pub.as_affine());
        let ecdhe_ss = shared.raw_secret_bytes().to_vec();
        if ecdhe_ss.iter().all(|&b| b == 0) {
            return Err(Error::P384IdentityResult);
        }
        let ct: Ciphertext<MlKem1024> = Array::try_from(ct_bytes).map_err(|_| Error::MlKemCiphertext)?;
        let mlkem_ss = self.mlkem_dk.decapsulate(&ct).map_err(|_| Error::MlKemDecapsulate)?;
        Ok(SharedSecrets1024 { ecdhe: ecdhe_ss, mlkem: mlkem_ss.as_slice().to_vec() })
    }
}

/// The server (responder) side of the SecP384r1MLKEM1024 exchange: parses the
/// client's KEMShare, generates a fresh server secp384r1 key, performs ECDH,
/// encapsulates to the ML-KEM-1024 key, and returns the TLV 0x08 KEMCiphertext
/// value plus the component shared secrets.
pub fn encapsulate(kem_share: &[u8]) -> Result<(Vec<u8>, SharedSecrets1024), Error> {
    let server_p384 = random_p384_secret_key()?;
    encapsulate_with(kem_share, &server_p384)
}

/// [`encapsulate`] with a caller-supplied server secp384r1 private key (the
/// ML-KEM-1024 encapsulation randomness still comes from the secure random source).
/// Exists so known-answer vectors can pin the secp384r1 half to published values
/// through the real server code path — the ML-KEM leg's encapsulation randomness is
/// NOT pinned by the KAT (mirroring `impl/go/kem1024.go`'s `EncapsulateWith1024`,
/// which documents the identical scope for `crypto/mlkem`'s internal randomness).
pub fn encapsulate_with(kem_share: &[u8], server_p384: &P384SecretKey) -> Result<(Vec<u8>, SharedSecrets1024), Error> {
    if kem_share.len() != KEM_SHARE_SIZE_1024 {
        return Err(Error::KemShareSize);
    }
    let client_pub_bytes = &kem_share[..P384_PUBLIC_KEY_SIZE];
    let ek_bytes = &kem_share[P384_PUBLIC_KEY_SIZE..];
    let client_pub = P384PublicKey::from_sec1_bytes(client_pub_bytes).map_err(|_| Error::P384PublicKey)?;
    let ek_arr = Array::try_from(ek_bytes).map_err(|_| Error::MlKemEncapsulationKey)?;
    let ek = Ek1024::from_bytes(&ek_arr);

    let shared = ecdh::diffie_hellman(server_p384.to_nonzero_scalar(), client_pub.as_affine());
    let ecdhe_ss = shared.raw_secret_bytes().to_vec();
    if ecdhe_ss.iter().all(|&b| b == 0) {
        return Err(Error::P384IdentityResult);
    }

    let m = os_random::<32>();
    let m_arr = Array::try_from(&m[..]).map_err(|_| Error::MlKemEncapsulate)?;
    let (ct, mlkem_ss) = ek.encapsulate_deterministic(&m_arr).map_err(|_| Error::MlKemEncapsulate)?;

    let mut kem_ct = Vec::with_capacity(KEM_CIPHERTEXT_SIZE_1024);
    kem_ct.extend_from_slice(p384::Sec1Point::from(server_p384.public_key()).as_bytes());
    kem_ct.extend_from_slice(ct.as_slice());
    Ok((kem_ct, SharedSecrets1024 { ecdhe: ecdhe_ss, mlkem: mlkem_ss.as_slice().to_vec() }))
}

/// handshake_secret_1024 = HKDF-Extract(salt = HashLen x 0x00, IKM = ss.combined())
/// (spec/10 section 5, section 4a). Identical construction to
/// [`crate::derive_handshake_secret`] over the wider 1024 shared-secret type:
/// `ss.combined()` is ECDHE_SS || ML-KEM_SS (SecP384r1MLKEM1024 is ECDHE-first, the
/// reverse of X25519MLKEM768's ML-KEM-first order). `standard` selects SHA-256 vs
/// SHA-384 exactly like the rest of the key schedule — but High/Sovereign are the
/// only profiles that may reach this call; `standard = true` (Standard profile) is
/// fail-closed (see [`Error::StandardProfileForbidden`]).
pub fn handshake_secret_1024(ss: &SharedSecrets1024, standard: bool) -> Result<Vec<u8>, Error> {
    if standard {
        return Err(Error::StandardProfileForbidden);
    }
    Ok(crate::hkdf_extract(&vec![0u8; 48], &ss.combined(), standard))
}
