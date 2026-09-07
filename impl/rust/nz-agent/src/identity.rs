// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

//! SPIFFE identity binding (E2.6, R12 AC2): `nz-agent` binds every workload's
//! N-PAMP session to a SPIFFE X.509 SVID issued by SPIRE via OS-level workload
//! attestation — never an ambient/shared credential.
//!
//! # Grounded against the primary source (this build)
//!
//! [`SpiffeId::parse`] enforces the structural rules of the SPIFFE-ID
//! specification (`spiffe/spiffe` standards/SPIFFE-ID.md, fetched this build):
//! scheme MUST be `spiffe`; the trust domain MUST be non-empty, lowercase, and
//! contain only `[a-z0-9.-_]`; `userinfo` and port MUST be empty; a query or
//! fragment component MUST NOT be present; each path segment MUST contain only
//! `[a-zA-Z0-9.-_]` and MUST NOT be empty, `.`, or `..`; the path MUST NOT have
//! a trailing `/`; the scheme and trust domain are case-insensitive, the path
//! is case-sensitive; the whole URI MUST be at most 2048 bytes and the trust
//! domain at most 255 bytes.
//!
//! # The live SPIRE client (E2.6, closed this build)
//!
//! [`DelegatedIdentitySource`] is the seam a real SPIRE Workload API client
//! (the "DelegatedIdentity API" the design doc names — a gRPC surface over a
//! Unix-domain socket, documented in `spire-api-sdk`, consumed by a trusted
//! third party like `nz-agent` that does not run as the workload's own
//! process) implements. This build ships TWO siblings behind the trait:
//! [`StaticIdentitySource`] below (a deterministic in-memory test double —
//! kept, not replaced, for tests and local dev without a live SPIRE
//! deployment) and [`crate::spire_client::SpireWorkloadApiSource`] (the real
//! gRPC-over-UDS client, `src/spire_client.rs` — standing up a live SPIRE
//! Server+Agent is still infra this build environment cannot host, but the
//! client itself is built, wired into `bin/nz_agent.rs` via
//! `--spire-socket`, and tested end to end against an in-process mock
//! DelegatedIdentity server over a real Unix-domain socket). No change was
//! needed to [`crate::agent::NodeAgent`], exactly as this module's docs
//! previously predicted.

use std::collections::HashMap;
use std::fmt;

use ed25519_dalek::SigningKey;
use npamp::session;

/// A validated SPIFFE ID (`spiffe://trust-domain/path...`).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SpiffeId {
    trust_domain: String,
    path: String,
}

/// Why a candidate string is not a valid SPIFFE ID — named per the specific
/// structural rule violated, never a bare "invalid" (fail-closed callers need
/// to log WHY a workload's claimed identity was rejected).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpiffeIdError {
    TooLong(usize),
    WrongScheme,
    HasQueryOrFragment,
    EmptyTrustDomain,
    TrustDomainTooLong(usize),
    InvalidTrustDomainChar(char),
    NonEmptyUserinfoOrPort,
    EmptyPathSegment,
    RelativePathSegment(String),
    InvalidPathSegmentChar(char),
    TrailingSlash,
}

impl fmt::Display for SpiffeIdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SpiffeIdError::TooLong(n) => write!(f, "SPIFFE ID exceeds 2048 bytes ({n})"),
            SpiffeIdError::WrongScheme => write!(f, "scheme is not \"spiffe\""),
            SpiffeIdError::HasQueryOrFragment => write!(f, "SPIFFE ID MUST NOT include a query or fragment component"),
            SpiffeIdError::EmptyTrustDomain => write!(f, "trust domain is empty"),
            SpiffeIdError::TrustDomainTooLong(n) => write!(f, "trust domain exceeds 255 bytes ({n})"),
            SpiffeIdError::InvalidTrustDomainChar(c) => write!(f, "trust domain contains an invalid character {c:?} (only [a-z0-9.-_] allowed)"),
            SpiffeIdError::NonEmptyUserinfoOrPort => write!(f, "authority component carries userinfo or a port, which MUST be empty"),
            SpiffeIdError::EmptyPathSegment => write!(f, "path contains an empty segment"),
            SpiffeIdError::RelativePathSegment(s) => write!(f, "path contains a relative path modifier segment {s:?}"),
            SpiffeIdError::InvalidPathSegmentChar(c) => write!(f, "path segment contains an invalid character {c:?} (only [a-zA-Z0-9.-_] allowed)"),
            SpiffeIdError::TrailingSlash => write!(f, "path MUST NOT include a trailing '/'"),
        }
    }
}

impl std::error::Error for SpiffeIdError {}

const MAX_URI_LEN: usize = 2048;
const MAX_TRUST_DOMAIN_LEN: usize = 255;

fn is_trust_domain_char(c: char) -> bool {
    c.is_ascii_lowercase() || c.is_ascii_digit() || c == '.' || c == '-' || c == '_'
}

fn is_path_segment_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_'
}

impl SpiffeId {
    /// Parses and fully validates a candidate SPIFFE ID string. Fail-closed:
    /// any structural violation is a named [`SpiffeIdError`], never a
    /// best-effort partial ID.
    pub fn parse(s: &str) -> Result<SpiffeId, SpiffeIdError> {
        if s.len() > MAX_URI_LEN {
            return Err(SpiffeIdError::TooLong(s.len()));
        }
        let rest = s.strip_prefix("spiffe://").ok_or(SpiffeIdError::WrongScheme)?;
        if rest.contains('?') || rest.contains('#') {
            return Err(SpiffeIdError::HasQueryOrFragment);
        }
        let (authority, path) = match rest.find('/') {
            Some(idx) => (&rest[..idx], &rest[idx..]),
            None => (rest, ""),
        };
        if authority.contains('@') || authority.contains(':') {
            return Err(SpiffeIdError::NonEmptyUserinfoOrPort);
        }
        let trust_domain = authority.to_ascii_lowercase();
        if trust_domain.is_empty() {
            return Err(SpiffeIdError::EmptyTrustDomain);
        }
        if trust_domain.len() > MAX_TRUST_DOMAIN_LEN {
            return Err(SpiffeIdError::TrustDomainTooLong(trust_domain.len()));
        }
        if let Some(c) = trust_domain.chars().find(|&c| !is_trust_domain_char(c)) {
            return Err(SpiffeIdError::InvalidTrustDomainChar(c));
        }

        if path.ends_with('/') && path.len() > 1 {
            return Err(SpiffeIdError::TrailingSlash);
        }
        let path_body = path.trim_start_matches('/');
        if !path_body.is_empty() {
            for seg in path_body.split('/') {
                if seg.is_empty() {
                    return Err(SpiffeIdError::EmptyPathSegment);
                }
                if seg == "." || seg == ".." {
                    return Err(SpiffeIdError::RelativePathSegment(seg.to_string()));
                }
                if let Some(c) = seg.chars().find(|&c| !is_path_segment_char(c)) {
                    return Err(SpiffeIdError::InvalidPathSegmentChar(c));
                }
            }
        }

        Ok(SpiffeId { trust_domain, path: format!("/{path_body}") })
    }

    pub fn trust_domain(&self) -> &str {
        &self.trust_domain
    }

    pub fn path(&self) -> &str {
        &self.path
    }
}

impl fmt::Display for SpiffeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "spiffe://{}{}", self.trust_domain, self.path)
    }
}

/// A workload's X.509-SVID as `nz-agent` needs it: the proven [`SpiffeId`] plus
/// the Ed25519 identity key that the workload's `npamp::session::Session`
/// handshake authenticates with. This crate performs no X.509 parsing of its
/// own; a real SPIRE client validates the certificate chain and hands
/// `nz-agent` an `Svid` after that validation succeeds.
#[derive(Debug)]
pub struct Svid {
    id: SpiffeId,
    signing_key: SigningKey,
}

impl Svid {
    pub fn new(id: SpiffeId, signing_key: SigningKey) -> Svid {
        Svid { id, signing_key }
    }

    pub fn id(&self) -> &SpiffeId {
        &self.id
    }

    pub fn signing_key(&self) -> &SigningKey {
        &self.signing_key
    }
}

/// The seam a real SPIRE Workload API (DelegatedIdentity) client implements:
/// given the OS-attested process identity of a workload (its PID, per the
/// design doc's "PID + OS-level attestation" model), return the SVID SPIRE
/// issued it. Fail-closed by contract: an attestation failure or an unknown
/// workload MUST return `Err`, never a default/placeholder SVID.
pub trait DelegatedIdentitySource: Send + Sync {
    /// Fetches (or mints, for the static/test source) the SVID for the
    /// workload identified by `workload_pid`. `nz-agent` never accepts a
    /// self-asserted identity: the caller supplies only the OS-level
    /// attestation input (PID), never a claimed SPIFFE ID string.
    fn svid_for_workload(&self, workload_pid: u32) -> Result<Svid, IdentityError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentityError {
    UnknownWorkload(u32),
    Malformed(String),
    /// A [`DelegatedIdentitySource`] backed by a network/IPC transport
    /// (currently only [`crate::spire_client::SpireWorkloadApiSource`])
    /// could not reach its source — connect failure, transport error, or
    /// any non-`NotFound` RPC failure. Fail-closed: never silently
    /// substituted with a node-global or cached identity.
    Unreachable(String),
    /// The source returned a real SVID, but it had already expired
    /// (`expires_at <= now`) at the moment it was fetched. Fail-closed:
    /// an expired credential is refused, never handed to a caller as if
    /// still valid.
    Expired { pid: u32, expires_at_unix: i64 },
}

impl fmt::Display for IdentityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IdentityError::UnknownWorkload(pid) => write!(f, "no attested SVID for workload pid {pid}"),
            IdentityError::Malformed(m) => write!(f, "malformed SVID: {m}"),
            IdentityError::Unreachable(m) => write!(f, "identity source unreachable: {m}"),
            IdentityError::Expired { pid, expires_at_unix } => {
                write!(f, "SVID for workload pid {pid} expired at unix time {expires_at_unix}")
            }
        }
    }
}

impl std::error::Error for IdentityError {}

/// A deterministic, in-memory [`DelegatedIdentitySource`] test double: a fixed
/// table of `pid -> SpiffeId`, minting a fresh Ed25519 identity key per entry
/// at construction time. Used by this crate's own tests and by any caller
/// that wants a `NodeAgent` running without a live SPIRE deployment (e.g. a
/// local dev loop) — NOT for production (no attestation is actually
/// performed; the table is caller-trusted).
pub struct StaticIdentitySource {
    table: HashMap<u32, Svid>,
}

impl StaticIdentitySource {
    /// Builds a source from `(pid, spiffe_id)` pairs, minting a fresh identity
    /// key for each. Fails closed if any `spiffe_id` string does not parse.
    pub fn from_pairs(pairs: &[(u32, &str)]) -> Result<StaticIdentitySource, SpiffeIdError> {
        let mut table = HashMap::new();
        for (pid, raw) in pairs {
            let id = SpiffeId::parse(raw)?;
            let key = session::generate_identity();
            table.insert(*pid, Svid::new(id, key));
        }
        Ok(StaticIdentitySource { table })
    }
}

impl DelegatedIdentitySource for StaticIdentitySource {
    fn svid_for_workload(&self, workload_pid: u32) -> Result<Svid, IdentityError> {
        self.table
            .get(&workload_pid)
            .map(|svid| Svid::new(svid.id().clone(), svid.signing_key().clone()))
            .ok_or(IdentityError::UnknownWorkload(workload_pid))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test fixture trust domain: "cluster.local" is the conventional default
    // Kubernetes cluster DNS/SPIFFE trust domain (not a live network
    // endpoint — this module never dials it, it is a string identifier
    // compared structurally).
    const TD: &str = "cluster.local";

    #[test]
    fn accepts_a_well_formed_spiffe_id() {
        let id = SpiffeId::parse(&format!("spiffe://{TD}/ns/prod/sa/checkout")).expect("valid");
        assert_eq!(id.trust_domain(), TD);
        assert_eq!(id.path(), "/ns/prod/sa/checkout");
        assert_eq!(id.to_string(), format!("spiffe://{TD}/ns/prod/sa/checkout"));
    }

    #[test]
    fn trust_domain_is_case_folded_but_path_is_case_sensitive() {
        let id = SpiffeId::parse("spiffe://Cluster.Local/ns/Prod").expect("valid");
        assert_eq!(id.trust_domain(), TD);
        assert_eq!(id.path(), "/ns/Prod"); // path case preserved
    }

    #[test]
    fn rejects_wrong_scheme() {
        assert_eq!(SpiffeId::parse(&format!("https://{TD}/ns/prod")), Err(SpiffeIdError::WrongScheme));
    }

    #[test]
    fn rejects_query_and_fragment() {
        assert_eq!(SpiffeId::parse(&format!("spiffe://{TD}/ns?x=1")), Err(SpiffeIdError::HasQueryOrFragment));
        assert_eq!(SpiffeId::parse(&format!("spiffe://{TD}/ns#frag")), Err(SpiffeIdError::HasQueryOrFragment));
    }

    #[test]
    fn rejects_empty_trust_domain() {
        assert_eq!(SpiffeId::parse("spiffe:///ns/prod"), Err(SpiffeIdError::EmptyTrustDomain));
    }

    #[test]
    fn rejects_userinfo_and_port_in_authority() {
        assert_eq!(SpiffeId::parse(&format!("spiffe://user@{TD}/ns")), Err(SpiffeIdError::NonEmptyUserinfoOrPort));
        assert_eq!(SpiffeId::parse(&format!("spiffe://{TD}:8443/ns")), Err(SpiffeIdError::NonEmptyUserinfoOrPort));
    }

    #[test]
    fn rejects_relative_path_segments() {
        assert_eq!(SpiffeId::parse(&format!("spiffe://{TD}/ns/../prod")), Err(SpiffeIdError::RelativePathSegment("..".into())));
        assert_eq!(SpiffeId::parse(&format!("spiffe://{TD}/./prod")), Err(SpiffeIdError::RelativePathSegment(".".into())));
    }

    #[test]
    fn rejects_empty_path_segment_and_trailing_slash() {
        assert_eq!(SpiffeId::parse(&format!("spiffe://{TD}/ns//prod")), Err(SpiffeIdError::EmptyPathSegment));
        assert_eq!(SpiffeId::parse(&format!("spiffe://{TD}/ns/prod/")), Err(SpiffeIdError::TrailingSlash));
    }

    #[test]
    fn rejects_invalid_characters() {
        assert!(matches!(SpiffeId::parse("spiffe://Cluster_Local!/ns"), Err(SpiffeIdError::InvalidTrustDomainChar(_))));
        assert!(matches!(SpiffeId::parse(&format!("spiffe://{TD}/ns/prod$")), Err(SpiffeIdError::InvalidPathSegmentChar(_))));
    }

    #[test]
    fn no_path_is_valid_trust_domain_only_id() {
        let id = SpiffeId::parse(&format!("spiffe://{TD}")).expect("trust-domain-only id is valid");
        assert_eq!(id.path(), "/");
    }

    #[test]
    fn static_source_fails_closed_on_unknown_pid() {
        let src = StaticIdentitySource::from_pairs(&[(100, "spiffe://cluster.local/ns/prod/sa/a")]).expect("valid table");
        let err = src.svid_for_workload(999).expect_err("unknown pid must fail closed");
        assert_eq!(err, IdentityError::UnknownWorkload(999));
    }

    /// R12 AC2's core testable claim: two workloads, two keys. Directly
    /// exercised at the identity layer here (see agent.rs for the
    /// session-level version composing npamp::session::Session).
    #[test]
    fn two_workloads_get_distinct_identity_keys() {
        let src = StaticIdentitySource::from_pairs(&[
            (100, "spiffe://cluster.local/ns/prod/sa/a"),
            (200, "spiffe://cluster.local/ns/prod/sa/b"),
        ])
        .expect("valid table");
        let a = src.svid_for_workload(100).expect("a");
        let b = src.svid_for_workload(200).expect("b");
        assert_ne!(a.signing_key().verifying_key().to_bytes(), b.signing_key().verifying_key().to_bytes());
    }
}
