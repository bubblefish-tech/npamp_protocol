// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

//! Node-local L4 authorization (E2.6, design doc Component 1: "L4
//! authorization (which workload may reach which) enforced here, at the
//! node"). Independent of, and enforced BEFORE, any waypoint's L7 authz
//! ([`crate::waypoint`]) — the 80/20 split the design doc describes: most
//! workloads are L4-only, so this table is the ONLY authorization most
//! traffic ever passes through.
//!
//! # Fail-closed by construction
//!
//! [`AuthzTable::check`] has exactly one way to return `Allow`: an explicit
//! entry for the `(source, destination)` [`SpiffeId`] pair. There is no
//! wildcard-allow, no "unknown pair defaults to permit", and no notion of an
//! empty table meaning "everything is allowed" — an empty table denies
//! everything, which is what a fresh `nz-agent` with no policy pushed yet
//! MUST do.

use std::collections::HashSet;

use crate::identity::SpiffeId;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Deny,
}

/// Why a pair was denied — always populated on [`Decision::Deny`] so a caller
/// can log a specific, auditable reason rather than a bare "denied" (D3:
/// silent enforcement failures are a defect to investigate, not accept).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DenyReason {
    NoEntryForPair,
}

pub struct AuthzTable {
    // (source trust_domain+path, destination trust_domain+path) allow-set.
    // SpiffeId does not implement a total order needed for a BTreeSet, and a
    // hashable pair is exactly what this lookup needs.
    allowed: HashSet<(SpiffeId, SpiffeId)>,
}

impl AuthzTable {
    /// A fresh table denies every pair (fail-closed default — no entries
    /// means no traffic is authorized, matching the module docs).
    pub fn new() -> AuthzTable {
        AuthzTable { allowed: HashSet::new() }
    }

    /// Allows `source` to reach `destination`. Idempotent (allowing an
    /// already-allowed pair is a no-op, not an error).
    pub fn allow(&mut self, source: SpiffeId, destination: SpiffeId) {
        self.allowed.insert((source, destination));
    }

    /// Revokes a previously-allowed pair. A pair that was never allowed
    /// staying denied after a revoke is the correct (already fail-closed)
    /// outcome, not an error.
    pub fn revoke(&mut self, source: &SpiffeId, destination: &SpiffeId) {
        self.allowed.remove(&(source.clone(), destination.clone()));
    }

    /// The one authorization decision this crate's L4 layer makes: is there
    /// an explicit `(source, destination)` entry? Anything else — including
    /// an entry for `(source, X)` with a DIFFERENT destination, or `(X,
    /// destination)` with a different source — is [`Decision::Deny`].
    pub fn check(&self, source: &SpiffeId, destination: &SpiffeId) -> (Decision, Option<DenyReason>) {
        if self.allowed.contains(&(source.clone(), destination.clone())) {
            (Decision::Allow, None)
        } else {
            (Decision::Deny, Some(DenyReason::NoEntryForPair))
        }
    }
}

impl Default for AuthzTable {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(path: &str) -> SpiffeId {
        SpiffeId::parse(&format!("spiffe://cluster.local/ns/prod/sa/{path}")).expect("valid id")
    }

    #[test]
    fn fresh_table_denies_everything() {
        let t = AuthzTable::new();
        let (d, reason) = t.check(&id("a"), &id("b"));
        assert_eq!(d, Decision::Deny);
        assert_eq!(reason, Some(DenyReason::NoEntryForPair));
    }

    #[test]
    fn allowed_pair_is_allowed() {
        let mut t = AuthzTable::new();
        t.allow(id("a"), id("b"));
        assert_eq!(t.check(&id("a"), &id("b")).0, Decision::Allow);
    }

    /// Fail-closed: allowing A->B does NOT allow B->A (directionality) and
    /// does NOT allow A->C (destination-specificity). Mutated away by
    /// M-authz-1 in RED-EVIDENCE.md.
    #[test]
    fn allow_is_directional_and_destination_specific() {
        let mut t = AuthzTable::new();
        t.allow(id("a"), id("b"));
        assert_eq!(t.check(&id("b"), &id("a")).0, Decision::Deny, "reverse direction must not be implicitly allowed");
        assert_eq!(t.check(&id("a"), &id("c")).0, Decision::Deny, "a different destination must not be implicitly allowed");
    }

    #[test]
    fn revoke_returns_pair_to_denied() {
        let mut t = AuthzTable::new();
        t.allow(id("a"), id("b"));
        assert_eq!(t.check(&id("a"), &id("b")).0, Decision::Allow);
        t.revoke(&id("a"), &id("b"));
        assert_eq!(t.check(&id("a"), &id("b")).0, Decision::Deny);
    }

    #[test]
    fn revoking_a_never_allowed_pair_is_not_an_error() {
        let mut t = AuthzTable::new();
        t.revoke(&id("a"), &id("b")); // must not panic
        assert_eq!(t.check(&id("a"), &id("b")).0, Decision::Deny);
    }
}
