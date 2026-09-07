// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

//! Workload traffic capture (E2.5, R12 AC1): `nz-agent` captures workload
//! traffic via eBPF redirect, with an **iptables/TPROXY fallback** — the
//! fallback this build ships (per the grounding pass: "R12 ships correctly on
//! the iptables/TPROXY fallback alone", which R13's eBPF datapath later
//! accelerates without changing this seam).
//!
//! # What this module builds vs. what it depends on
//!
//! This module builds the **rule construction** for the iptables/TPROXY
//! fallback: given a [`CaptureConfig`], [`IptablesCapture::rules_for`]
//! deterministically produces the exact `iptables`/`ip6tables` argument
//! vectors that would install the redirect (testable without root or a real
//! netfilter stack — see the tests below, which assert on the produced
//! command text). It does NOT execute those rules against a live kernel: that
//! needs `CAP_NET_ADMIN` (iptables) or `CAP_BPF`+root (a future eBPF path),
//! which this build environment does not grant. [`RuleExecutor`] is the seam
//! a live deployment supplies (a real `std::process::Command` runner, or an
//! eBPF loader for R13); this build ships [`RecordingExecutor`], a
//! deterministic in-memory test double that records what it would have run.
//!
//! # Fail-closed capture posture
//!
//! [`CaptureSource::install`] returns the exact rule set that WILL be
//! installed before any execution happens (never issues a rule the caller
//! cannot audit first), and [`RuleExecutor::apply`] propagates the first rule
//! failure as an error rather than continuing to apply a partial rule set —
//! a partially-installed redirect ("some workloads captured, some not") is
//! exactly the kind of silent gap this crate's fail-closed discipline
//! forbids.

use std::fmt;

/// The node-local redirect target `nz-agent` listens on for captured
/// workload traffic — the port/address the TPROXY (or, on a plain-iptables
/// fallback, REDIRECT) rule sends intercepted packets to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RedirectTarget {
    pub port: u16,
    /// TPROXY needs an explicit fwmark to distinguish already-redirected
    /// traffic from fresh workload traffic (avoids a redirect loop); 0 means
    /// "use the mark this module's default constant defines".
    pub mark: u32,
}

/// One workload's outbound-capture scope: which local process/cgroup or
/// address range gets redirected. Mirrors the granularity a real per-node
/// agent needs (cgroup-scoped in the eBPF path per EBPF-DATAPATH-DESIGN.md;
/// address/interface-scoped on the iptables fallback, since raw iptables has
/// no first-class cgroup match without the `cgroup` xt module).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CaptureScope {
    /// Redirect all outbound TCP from this node's pod/veth CIDR (the whole-
    /// node fallback: every workload on the node is captured identically;
    /// per-workload session isolation still holds at the N-PAMP layer even
    /// though the CAPTURE granularity here is node-wide).
    NodeCidr { cidr: String },
    /// Redirect outbound TCP tagged with a specific cgroup's net_cls
    /// classid (finer-grained; needs the `cgroup` xt module or the eBPF
    /// path).
    CgroupClassid { classid: u32 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptureConfig {
    pub scope: CaptureScope,
    pub target: RedirectTarget,
}

/// The default TPROXY mark, chosen out of the ephemeral/private mark range to
/// avoid colliding with an operator's own netfilter marks (documented, not
/// magic: rule-construction tests assert on this exact value).
pub const DEFAULT_TPROXY_MARK: u32 = 0x4e5a; // "NZ" in ASCII hex, nz-agent's own mark

/// One shell-invokable rule: the binary name and its argument vector,
/// constructed but never itself executed by this type (see [`RuleExecutor`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    pub program: String,
    pub args: Vec<String>,
}

impl fmt::Display for Rule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.program, self.args.join(" "))
    }
}

/// Builds the iptables/TPROXY fallback rule set for a [`CaptureConfig`].
/// Pure rule CONSTRUCTION — no side effects, no `std::process::Command`
/// invocation here (see [`RuleExecutor`]).
pub struct IptablesCapture;

impl IptablesCapture {
    /// Returns the ordered `iptables` invocations that install `cfg`'s
    /// redirect: a `mangle`-table `TPROXY` rule marking and redirecting
    /// matched traffic to `cfg.target`, preceded by the mark-exemption rule
    /// that prevents already-marked (already-captured) traffic from being
    /// redirected again (the redirect-loop guard named in the module docs).
    pub fn rules_for(cfg: &CaptureConfig) -> Vec<Rule> {
        let mark = if cfg.target.mark == 0 { DEFAULT_TPROXY_MARK } else { cfg.target.mark };
        let mark_hex = format!("0x{mark:x}");
        let scope_match: Vec<String> = match &cfg.scope {
            CaptureScope::NodeCidr { cidr } => vec!["-s".into(), cidr.clone()],
            CaptureScope::CgroupClassid { classid } => vec!["-m".into(), "cgroup".into(), "--cgroup".into(), classid.to_string()],
        };

        let mut divert = vec!["-t".into(), "mangle".into(), "-A".into(), "NZAGENT_DIVERT".into()];
        divert.extend(["-j".into(), "MARK".into(), "--set-mark".into(), mark_hex.clone()]);
        let divert_rule = Rule { program: "iptables".into(), args: divert };

        let mut divert_accept = vec!["-t".into(), "mangle".into(), "-A".into(), "NZAGENT_DIVERT".into()];
        divert_accept.extend(["-j".into(), "ACCEPT".into()]);
        let divert_accept_rule = Rule { program: "iptables".into(), args: divert_accept };

        let mut skip_already_marked = vec!["-t".into(), "mangle".into(), "-A".into(), "PREROUTING".into()];
        skip_already_marked.extend(["-m".into(), "mark".into(), "--mark".into(), mark_hex.clone()]);
        skip_already_marked.extend(["-j".into(), "NZAGENT_DIVERT".into()]);
        let skip_rule = Rule { program: "iptables".into(), args: skip_already_marked };

        let mut tproxy = vec!["-t".into(), "mangle".into(), "-A".into(), "PREROUTING".into()];
        tproxy.extend(scope_match);
        tproxy.extend([
            "-p".into(),
            "tcp".into(),
            "-j".into(),
            "TPROXY".into(),
            "--on-port".into(),
            cfg.target.port.to_string(),
            "--tproxy-mark".into(),
            mark_hex,
        ]);
        let tproxy_rule = Rule { program: "iptables".into(), args: tproxy };

        vec![divert_rule, divert_accept_rule, skip_rule, tproxy_rule]
    }
}

/// A named capture-rule failure: fail-closed, the caller MUST NOT treat a
/// partial rule application as "captured".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleApplyError {
    pub failed_rule: Rule,
    pub reason: String,
}

impl fmt::Display for RuleApplyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "nz-agent/capture: rule failed ({}): {}", self.failed_rule, self.reason)
    }
}

impl std::error::Error for RuleApplyError {}

/// The seam a live deployment supplies to actually run the rules
/// [`IptablesCapture::rules_for`] constructs (a real `std::process::Command`
/// runner requiring `CAP_NET_ADMIN`/root — not implemented by this crate; see
/// the module docs' tracked-gap note).
pub trait RuleExecutor {
    fn run(&mut self, rule: &Rule) -> Result<(), String>;
}

/// Applies `rules` in order via `executor`, stopping at (and reporting) the
/// first failure — never silently continuing past a rule that failed to
/// apply (fail-closed: a partially-installed capture is reported as a
/// failure, not swallowed).
pub fn apply<E: RuleExecutor>(executor: &mut E, rules: &[Rule]) -> Result<(), RuleApplyError> {
    for rule in rules {
        if let Err(reason) = executor.run(rule) {
            return Err(RuleApplyError { failed_rule: rule.clone(), reason });
        }
    }
    Ok(())
}

/// A deterministic, side-effect-free [`RuleExecutor`] test double: records
/// every rule it "ran" (in order) instead of invoking a real `iptables`
/// binary. `fail_after` optionally makes the Nth call fail, for testing the
/// fail-closed partial-application path.
pub struct RecordingExecutor {
    pub recorded: Vec<Rule>,
    fail_after: Option<usize>,
}

impl RecordingExecutor {
    pub fn new() -> RecordingExecutor {
        RecordingExecutor { recorded: Vec::new(), fail_after: None }
    }

    pub fn failing_at(n: usize) -> RecordingExecutor {
        RecordingExecutor { recorded: Vec::new(), fail_after: Some(n) }
    }
}

impl Default for RecordingExecutor {
    fn default() -> Self {
        Self::new()
    }
}

impl RuleExecutor for RecordingExecutor {
    fn run(&mut self, rule: &Rule) -> Result<(), String> {
        let idx = self.recorded.len();
        self.recorded.push(rule.clone());
        if self.fail_after == Some(idx) {
            return Err(format!("simulated failure at rule index {idx}"));
        }
        Ok(())
    }
}

/// Composes rule construction ([`IptablesCapture::rules_for`]) with
/// application ([`apply`]) behind one call, mirroring what a live
/// `nz-agent` startup path does. Generic over the executor so the eBPF path
/// (R13) can supply a different `RuleExecutor` without this crate's capture
/// module changing.
pub trait CaptureSource {
    fn install<E: RuleExecutor>(&self, executor: &mut E) -> Result<Vec<Rule>, RuleApplyError>;
}

impl CaptureSource for CaptureConfig {
    fn install<E: RuleExecutor>(&self, executor: &mut E) -> Result<Vec<Rule>, RuleApplyError> {
        let rules = IptablesCapture::rules_for(self);
        apply(executor, &rules)?;
        Ok(rules)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> CaptureConfig {
        CaptureConfig {
            scope: CaptureScope::NodeCidr { cidr: "10.244.1.0/24".into() },
            target: RedirectTarget { port: 15006, mark: 0 },
        }
    }

    #[test]
    fn rules_for_uses_default_mark_when_unset() {
        let rules = IptablesCapture::rules_for(&cfg());
        let joined = rules.iter().map(|r| r.to_string()).collect::<Vec<_>>().join("\n");
        assert!(joined.contains(&format!("0x{DEFAULT_TPROXY_MARK:x}")), "expected default mark in: {joined}");
    }

    #[test]
    fn rules_for_targets_the_configured_port() {
        let rules = IptablesCapture::rules_for(&cfg());
        let joined = rules.iter().map(|r| r.to_string()).collect::<Vec<_>>().join("\n");
        assert!(joined.contains("--on-port 15006"), "expected port 15006 in: {joined}");
    }

    #[test]
    fn cgroup_scope_uses_cgroup_match_not_source_cidr() {
        let cfg = CaptureConfig { scope: CaptureScope::CgroupClassid { classid: 42 }, target: RedirectTarget { port: 15006, mark: 0 } };
        let rules = IptablesCapture::rules_for(&cfg);
        let tproxy = rules.last().expect("tproxy rule present");
        assert!(tproxy.args.contains(&"cgroup".to_string()));
        assert!(tproxy.args.contains(&"42".to_string()));
        assert!(!tproxy.args.contains(&"-s".to_string()));
    }

    #[test]
    fn apply_runs_every_rule_in_order() {
        let rules = IptablesCapture::rules_for(&cfg());
        let mut exec = RecordingExecutor::new();
        apply(&mut exec, &rules).expect("apply should succeed");
        assert_eq!(exec.recorded, rules);
    }

    /// Fail-closed: a rule failure at index 2 must stop application (never
    /// silently install rules 3.. after a failure) and report which rule
    /// failed. Mutated away by M-capture-2 in RED-EVIDENCE.md.
    #[test]
    fn apply_stops_at_first_failure_fail_closed() {
        let rules = IptablesCapture::rules_for(&cfg());
        let mut exec = RecordingExecutor::failing_at(2);
        let err = apply(&mut exec, &rules).expect_err("must fail closed");
        assert_eq!(err.failed_rule, rules[2]);
        assert_eq!(exec.recorded.len(), 3, "must not attempt rules after the failure");
    }

    #[test]
    fn capture_source_install_composes_construct_and_apply() {
        let mut exec = RecordingExecutor::new();
        let installed = cfg().install(&mut exec).expect("install should succeed");
        assert_eq!(installed.len(), 4);
        assert_eq!(exec.recorded, installed);
    }
}
