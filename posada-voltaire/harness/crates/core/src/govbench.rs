//! Parallel governance benchmark (SPEC §14): stake-weighted CIP-1694 tally vs a
//! secret 1p1v shadow ballot on the same yes/no/abstain question.
//!
//! The CIP-1694 *tallying semantics* implemented here are real (confirmed from
//! gov.tools docs): Abstain is excluded from the active voting stake, and — for
//! ordinary actions — registered stake that did not vote is treated as No. The
//! stake *numbers* are a JSON config input, because live fetch of gov.tools /
//! adastat returned HTTP 403 inside the harness (stated plainly in output).

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GovConfig {
    /// e.g. "gov_action1..." — the concluded action being shadowed.
    pub action_id: String,
    pub action_type: String,
    /// Honest provenance of the numbers below.
    pub provenance: String,
    /// DRep stake (in lovelace or ADA — unit is cosmetic here) voting Yes.
    pub drep_yes: u64,
    pub drep_no: u64,
    pub drep_abstain: u64,
    /// Registered DRep stake that did NOT vote (auto-No for ordinary actions).
    pub not_voted_registered: u64,
    /// Ratification threshold as a fraction of active (Yes+No) stake, e.g. 0.67.
    pub threshold: f64,
    /// If true, non-voting registered stake counts as No (ordinary actions).
    pub non_voters_count_as_no: bool,
    /// Shadow-ballot parameters.
    pub shadow_voters: u64,
    /// Proportions [yes, no, abstain] summing to ~1.0 for the shadow ballot.
    pub shadow_distribution: [f64; 3],
}

#[derive(Clone, Debug)]
pub struct StakeResult {
    pub yes: u64,
    pub no_effective: u64,
    pub abstain: u64,
    pub active_stake: u64,
    pub yes_ratio: f64,
    pub threshold: f64,
    pub ratified: bool,
}

pub fn stake_weighted(cfg: &GovConfig) -> StakeResult {
    let no_effective = cfg.drep_no + if cfg.non_voters_count_as_no { cfg.not_voted_registered } else { 0 };
    let active = cfg.drep_yes + no_effective; // Abstain excluded from active stake
    let yes_ratio = if active > 0 { cfg.drep_yes as f64 / active as f64 } else { 0.0 };
    StakeResult {
        yes: cfg.drep_yes,
        no_effective,
        abstain: cfg.drep_abstain,
        active_stake: active,
        yes_ratio,
        threshold: cfg.threshold,
        ratified: yes_ratio >= cfg.threshold,
    }
}

#[derive(Clone, Debug)]
pub struct OnePersonResult {
    pub yes: u64,
    pub no: u64,
    pub abstain: u64,
    pub turnout: u64,
    pub yes_ratio_excl_abstain: f64,
    pub passes_majority: bool,
}

/// Compute the 1p1v outcome from decrypted counts (simple majority of Yes vs No,
/// abstentions excluded — the analogue of the CIP-1694 active-stake rule but
/// weighted by *people*, not lovelace).
pub fn one_person(yes: u64, no: u64, abstain: u64) -> OnePersonResult {
    let active = yes + no;
    let ratio = if active > 0 { yes as f64 / active as f64 } else { 0.0 };
    OnePersonResult {
        yes,
        no,
        abstain,
        turnout: yes + no + abstain,
        yes_ratio_excl_abstain: ratio,
        passes_majority: ratio > 0.5,
    }
}

/// Deterministic per-voter choice for the shadow ballot from a distribution,
/// so runs are reproducible without an RNG dependency in the distribution.
pub fn shadow_choice(i: u64, dist: &[f64; 3]) -> usize {
    // Interleave deterministically by scaling index into [0,1) via a hash-free
    // low-discrepancy sequence (van der Corput base 2) to avoid clustering.
    let mut x = 0.0f64;
    let mut denom = 0.5f64;
    let mut n = i + 1;
    while n > 0 {
        if n & 1 == 1 {
            x += denom;
        }
        denom *= 0.5;
        n >>= 1;
    }
    let c0 = dist[0];
    let c1 = dist[0] + dist[1];
    if x < c0 {
        0
    } else if x < c1 {
        1
    } else {
        2
    }
}
