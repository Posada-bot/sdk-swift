//! P4 Variant A — the coercer's view of the PUBLIC bulletin board.
//!
//! Given only the public transcript (deterministic nullifiers per §4.4/§8), the
//! coercer tries to (a) detect that a given credential re-voted and (b) link two
//! ballots to a single voter. If it succeeds, the deterministic-nullifier
//! design provides NO unlinkable re-voting ⇒ coercion resistance fails.

use std::collections::HashMap;
use voltaire_core::tally::Transcript;

#[derive(Clone, Debug)]
pub struct CoercerReport {
    pub board_ballots: usize,
    pub distinct_nullifiers: usize,
    pub revote_nullifiers: usize,
    pub linked_ballots: usize,
    /// (index_a, index_b, nullifier_hex) — a concrete linked pair, if any.
    pub example_link: Option<(usize, usize, String)>,
    pub can_detect_revote: bool,
    pub can_link_two_ballots: bool,
}

/// Analyze the public board. Works on whatever ballots are present (under
/// LastWriteWins every re-vote is appended, so repeated nullifiers are visible).
pub fn analyze(t: &Transcript) -> CoercerReport {
    let nulls: Vec<&str> = t.ballots.iter().map(|b| b.nullifier.as_str()).collect();
    analyze_nullifiers(&nulls)
}

/// Coercion-linkage analysis over the public nullifiers ALONE. This is the
/// substance of P4 Variant A: the claim depends only on nullifiers being public
/// and deterministic per (voter, election), which is real Poseidon output.
/// Used at large N (e.g. 1_000_000) where re-running full ballot crypto is
/// unnecessary to demonstrate linkability.
pub fn analyze_nullifiers<S: AsRef<str>>(nulls: &[S]) -> CoercerReport {
    let mut by_null: HashMap<&str, Vec<usize>> = HashMap::new();
    for (i, n) in nulls.iter().enumerate() {
        by_null.entry(n.as_ref()).or_default().push(i);
    }
    let mut revote_nullifiers = 0usize;
    let mut linked_ballots = 0usize;
    let mut example: Option<(usize, usize, String)> = None;
    for (null, idxs) in &by_null {
        if idxs.len() > 1 {
            revote_nullifiers += 1;
            linked_ballots += idxs.len();
            if example.is_none() {
                example = Some((idxs[0], idxs[1], (*null).to_string()));
            }
        }
    }
    CoercerReport {
        board_ballots: nulls.len(),
        distinct_nullifiers: by_null.len(),
        revote_nullifiers,
        linked_ballots,
        example_link: example,
        can_detect_revote: revote_nullifiers > 0,
        can_link_two_ballots: revote_nullifiers > 0,
    }
}
