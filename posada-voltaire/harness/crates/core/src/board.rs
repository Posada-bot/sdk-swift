//! Append-only bulletin board.
//!
//! Two policies are implemented on purpose, because the SPEC is internally
//! contradictory about re-voting (§4.4 vs §8):
//!   * `RejectDuplicate`  — §4.4: a repeated public nullifier is rejected.
//!   * `LastWriteWins`    — §8:  the last ballot per nullifier is the one
//!                               counted (silent re-voting).
//!
//! In BOTH policies the deterministic public nullifier is written to the board,
//! which is exactly what the P4 coercer test attacks.

use crate::elgamal::{Ciphertext, PublicKey};
use crate::validity::{verify_ballot, BallotProof};
use std::collections::HashMap;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Policy {
    RejectDuplicate,
    LastWriteWins,
}

impl Policy {
    pub fn as_str(&self) -> &'static str {
        match self {
            Policy::RejectDuplicate => "reject_duplicate",
            Policy::LastWriteWins => "last_write_wins",
        }
    }
}

#[derive(Clone, Debug)]
pub struct Ballot {
    pub nullifier: [u8; 32],
    pub cts: Vec<Ciphertext>,
    pub proof: BallotProof,
    /// Optional Semaphore-style membership proof bytes (hex), attached by the
    /// harness when the ZK layer is exercised.
    pub membership: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AppendResult {
    Accepted,
    RejectedDuplicate,
    RejectedInvalidProof,
    Replaced,
}

/// The append-only board. `records` is the full ordered transcript (nothing is
/// deleted, even under LastWriteWins — replacement is a new appended record and
/// the index simply points at the latest).
pub struct Board {
    pub policy: Policy,
    pub records: Vec<Ballot>,
    latest_index: HashMap<[u8; 32], usize>,
    pub rejected_duplicates: u64,
}

impl Board {
    pub fn new(policy: Policy) -> Self {
        Board {
            policy,
            records: Vec::new(),
            latest_index: HashMap::new(),
            rejected_duplicates: 0,
        }
    }

    /// Append a ballot. Its validity proof is checked first; invalid ballots
    /// never enter the board.
    pub fn append(&mut self, pk: &PublicKey, ballot: Ballot) -> AppendResult {
        if !verify_ballot(pk, &ballot.cts, &ballot.proof) {
            return AppendResult::RejectedInvalidProof;
        }
        let seen = self.latest_index.get(&ballot.nullifier).copied();
        match (self.policy, seen) {
            (Policy::RejectDuplicate, Some(_)) => {
                self.rejected_duplicates += 1;
                AppendResult::RejectedDuplicate
            }
            (Policy::RejectDuplicate, None) => {
                self.latest_index.insert(ballot.nullifier, self.records.len());
                self.records.push(ballot);
                AppendResult::Accepted
            }
            (Policy::LastWriteWins, _) => {
                // Everything is appended (append-only), index tracks the latest.
                self.latest_index.insert(ballot.nullifier, self.records.len());
                let existed = seen.is_some();
                self.records.push(ballot);
                if existed {
                    AppendResult::Replaced
                } else {
                    AppendResult::Accepted
                }
            }
        }
    }

    /// The set of ballots that count, honoring the policy.
    pub fn counted(&self) -> Vec<&Ballot> {
        match self.policy {
            Policy::RejectDuplicate => {
                // First occurrence per nullifier (duplicates were never added).
                self.records.iter().collect()
            }
            Policy::LastWriteWins => {
                // Latest record per nullifier.
                let mut out: Vec<&Ballot> = Vec::new();
                for (&_null, &idx) in &self.latest_index {
                    out.push(&self.records[idx]);
                }
                out
            }
        }
    }

    /// Distinct voters that appear on the board (by nullifier).
    pub fn distinct_voters(&self) -> usize {
        self.latest_index.len()
    }
}
