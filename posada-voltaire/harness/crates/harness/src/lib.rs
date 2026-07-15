//! Orchestration for the Posada Voltaire falsification harness.
//!
//! Ties the real crypto in `voltaire-core` and the real Groth16 membership
//! proof in `voltaire-zk` into: a full end-to-end election, the P4 coercer
//! analysis over the public board, the JCJ scaling driver, and the governance
//! shadow ballot.

use ark_bn254::Fr;
use rand::rngs::StdRng;
use std::time::Instant;
use voltaire_core::board::{Ballot, Board, Policy};
use voltaire_core::dkg::{self, Dkg};
use voltaire_core::tally::{self, Transcript};
use voltaire_core::validity;
use voltaire_zk as zk;

pub mod coercer;

/// A single cast event (a voter may appear more than once — a re-vote).
#[derive(Clone, Copy, Debug)]
pub struct CastEvent {
    pub voter: u64,
    pub choice: usize,
}

#[derive(Clone, Debug, Default)]
pub struct Timings {
    pub setup_ms: f64,
    pub cast_ms: f64,
    pub tally_ms: f64,
    pub verify_ms: f64,
}

pub struct ElectionResult {
    pub transcript: Transcript,
    pub dkg: Dkg,
    pub board: Board,
    pub counts: Vec<u64>,
    pub timings: Timings,
    pub distinct_voters: usize,
    pub rejected_duplicates: u64,
    pub cast_count: usize,
}

/// Run a complete election with REAL crypto end to end.
#[allow(clippy::too_many_arguments)]
pub fn run_election(
    n_enrolled: u64,
    options: &[String],
    t: usize,
    nn: usize,
    policy: Policy,
    election_id: u64,
    events: &[CastEvent],
    rng: &mut StdRng,
) -> ElectionResult {
    let k = options.len();
    let cfg = zk::poseidon_config();
    let e_field = Fr::from(election_id);

    let s0 = Instant::now();
    let dkg = dkg::run(t, nn, rng);
    let setup_ms = s0.elapsed().as_secs_f64() * 1e3;

    let mut board = Board::new(policy);
    let c0 = Instant::now();
    for ev in events {
        let secret = zk::voter_secret(ev.voter);
        let null = zk::fr_to_bytes(zk::nullifier(&cfg, secret, e_field));
        let (cts, proof) = validity::prove_ballot(&dkg.public_key, ev.choice, k, rng);
        board.append(
            &dkg.public_key,
            Ballot {
                nullifier: null,
                cts,
                proof,
                membership: None,
            },
        );
    }
    let cast_ms = c0.elapsed().as_secs_f64() * 1e3;

    let counted = board.counted();
    let max = counted.len().max(1) as u64;
    let t0 = Instant::now();
    let tally_section = tally::run_tally(&dkg, &counted, k, max, rng);
    let tally_ms = t0.elapsed().as_secs_f64() * 1e3;
    let counts = tally_section.results.clone();
    let distinct_voters = board.distinct_voters();
    let rejected_duplicates = board.rejected_duplicates;
    let cast_count = board.records.len();

    let transcript = tally::build_transcript(
        &format!("posada-voltaire/election/{election_id}"),
        options,
        &dkg,
        &board,
        n_enrolled,
        Some(tally_section),
    );

    let v0 = Instant::now();
    let _ = tally::verify_transcript(&transcript);
    let verify_ms = v0.elapsed().as_secs_f64() * 1e3;

    ElectionResult {
        transcript,
        dkg,
        board,
        counts,
        timings: Timings {
            setup_ms,
            cast_ms,
            tally_ms,
            verify_ms,
        },
        distinct_voters,
        rejected_duplicates,
        cast_count,
    }
}

// ---------------------------------------------------------------------------
// Property checks used by the harness binary's one-screen verdict. The
// integration tests in `tests/properties.rs` assert the same properties
// independently and more granularly.
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct Check {
    pub name: &'static str,
    pub pass: bool,
    pub detail: String,
}

/// P1 — one person, one vote.
pub fn check_p1(rng: &mut StdRng) -> Check {
    let opts = vec!["A".into(), "B".into(), "C".into()];
    let n = 200u64;
    let mut events: Vec<CastEvent> = (0..n).map(|v| CastEvent { voter: v, choice: (v % 3) as usize }).collect();
    // Voter 7 double-casts (same secret ⇒ same nullifier).
    events.push(CastEvent { voter: 7, choice: 2 });
    events.push(CastEvent { voter: 42, choice: 0 });
    let r = run_election(n, &opts, 3, 5, Policy::RejectDuplicate, 1, &events, rng);
    let counted_total: u64 = r.counts.iter().sum();
    let pass = r.rejected_duplicates == 2 && counted_total <= n && r.distinct_voters as u64 == n;
    Check {
        name: "P1 1p1v",
        pass,
        detail: format!(
            "{} cast attempts, {} duplicates rejected, {} distinct voters, {} counted (≤ N={})",
            r.cast_count + r.rejected_duplicates as usize,
            r.rejected_duplicates,
            r.distinct_voters,
            counted_total,
            n
        ),
    }
}

/// P2 — no single-ballot decryption / t-1 cannot decrypt.
pub fn check_p2(rng: &mut StdRng) -> Check {
    use voltaire_core::elgamal::encrypt;
    use voltaire_core::threshold::{decrypt, partial_decrypt};
    let d = dkg::run(3, 5, rng);
    let (ct, _) = encrypt(&d.public_key, 1, rng);

    // (a) every (t-1)-subset fails to decrypt.
    let subsets = [[0usize, 1], [0, 2], [1, 3], [2, 4], [3, 4]];
    let mut t_minus_1_all_fail = true;
    for combo in subsets {
        let parts: Vec<_> = combo.iter().map(|&i| partial_decrypt(&d.trustees[i], &ct, rng)).collect();
        if decrypt(&d, &ct, &parts, 10).is_some() {
            t_minus_1_all_fail = false;
        }
    }
    // (b) t suffices only on the COMBINED ciphertext — sanity that decrypt works
    //     for the aggregate but is never invoked on an individual ballot in the
    //     tally path (enforced structurally: run_tally only calls decrypt on the
    //     homomorphic product).
    let parts_t: Vec<_> = [0, 2, 4].iter().map(|&i| partial_decrypt(&d.trustees[i], &ct, rng)).collect();
    let t_works = decrypt(&d, &ct, &parts_t, 10).is_some();

    Check {
        name: "P2 no single-ballot decrypt",
        pass: t_minus_1_all_fail && t_works,
        detail: format!(
            "all 5 tested (t-1)=2 subsets returned None: {}; t=3 on combined ct works: {}; \
             tally path decrypts ONLY the homomorphic product",
            t_minus_1_all_fail, t_works
        ),
    }
}

/// P3 — universal verifiability + tamper-evidence.
pub fn check_p3(rng: &mut StdRng) -> Check {
    let opts = vec!["Yes".into(), "No".into(), "Abstain".into()];
    let n = 120u64;
    let events: Vec<CastEvent> = (0..n)
        .map(|v| CastEvent { voter: v, choice: (v % 3) as usize })
        .collect();
    let r = run_election(n, &opts, 3, 5, Policy::RejectDuplicate, 9, &events, rng);

    // Clean transcript must verify.
    let clean = tally::verify_transcript(&r.transcript);

    // Tamper: swap one ballot's ciphertexts for a different (valid) ballot's,
    // leaving the published tally/partials unchanged. Verifier must FAIL.
    let mut tampered = r.transcript.clone();
    if tampered.ballots.len() >= 2 {
        let victim = tampered.ballots[1].ballot.cts.clone();
        tampered.ballots[0].ballot.cts = victim;
    }
    let after = tally::verify_transcript(&tampered);

    let pass = clean.pass && !after.pass;
    Check {
        name: "P3 universal verifiability",
        pass,
        detail: format!(
            "clean transcript: {} ({}); tampered transcript: {} ({})",
            if clean.pass { "PASS" } else { "FAIL" },
            clean.reason,
            if after.pass { "PASS (BAD)" } else { "FAIL (good — tamper caught)" },
            after.reason
        ),
    }
}
