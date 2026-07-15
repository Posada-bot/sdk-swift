//! Independent integration tests for the mechanical properties P1–P3.
//! These use the full real pipeline (dalek ElGamal/DKG + Helios validity proofs
//! + homomorphic threshold tally). `cargo test` must be green for these.
//!
//! P4 is deliberately NOT here: it is a falsification result (the design breaks),
//! reported by the `harness` binary, not a property that should pass.

use rand::rngs::StdRng;
use rand::SeedableRng;
use voltaire_core::board::Policy;
use voltaire_core::elgamal::encrypt;
use voltaire_core::group::scalar_to_hex;
use voltaire_core::tally::verify_transcript;
use voltaire_core::threshold::{decrypt, partial_decrypt};
use voltaire_core::{dkg, group};
use voltaire_harness::{run_election, CastEvent};

fn opts() -> Vec<String> {
    vec!["Yes".into(), "No".into(), "Abstain".into()]
}

/// P1 — one person, one vote: a double-cast with the same secret (⇒ same
/// nullifier) is rejected; N credentials produce at most N counted ballots.
#[test]
fn p1_one_person_one_vote() {
    let mut rng = StdRng::seed_from_u64(11);
    let n = 300u64;
    let mut events: Vec<CastEvent> = (0..n).map(|v| CastEvent { voter: v, choice: (v % 3) as usize }).collect();
    // Three separate double-cast attempts.
    events.push(CastEvent { voter: 1, choice: 0 });
    events.push(CastEvent { voter: 2, choice: 1 });
    events.push(CastEvent { voter: 3, choice: 2 });

    let r = run_election(n, &opts(), 3, 5, Policy::RejectDuplicate, 1, &events, &mut rng);
    let counted: u64 = r.counts.iter().sum();

    assert_eq!(r.rejected_duplicates, 3, "all 3 double-casts must be rejected");
    assert_eq!(r.distinct_voters as u64, n, "exactly N distinct voters");
    assert!(counted <= n, "counted {counted} must be <= N {n}");
    assert_eq!(counted, n, "every distinct voter counted exactly once");
}

/// P2 — no single-ballot decryption. Every (t-1)-subset of trustees fails to
/// decrypt; only >= t partials on a ciphertext work. In the tally path the only
/// ciphertext ever decrypted is the homomorphic product (see run_tally).
#[test]
fn p2_no_single_ballot_decryption() {
    let mut rng = StdRng::seed_from_u64(22);
    let d = dkg::run(3, 5, &mut rng);
    let (ct, _) = encrypt(&d.public_key, 1, &mut rng);

    // All C(5,2) = 10 subsets of size t-1 = 2 must fail.
    let mut count = 0;
    for i in 0..5 {
        for j in (i + 1)..5 {
            let parts = vec![
                partial_decrypt(&d.trustees[i], &ct, &mut rng),
                partial_decrypt(&d.trustees[j], &ct, &mut rng),
            ];
            assert!(decrypt(&d, &ct, &parts, 100).is_none(), "t-1 subset ({i},{j}) must NOT decrypt");
            count += 1;
        }
    }
    assert_eq!(count, 10);

    // >= t works, but note: an *individual ballot* is never sent to decrypt in
    // the real tally; we only exercise it here to prove the threshold boundary.
    let parts_t = vec![
        partial_decrypt(&d.trustees[0], &ct, &mut rng),
        partial_decrypt(&d.trustees[1], &ct, &mut rng),
        partial_decrypt(&d.trustees[4], &ct, &mut rng),
    ];
    assert_eq!(decrypt(&d, &ct, &parts_t, 100), Some(1));
}

/// P3 — universal verifiability: the independent verifier reproduces the tally
/// from the transcript alone, and ANY tampering flips it to FAIL.
#[test]
fn p3_universal_verifiability_and_tamper_evidence() {
    let mut rng = StdRng::seed_from_u64(33);
    let n = 150u64;
    let events: Vec<CastEvent> = (0..n).map(|v| CastEvent { voter: v, choice: (v % 3) as usize }).collect();
    let r = run_election(n, &opts(), 3, 5, Policy::RejectDuplicate, 5, &events, &mut rng);

    // Clean transcript verifies and matches the published counts.
    let clean = verify_transcript(&r.transcript);
    assert!(clean.pass, "clean transcript must verify: {}", clean.reason);
    assert_eq!(clean.counts, r.counts);

    // Tamper 1: replace a ballot's ciphertexts with another valid ballot's.
    let mut t1 = r.transcript.clone();
    let victim = t1.ballots[7].ballot.cts.clone();
    t1.ballots[3].ballot.cts = victim;
    assert!(!verify_transcript(&t1).pass, "swapped-ballot tamper must be caught");

    // Tamper 2: forge the published result.
    let mut t2 = r.transcript.clone();
    if let Some(tl) = t2.tally.as_mut() {
        tl.results[0] += 1;
    }
    assert!(!verify_transcript(&t2).pass, "forged result must be caught");

    // Tamper 3: corrupt a trustee partial decryption.
    let mut t3 = r.transcript.clone();
    if let Some(tl) = t3.tally.as_mut() {
        let bad = scalar_to_hex(&(group::scalar_from_hex(&tl.partials[0][0].z).unwrap() + curve25519_dalek::scalar::Scalar::from(1u64)));
        tl.partials[0][0].z = bad;
    }
    assert!(!verify_transcript(&t3).pass, "corrupted partial-decryption proof must be caught");
}
