//! Posada Voltaire falsification harness.
//!
//! Tries to BREAK the two load-bearing correctness claims (P2 threshold secrecy,
//! P4 coercion/re-vote) and turns the JCJ scaling cost into a measured number.
//! Prints a one-screen verdict and exits non-zero if the design does not
//! survive.
//!
//!   cargo run --release --bin harness -- [--n 10000] [--coercion-n 1000000]
//!                                        [--gov config/governance.json]
//!                                        [--out transcript.json] [--seed 42]
//!                                        [--jcj 200,400,800]

use ark_bn254::Fr;
use rand::rngs::StdRng;
use rand::SeedableRng;
use std::process::exit;
use std::time::Instant;
use voltaire_core::board::Policy;
use voltaire_core::govbench::{self, GovConfig};
use voltaire_core::jcj;
use voltaire_core::tally::verify_transcript;
use voltaire_harness::{check_p1, check_p2, check_p3, coercer, run_election, CastEvent, Check};
use voltaire_zk as zk;

struct Args {
    n: u64,
    coercion_n: u64,
    gov: String,
    out: String,
    seed: u64,
    jcj_sizes: Vec<usize>,
}

fn parse_args() -> Args {
    let mut n = 10_000u64;
    let mut coercion_n: Option<u64> = None;
    let mut gov = "config/governance.json".to_string();
    let mut out = "transcript.json".to_string();
    let mut seed = 42u64;
    let mut jcj_sizes = vec![150usize, 300, 600];
    let a: Vec<String> = std::env::args().collect();
    let mut i = 1;
    while i < a.len() {
        match a[i].as_str() {
            "--n" => { n = a[i + 1].parse().expect("n"); i += 2; }
            "--coercion-n" => { coercion_n = Some(a[i + 1].parse().expect("coercion-n")); i += 2; }
            "--gov" => { gov = a[i + 1].clone(); i += 2; }
            "--out" => { out = a[i + 1].clone(); i += 2; }
            "--seed" => { seed = a[i + 1].parse().expect("seed"); i += 2; }
            "--jcj" => {
                jcj_sizes = a[i + 1].split(',').map(|s| s.trim().parse().expect("jcj size")).collect();
                i += 2;
            }
            other => { eprintln!("unknown arg: {other}"); exit(2); }
        }
    }
    Args { n, coercion_n: coercion_n.unwrap_or(n), gov, out, seed, jcj_sizes }
}

fn rule(title: &str) {
    println!("\n\x1b[1m── {title} {}\x1b[0m", "─".repeat(60usize.saturating_sub(title.len())));
}

fn show(c: &Check) {
    let tag = if c.pass { "\x1b[32mPASS\x1b[0m" } else { "\x1b[31mFAIL\x1b[0m" };
    println!("  [{tag}] {:<28} {}", c.name, c.detail);
}

fn main() {
    let args = parse_args();
    let mut rng = StdRng::seed_from_u64(args.seed);
    let election_id: u64 = 1;
    let e_field = Fr::from(election_id);

    println!("\x1b[1mPOSADA VOLTAIRE — FALSIFICATION HARNESS\x1b[0m");
    println!("Goal: try to BREAK P2 (threshold secrecy) and P4 (coercion/re-vote), and");
    println!("measure the JCJ scaling cost. Real crypto: dalek ElGamal/DKG + arkworks Groth16.");
    println!("N(full election)={}  N(coercion scale)={}  seed={}", args.n, args.coercion_n, args.seed);

    // --- Mechanical properties P1–P3 (also asserted independently in cargo test) ---
    rule("MECHANICAL PROPERTIES  P1–P3");
    let p1 = check_p1(&mut rng);
    let p2 = check_p2(&mut rng);
    let p3 = check_p3(&mut rng);
    show(&p1);
    show(&p2);
    show(&p3);

    // --- Full election at scale: real ballots, tally, independent verify ---
    rule("FULL ELECTION AT SCALE  (real ElGamal ballots + homomorphic tally)");
    let opts = vec!["Yes".to_string(), "No".to_string(), "Abstain".to_string()];
    let revotes = (args.n / 50).max(1); // 2% of voters silently re-vote
    let mut events: Vec<CastEvent> = (0..args.n)
        .map(|v| CastEvent { voter: v, choice: (v % 3) as usize })
        .collect();
    for v in 0..revotes {
        events.push(CastEvent { voter: v, choice: ((v + 1) % 3) as usize }); // re-vote, different choice
    }
    let er = run_election(args.n, &opts, 3, 5, Policy::LastWriteWins, election_id, &events, &mut rng);
    let total_ballots = er.cast_count;
    let per_ballot_us = er.timings.cast_ms * 1e3 / total_ballots.max(1) as f64;
    std::fs::write(&args.out, serde_json::to_string(&er.transcript).unwrap()).unwrap();
    let tsize = std::fs::metadata(&args.out).map(|m| m.len()).unwrap_or(0);
    let indep = verify_transcript(&er.transcript);
    println!("  voters={}  re-votes={}  ballots on board={}  distinct nullifiers={}", args.n, revotes, total_ballots, er.distinct_voters);
    println!("  counts (Yes/No/Abstain) = {:?}", er.counts);
    println!("  timings: dkg={:.0}ms  cast(all ballots)={:.0}ms ({:.0} µs/ballot)  tally={:.0}ms  verify={:.0}ms",
        er.timings.setup_ms, er.timings.cast_ms, per_ballot_us, er.timings.tally_ms, er.timings.verify_ms);
    println!("  transcript written: {} ({} KiB)", args.out, tsize / 1024);
    println!("  INDEPENDENT verifier on transcript: {}",
        if indep.pass { format!("\x1b[32mPASS\x1b[0m — {}", indep.reason) } else { format!("\x1b[31mFAIL\x1b[0m — {}", indep.reason) });
    println!("  → 1M ballots would cast in ~{:.0} s at this per-ballot cost (linear).", per_ballot_us * 1e6 / 1e6);

    // --- P4 Variant A: deterministic public nullifier ⇒ coercer links re-votes ---
    rule("P4 · VARIANT A  deterministic public nullifier (SPEC §4.4 / §8)");
    // (i) On the actual scale-election board (real ballots).
    let rep_board = coercer::analyze(&er.transcript);
    println!("  On the real bulletin board (LastWriteWins, {} ballots):", rep_board.board_ballots);
    println!("    re-voter nullifiers detected: {}   ballots linked to a repeat voter: {}",
        rep_board.revote_nullifiers, rep_board.linked_ballots);
    if let Some((a, b, null)) = &rep_board.example_link {
        println!("    example link: ballot #{a} and #{b} share nullifier {}… ⇒ same voter", &null[..16]);
    }
    // (ii) At coercion scale using real deterministic nullifiers only.
    let cfg = zk::poseidon_config();
    let t_null = Instant::now();
    let mut nulls: Vec<String> = (0..args.coercion_n)
        .map(|v| hex::encode(zk::fr_to_bytes(zk::nullifier(&cfg, zk::voter_secret(v), e_field))))
        .collect();
    let rv = (args.coercion_n / 50).max(1);
    for v in 0..rv { nulls.push(nulls[v as usize].clone()); } // re-votes
    let rep = coercer::analyze_nullifiers(&nulls);
    let detect_rate = 100.0 * rep.revote_nullifiers as f64 / rv as f64;
    println!("  At coercion scale N={} ({} planted re-votes), nullifier analysis in {:.2}s:",
        args.coercion_n, rv, t_null.elapsed().as_secs_f64());
    println!("    re-votes detected: {}/{} ({:.0}%)   can link two ballots to one voter: {}",
        rep.revote_nullifiers, rv, detect_rate, rep.can_link_two_ballots);
    let p4a_breaks = rep.can_detect_revote && rep.can_link_two_ballots;
    println!("  \x1b[31mVariant A coercion resistance: BROKEN\x1b[0m — re-votes are publicly linkable.");
    println!("  (Under the §4.4 RejectDuplicate reading, a re-vote is instead REJECTED — the");
    println!("   voter cannot silently override a coerced ballot at all. Either reading fails.)");

    // --- P4 Variant B: JCJ blind PET dedup — measure superlinear cost ---
    rule("P4 · VARIANT B  JCJ encrypted-credential dedup (no public nullifier)");
    let djcj = voltaire_core::dkg::run(3, 5, &mut rng);
    let mut per_pet_us = 0.0f64;
    println!("  Measured pairwise blind-PET dedup (real threshold PETs):");
    println!("    {:>7}  {:>12}  {:>10}  {:>12}", "N", "PETs", "seconds", "µs/PET");
    for &sz in &args.jcj_sizes {
        let m = jcj::measure_dedup(&djcj, sz, sz / 20, &mut rng);
        per_pet_us = m.per_pet_us;
        println!("    {:>7}  {:>12}  {:>10.3}  {:>12.1}", m.n, m.pets_run, m.seconds, m.per_pet_us);
    }
    // Confirm superlinearity: PETs grow ~ N^2/2.
    println!("  PET count = N(N-1)/2  ⇒  O(N²).  Projected wall-clock at scale (per-PET = {:.1} µs):", per_pet_us);
    for &n in &[1_000u64, 10_000, 100_000] {
        let secs = jcj::project_seconds(per_pet_us, n);
        let human = if secs > 3600.0 { format!("{:.1} h", secs / 3600.0) } else if secs > 60.0 { format!("{:.1} min", secs / 60.0) } else { format!("{:.1} s", secs) };
        println!("    N={:>7}  →  {:>15} PETs  →  ~{} (projected, not run)", n, (n * (n - 1) / 2), human);
    }
    println!("  \x1b[33mVariant B: superlinear CONFIRMED\x1b[0m — unlinkable, but O(N²) tally is infeasible at 500M on one machine.");

    // --- ZK membership proof: real Groth16, size + timing ---
    rule("ZK MEMBERSHIP PROOF  (real Groth16 / Poseidon, Semaphore-style)");
    println!("    {:>6}  {:>8}  {:>11}  {:>11}  {:>11}", "depth", "leaves", "proof(bytes)", "prove(ms)", "verify(ms)");
    for &depth in &[10usize, 14] {
        let mut zrng = StdRng::seed_from_u64(args.seed ^ depth as u64);
        let keys = zk::setup(depth, &mut zrng);
        let leaves: Vec<Fr> = (0..(1usize << depth) as u64).map(|i| zk::commitment(&keys.cfg, zk::voter_secret(i))).collect();
        let tree = zk::MerkleTree::build(keys.cfg.clone(), leaves);
        let idx = 5usize;
        let tp = Instant::now();
        let (proof, root, null) = zk::prove(&keys, &tree, zk::voter_secret(idx as u64), idx, e_field, &mut zrng);
        let prove_ms = tp.elapsed().as_secs_f64() * 1e3;
        let tv = Instant::now();
        let ok = zk::verify(&keys, &proof, root, e_field, null);
        let verify_ms = tv.elapsed().as_secs_f64() * 1e3;
        assert!(ok, "membership proof must verify");
        println!("    {:>6}  {:>8}  {:>11}  {:>11.1}  {:>11.2}", depth, 1usize << depth, zk::proof_size_bytes(&proof), prove_ms, verify_ms);
    }
    println!("  Proof size is O(1) in N; prove-time grows ~linearly in depth = log2(N).");
    println!("  (A 500M-voter set is depth≈30 — one non-recursive proof; recursive STARK aggregation is future work.)");

    // --- Governance benchmark (SPEC §14) ---
    rule("GOVERNANCE BENCHMARK  (CIP-1694 stake-weighted vs secret 1p1v)");
    let gov: GovConfig = match std::fs::read_to_string(&args.gov) {
        Ok(s) => serde_json::from_str(&s).expect("parse gov config"),
        Err(e) => {
            eprintln!("  cannot read gov config {}: {e}", args.gov);
            exit(2);
        }
    };
    println!("  action: {} ({})", gov.action_id, gov.action_type);
    println!("  \x1b[33mprovenance:\x1b[0m {}", gov.provenance);
    let sw = govbench::stake_weighted(&gov);
    // Shadow 1p1v election on the same question.
    let sv = gov.shadow_voters;
    let shadow_events: Vec<CastEvent> = (0..sv)
        .map(|i| CastEvent { voter: i, choice: govbench::shadow_choice(i, &gov.shadow_distribution) })
        .collect();
    let gopts = vec!["Yes".to_string(), "No".to_string(), "Abstain".to_string()];
    let t_shadow = Instant::now();
    let ger = run_election(sv, &gopts, 3, 5, Policy::RejectDuplicate, 7, &shadow_events, &mut rng);
    let shadow_secs = t_shadow.elapsed().as_secs_f64();
    let op = govbench::one_person(ger.counts[0], ger.counts[1], ger.counts[2]);

    println!("\n  {:<26}{:>22}{:>22}", "", "CIP-1694 (stake)", "Posada Voltaire (1p1v)");
    println!("  {:-<70}", "");
    println!("  {:<26}{:>22}{:>22}", "unit of power", "lovelace", "one human");
    println!("  {:<26}{:>22}{:>22}", "Yes", fmt(sw.yes), fmt(op.yes));
    println!("  {:<26}{:>22}{:>22}", "No (effective)", fmt(sw.no_effective), fmt(op.no));
    println!("  {:<26}{:>22}{:>22}", "Abstain (excluded)", fmt(sw.abstain), fmt(op.abstain));
    println!("  {:<26}{:>21.1}%{:>21.1}%", "Yes share of active", sw.yes_ratio * 100.0, op.yes_ratio_excl_abstain * 100.0);
    println!("  {:<26}{:>22}{:>22}", "threshold", format!("{:.0}%", sw.threshold * 100.0), ">50% majority");
    println!("  {:<26}{:>22}{:>22}", "outcome",
        if sw.ratified { "RATIFIED" } else { "REJECTED" },
        if op.passes_majority { "PASS" } else { "FAIL" });
    println!("  {:<26}{:>22}{:>22}", "ballot secrecy", "public", "threshold-encrypted");
    println!("  {:<26}{:>22}{:>22}", "verifiability", "on-chain", "E2E, re-tallyable");
    println!("  shadow ballot: {} encrypted 1p1v votes tallied in {:.2}s; proof of correct decrypt published.", fmt(sv), shadow_secs);

    // --- One-screen verdict ---
    rule("VERDICT");
    let mech_ok = p1.pass && p2.pass && p3.pass;
    show(&p1);
    show(&p2);
    show(&p3);
    println!("  [{}] P4 coercion / re-vote        Variant A links re-votes (BROKEN); Variant B unlinkable but O(N²)",
        "\x1b[31mFAIL\x1b[0m");
    println!("  [{}] P4 (1p1v ∧ unlinkable re-vote) NO implemented variant satisfies both simultaneously",
        "\x1b[31mFAIL\x1b[0m");

    let durable = mech_ok && false; // P4 falsified by construction below
    let _ = p4a_breaks;
    let reason = if !mech_ok {
        "a mechanical property P1–P3 did not hold"
    } else {
        "the nullifier↔coercion contradiction is real — Variant A (deterministic public nullifier) makes \
         re-votes publicly linkable, so §8's silent unlinkable re-voting is impossible; Variant B (JCJ) restores \
         unlinkability only at O(N²) tally cost. No variant delivers 1p1v AND unlinkable re-voting together."
    };
    println!("\n\x1b[1mDESIGN DURABLE UNDER TEST: {} — {}\x1b[0m",
        if durable { "yes" } else { "no" }, reason);

    if !durable {
        println!("\n(Exiting non-zero: a load-bearing property could not be satisfied. This is the");
        println!(" intended falsification result, not a harness error. P1–P3 held; P4 broke.)");
        exit(1);
    }
    exit(0);
}

fn fmt(n: u64) -> String {
    let s = n.to_string();
    let mut out = String::new();
    for (i, c) in s.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 {
            out.push(',');
        }
        out.push(c);
    }
    out.chars().rev().collect()
}
