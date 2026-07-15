# Posada Voltaire — Falsification Harness

A **falsification harness, not a product**. Its only job is to decide whether the
[`../SPEC.md`](../SPEC.md) design is durable by trying to **break** its two
load-bearing correctness claims and by turning its known scaling cost into a
**measured number** — before any production code is written.

It tries to falsify. Where a property cannot be satisfied it **says so and exits
non-zero**; it never papers over a failure to look clean. See
[`FINDINGS.md`](./FINDINGS.md) for the verdict and the measured numbers.

## What is real (no mocked crypto on any property under test)

| Piece | Library | Where |
|---|---|---|
| Exponential (additively homomorphic) ElGamal | `curve25519-dalek` (Ristretto) | `crates/core/src/elgamal.rs` |
| 3-of-5 joint-Feldman **DKG** + threshold decrypt + Chaum–Pedersen proofs | `curve25519-dalek` | `crates/core/src/{dkg,threshold}.rs` |
| Helios-style **ballot validity** proof ("exactly one choice") | sigma protocols over the ElGamal group | `crates/core/src/validity.rs` |
| **Semaphore-style membership + nullifier** proof | `arkworks` Groth16 + Poseidon over BN254 | `crates/zk/src/lib.rs` |
| **JCJ** blind Plaintext-Equivalence Test dedup | `curve25519-dalek` | `crates/core/src/jcj.rs` |
| Append-only bulletin board + homomorphic tally + **independent verifier** | — | `crates/core/src/{board,tally}.rs` |

Only standard *constructions* (Shamir/Feldman sharing, Lagrange, the circuit
wiring, the bulletin board) are ours; every *primitive* comes from the libraries
above.

## Properties

- **P1 — 1p1v:** double-cast with the same secret is rejected; N credentials ⇒ ≤ N counted.
- **P2 — no single-ballot decryption:** every (t−1)-subset fails; only the homomorphic product is ever decrypted.
- **P3 — universal verifiability:** the independent `verifier` reproduces the tally from the public transcript alone; any tamper flips it to FAIL.
- **P4 — coercion / re-vote (the decider):** both readings of the SPEC's contradiction (§4.4 deterministic public nullifier vs §8 silent unlinkable re-voting) are implemented and attacked. See `FINDINGS.md`.

## Requirements

Rust (stable, tested on 1.94). First build fetches `curve25519-dalek` and the
`arkworks` stack from crates.io.

## Run it

```bash
cd posada-voltaire/harness

# 1. cargo test must be GREEN for P1–P3 (plus all crypto unit tests)
cargo test

# 2. Build release (the harness does real proving; use --release)
cargo build --release

# 3. Run the falsification harness: P1–P3 checks, a full real election,
#    P4 (both variants), the JCJ scaling measurement, the ZK proof timing,
#    and the governance benchmark. Prints a one-screen verdict and exits
#    NON-ZERO because P4 breaks (this is the intended falsification result).
./target/release/harness                 # defaults: --n 10000

# smaller/faster smoke run:
./target/release/harness --n 1500

# demonstrate P4-A coercion linkage at one million voters (real nullifiers):
./target/release/harness --n 200 --coercion-n 1000000

# 4. Independent verifier on the transcript the harness wrote (P3):
./target/release/verifier transcript.json          # PASS, exit 0
```

### Harness flags

| flag | default | meaning |
|---|---|---|
| `--n` | `10000` | voters in the full real election (must also run at `1000000`) |
| `--coercion-n` | `= --n` | scale of the P4-A nullifier-linkage analysis (cheap; run at `1000000`) |
| `--gov` | `config/governance.json` | governance benchmark config |
| `--out` | `transcript.json` | where the election transcript is written |
| `--jcj` | `150,300,600` | ballot counts for the JCJ O(N²) measurement |
| `--seed` | `42` | RNG seed (reproducible) |

> **Scale note.** The full election runs real per-ballot ElGamal + validity
> proofs (~2 ms/ballot), so `--n 1000000` completes but takes ~30–40 min of
> proving on one core (linear). The P4-A coercion analysis (`--coercion-n`) uses
> real deterministic nullifiers only, so it runs at 1,000,000 in well under a
> minute — that is the scale-relevant decider for coercion.

## Governance benchmark config

Live fetch of **gov.tools** and **adastat.net** returned **HTTP 403** inside the
harness (agent proxy), so — as the task allows — the concluded governance action
is a **JSON config input**, not live data. This is stated plainly in the harness
output (the `provenance` line) and in `config/governance.json`. The CIP-1694
tallying **semantics** implemented are real (Abstain excluded from active stake;
non-voting registered stake counts as No for ordinary actions; `Yes/(Yes+No)` vs
threshold). To get a real head-to-head, replace the `drep_yes/no/abstain` and
`not_voted_registered` fields with a real concluded action's DRep tally from
gov.tools.

## Layout

```
harness/
  Cargo.toml                  workspace
  config/governance.json      governance benchmark input (provenance stated)
  crates/core/                ElGamal, DKG, threshold, validity, board, tally, JCJ, govbench
  crates/zk/                  Groth16 Semaphore-style membership + nullifier (Poseidon/BN254)
  crates/harness/             harness + verifier binaries; P1–P3 integration tests
  FINDINGS.md                 what held, what broke, the measured numbers, the verdict
```

## Verdict (see `FINDINGS.md` for detail)

`P1 PASS · P2 PASS · P3 PASS · P4 FAIL` → **DESIGN DURABLE UNDER TEST: no.**
The cryptographic spine is sound; the coercion-resistance story is not, because
the SPEC's §4.4 and §8 are mutually exclusive and the only unlinkable variant is
O(N²). Fixable — but only by changing the SPEC, so it is an open design problem,
not a settled property.
