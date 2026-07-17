# Posada Voltaire — Session Handoff

Context capture for continuing this work on another machine (e.g. a local
Claude Code session). Read this + `SPEC.md` + `harness/FINDINGS.md` and you have
the whole thread without needing the original chat.

Repo: `Posada-bot/sdk-swift` · branch: **`voting-app`** · all work under `posada-voltaire/`.

## What this project is

A design + falsification study for **Posada Voltaire**, a coercion-resistant,
end-to-end-verifiable voting protocol on Cardano (private ballots on Midnight,
one-person-one-vote via the Posada DID stack). Positioned as a parallel/benchmark
to stake-weighted CIP-1694 on-chain governance.

## The arc of the work (in order)

1. **`SPEC.md`** — deep architecture + threat model. Four layers: Identity (DID +
   ZK personhood → anonymous voter credential), Private ballot (Midnight,
   threshold-encrypted, nullifier), Scale (Hydra + recursive STARK aggregation),
   Anchor/tally (Cardano L1, threshold homomorphic tally, 4 integrity locks).
   Language picks: Aiken (validators), Haskell/Plutus (verified tally core), Rust
   (off-chain), Compact (Midnight). Honest open problems section included.
2. **`mockups.html`** + **`assets/`** — noble civic UI mockups (5-screen voter
   journey, architecture, integrity locks, manifesto) built around the real Ada
   Lovelace logo. **`MANIFESTO.md`** — Posada/Lovelace manifesto (EN + PT).
3. **`harness/`** — a Rust **falsification harness** (NOT a product) that tries to
   break the SPEC's two load-bearing claims and measures its scaling cost.

## Verdict already reached (see `harness/FINDINGS.md`)

`P1 PASS · P2 PASS · P3 PASS · P4 FAIL` → **DESIGN DURABLE UNDER TEST: no.**

- **Held:** 1p1v (nullifier dedup), no single-ballot decryption (t-of-n threshold;
  every t-1 subset fails), universal verifiability + tamper-evidence (independent
  verifier). Real crypto: dalek ElGamal/Feldman-DKG/threshold + Helios validity
  proofs + arkworks Groth16/Poseidon Semaphore-style membership.
- **Broke:** the SPEC's §4.4 (deterministic public nullifier, reject re-vote) and
  §8 (silent unlinkable re-voting) are **mutually exclusive**. Variant A links
  re-votes 100% (20,000/20,000 at N=1e6). Variant B (JCJ blind PET) is unlinkable
  but measured **O(N²)** (~191 µs/PET; ~265 h projected at 100k). No variant gives
  1p1v AND unlinkable re-voting together.

## Key decisions / rationale

- **dalek (Ristretto)** for ElGamal/DKG/threshold/PET; **arkworks (BN254)** for the
  Groth16 membership circuit — independent subsystems, both real libraries.
- Ballot validity ("exactly one choice") is **Helios-style disjunctive
  Chaum-Pedersen**, not a SNARK — the SNARK is only for anonymous membership.
- Exponential ElGamal (m·G) so the homomorphic product decrypts to the vote sum;
  bounded-BSGS decodes the final tally only.
- Governance benchmark: gov.tools/adastat return **403** to the harness, so the
  DRep tally is a **JSON config input** (`harness/config/governance.json`),
  provenance stated in output. CIP-1694 tallying *semantics* are real.

## Open problems / candidate next steps (not yet done)

1. **Resolve the P4 contradiction** (the whole point): needs a SPEC change, e.g.
   per-`(voter, epoch)` nullifiers with in-epoch revoting + inter-epoch mixnet;
   anonymous-credential revocation with a ZK "latest-ballot" proof; or near-linear
   PET (mix-and-hash). Prototype one and re-run the harness.
2. **Recursive STARK aggregation** (SPEC §9/§12) — currently one non-recursive
   Groth16 proof; the 1M *tally* path is ~linear-time proving, not aggregated.
3. Wire in a **real concluded CIP-1694 action** tally for a true §14 head-to-head.
4. Post-quantum (§10.3), biometric root (§4.5), 500M infra (§12) — documented,
   unbuilt, deliberately out of scope.

## Continue locally

```bash
git clone https://github.com/Posada-bot/sdk-swift.git
cd sdk-swift && git checkout voting-app
cd posada-voltaire/harness
cargo test && cargo build --release && ./target/release/harness
```
A fresh Claude Code session pointed at this repo can read this file + `SPEC.md` +
`harness/FINDINGS.md` and pick up where the thread left off.
