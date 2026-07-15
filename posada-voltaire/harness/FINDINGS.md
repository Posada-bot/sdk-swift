# Posada Voltaire — Falsification Findings

**Question asked of this harness:** does the SPEC survive an honest attempt to
break its two load-bearing correctness claims (P2 threshold secrecy, P4
coercion/re-vote), and what is the real cost of the scaling path it hand-waves?

**One-line answer:** P1–P3 hold under test; **P4 does not** — the SPEC's §4.4
and §8 are mutually exclusive, and no implemented variant delivers 1p1v *and*
unlinkable silent re-voting at the same time. **DESIGN DURABLE UNDER TEST: no.**

All numbers below are from a real run (`--seed 42`) on a 4-core cloud VM. Crypto
is real: `curve25519-dalek` (exponential ElGamal, Feldman DKG, threshold
decrypt, Helios validity proofs, JCJ PETs) and `arkworks` Groth16 + Poseidon
(Semaphore-style membership). Reproduce with the commands in `README.md`.

---

## What held

### P1 — one person, one vote — **PASS**
Deterministic nullifier `N = Poseidon(s, electionId)` per voter. Double-casting
with the same secret produces the same `N`; the board rejects it (RejectDuplicate)
or overwrites (LastWriteWins). In a 200-voter run with 2 double-cast attempts:
2 rejected, 200 distinct voters, 200 counted (≤ N). `cargo test`
`p1_one_person_one_vote` asserts 3/3 double-casts rejected and `counted == N`.

### P2 — no single-ballot decryption — **PASS**
3-of-5 joint-Feldman DKG; the secret is never assembled. **Every** one of the
`C(5,2)=10` two-trustee (t−1) subsets returns `None` from `decrypt()` — checked
exhaustively in `p2_no_single_ballot_decryption`. `combine()` refuses to
interpolate with `< t` valid partials. In the tally path the **only** ciphertext
ever passed to `decrypt()` is the homomorphic *product* (`run_tally`), never an
individual ballot. The threshold boundary is exact: t works, t−1 cannot.

### P3 — universal verifiability & tamper-evidence — **PASS**
A separate `verifier` binary recomputes the tally from the public transcript
alone (no secrets). Demonstrated:
- Clean 1500-ballot transcript → **PASS**, counts `[500,500,500]`, exit 0.
- Malformed ciphertext → **FAIL** (`undecodable`), exit 1.
- Swap two ballots' valid ciphertexts → **FAIL** (`INVALID validity proof`), exit 1.
- Forged published result / corrupted trustee partial → **FAIL** (unit test
  `p3_...tamper_evidence`): the Chaum–Pedersen partial-decryption proofs are
  Fiat–Shamir-bound to the recomputed combined ciphertext, so any ballot edit
  breaks them.

Real-election timings (N=1500, real ballots): DKG 7 ms; cast+prove+append
≈ 2.3 ms/ballot; homomorphic tally 13 ms; independent verify 1.7 s; transcript
2.3 MiB.

---

## What broke — P4 (the property that decides durability)

The SPEC is internally contradictory: **§4.4** rejects the second ballot via a
*deterministic public nullifier*; **§8** counts the *last* ballot and promises
*unlinkable silent re-voting*. We implemented both readings and attacked them.

### Variant A — deterministic public nullifier `N = Poseidon(s, E)` — **BROKEN**
Given only the public bulletin board, the coercer groups ballots by nullifier:
- **LastWriteWins (§8):** every re-vote is appended, so a re-voter's two ballots
  carry the **same public nullifier** → trivially linked. Detection/linkage rate
  **100%**. At **N = 1,000,000** with 20,000 planted re-votes: **20,000/20,000
  detected** in 46 s, and concrete ballot pairs linked to one voter.
- **RejectDuplicate (§4.4):** the re-vote is **rejected** — the voter simply
  *cannot* silently override a coerced ballot. Coercion resistance is impossible
  by construction.

Either reading fails: the nullifier that makes 1p1v cheap and publicly verifiable
is exactly what makes re-votes linkable. **A deterministic public nullifier and
unlinkable silent re-voting cannot coexist.**

### Variant B — JCJ / Civitas encrypted credentials, no public nullifier — **UNLINKABLE BUT SUPERLINEAR**
De-duplication is done at tally time by blind, threshold Plaintext-Equivalence
Tests (real, in `jcj.rs`). This *does* give unlinkable re-voting — at a measured
quadratic cost:

| N (ballots) | PETs run | seconds | µs/PET |
|------------:|---------:|--------:|-------:|
| 150 | 11,175 | 2.22 | 198.9 |
| 300 | 44,850 | 8.61 | 192.1 |
| 600 | 179,700 | 34.30 | 190.9 |

PET count is `N(N−1)/2` ⇒ **O(N²)**, confirmed (doubling N ≈ 4× time; per-PET
cost flat at ~191 µs). Projected wall-clock for the dedup phase **on one machine**:

| N | PETs | projected time |
|---:|---:|---:|
| 1,000 | 4.99×10⁵ | ~1.6 min |
| 10,000 | 5.00×10⁷ | ~2.7 h |
| 100,000 | 5.00×10⁹ | ~265 h |

At the SPEC's **500,000,000**-voter target this is ~1.25×10¹⁷ PETs — utterly
infeasible on the single-anchor architecture as written. (Near-linear JCJ via
mixnets/hashing exists but is *not* what §8 describes and is out of scope here.)

### Direct answer: is the nullifier↔coercion contradiction resolvable as designed?
**No — not as written.** §4.4 and §8 are mutually exclusive requirements:
- (a) a public per-voter nullifier for cheap, publicly verifiable 1p1v and O(1)
  double-vote prevention, **and**
- (b) unlinkable silent re-voting for coercion resistance

cannot both hold. A public deterministic nullifier links a voter's ballots (a);
removing it forces blind PET dedup, which is O(N²) (b). No variant we implemented
satisfies **1p1v ∧ unlinkable re-voting** simultaneously. Resolving it requires
*changing the SPEC*, e.g.: per-`(voter, epoch)` nullifiers with in-epoch revoting
+ a mixnet between epochs; anonymous-credential revocation with a ZK "this is my
latest ballot" proof; or a near-linear PET tally (mix-and-hash). Each is a
different design than §4.4/§8, and each moves cost or trust somewhere the SPEC
does not currently account for.

---

## Governance benchmark (SPEC §14)

Live fetch of gov.tools / adastat returned **HTTP 403** inside the harness, so the
DRep stake numbers are a **JSON config input** (`config/governance.json`), stated
plainly in the harness output. The CIP-1694 *tallying semantics* are real
(Abstain excluded from active stake; non-voting registered stake → No; Yes/(Yes+No)
vs threshold). With the placeholder figures and a 2,000-voter secret shadow ballot:

| | CIP-1694 (stake) | Posada Voltaire (1p1v) |
|---|---:|---:|
| unit of power | lovelace | one human |
| Yes share of active | 61.8% | 64.7% |
| threshold | 67% | >50% |
| **outcome** | **REJECTED** | **PASS** |
| ballot secrecy | public | threshold-encrypted |

The point is structural, not the exact numbers: a stake-weighted count and a
one-person count of the *same* question can diverge in **outcome**, and one is
public while the other is secret + end-to-end verifiable. Swap in a real concluded
action's tally to get a real head-to-head.

---

## ZK membership proof (real, sampled)

Groth16 over BN254 with Poseidon Merkle + nullifier (Semaphore-style), verified:

| depth | leaves | proof size | prove | verify |
|---:|---:|---:|---:|---:|
| 10 | 1,024 | 128 B | 139 ms | 1.9 ms |
| 14 | 16,384 | 128 B | 177 ms | 2.0 ms |

Proof size is **O(1)** in N; prove-time grows ~linearly in depth = log₂(N). A
500M set is depth ≈ 30 — still one proof, but per-ballot proving at that depth,
times N, is why the SPEC's recursive-STARK aggregation is needed (not implemented
here; noted as future work). We generate one real proof per sampled depth rather
than 10⁶ proofs; the P1 double-vote result is decided by the (real) nullifier at
full scale, not by proving every ballot.

---

## Explicitly out of scope — documented, NOT faked

- **Post-quantum ballot confidentiality (§10.3):** a prototype cannot close this.
  The ElGamal ciphertext is public by design and classically breakable by a future
  quantum adversary (harvest-now-decrypt-later). We did **not** implement a fake PQ
  envelope. Real mitigation (hash-based STARKs already PQ-safe; PQ-KEM envelope on
  stored ciphertext; PQ-homomorphic tally when standardized) is unbuilt.
- **Biometric / personhood issuance root (§4.5):** enrollment is *simulated*
  (random secrets + commitments). Sybil resistance at the human layer is assumed,
  not tested.
- **500M infrastructure, Hydra, recursive STARK aggregation (§9/§12):** single
  machine only; one non-recursive Groth16 proof; recursion noted as future work.

---

## Verdict

`P1 PASS · P2 PASS · P3 PASS · P4 FAIL (both variants)`

**DESIGN DURABLE UNDER TEST: no** — the nullifier↔coercion contradiction is real.
The cryptographic spine (threshold secrecy, homomorphic tally, universal
verifiability, 1p1v via nullifier) is sound and survived attack. The coercion-
resistance story does not: as written, §4.4 and §8 cannot both be true, and the
only unlinkable variant is O(N²). This is fixable, but only by changing the SPEC —
so it should be treated as an open design problem, not a settled property, before
any production code is written.
