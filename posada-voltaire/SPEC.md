# Posada Voltaire — Sovereign Voting Protocol

**A coercion‑resistant, end‑to‑end‑verifiable voting system on Cardano, with private ballots on Midnight and one‑person‑one‑vote enforced by the Posada DID stack.**

> *Cryptography replaces trust where trust is abused.* — Posada / Lovelace Manifesto

---

## 0. Status of this document

This is an architecture and threat‑model specification, not an implementation. It is written to be *adversarially honest*: every strong claim ("impossible to change the outcome", "nobody can see your vote", "one person, one vote at 500 M") is stated together with the exact mechanism that earns it and the residual risk that survives. Where a property cannot be achieved absolutely, that is said plainly.

Posada Voltaire is designed as a **parallel and benchmark to Cardano's on‑chain governance voting** (CIP‑1694 / DRep / stake‑weighted voting). The contrast is deliberate: on‑chain governance voting is *public, stake‑weighted, and coercible*. Posada Voltaire is *secret, one‑person‑one‑vote, and coercion‑resistant*. It is meant to demonstrate what a legitimate digital ballot looks like when the ballot — not the wallet balance — is the unit of power.

---

## 1. Design goals (in priority order)

The ordering is load‑bearing. When two goals conflict, the higher one wins.

| # | Goal | Non‑negotiable because |
|---|------|------------------------|
| 1 | **One person, one vote (1p1v)** | Legitimacy. Stake‑ or money‑weighted voting is not democracy. Every enrolled human contributes exactly one ballot, no more, no less. |
| 2 | **Outcome integrity** | A result that can be silently altered is worthless. The tally must be *publicly recomputable* from published evidence, and any tampering must be *detectable by anyone*. |
| 3 | **Ballot secrecy** | Nobody — not Posada, not a trustee, not the chain, not an observer — learns how any identified person voted. |
| 4 | **Coercion resistance / receipt‑freeness** | A voter must be *unable to prove to a third party how they voted*, even if they want to. This is what defeats vote‑buying and intimidation. |
| 5 | **Universal + individual verifiability** | Each voter can confirm their own ballot was counted; anyone can confirm the whole tally is correct. |
| 6 | **Availability under attack** | Eligible voters can cast even against a nation‑state adversary trying to *suppress* (not alter) the vote. |
| 7 | **Scale to 500 M+ voters and thousands of candidates** | The system is nation/continent scale from day one. |
| 8 | **Long‑term secrecy (post‑quantum)** | Ballots stay secret for decades, past the arrival of cryptographically‑relevant quantum computers. |

**Explicit non‑goals:** we do not attempt to make the voter's personal *device* trustworthy (we make the *protocol* robust to a partly‑compromised device via verification, §11). We do not claim to prevent a voter from *choosing* to sell their vote in a face‑to‑face physical setting where a coercer watches the entire session in real time — no remote system can. We reduce it to the hardest possible case and price the attack out (§8).

---

## 2. Threat model

### 2.1 Assets to protect

1. **The tally** (the result) — integrity + correctness.
2. **The link between identity and ballot** — must never exist in recoverable form.
3. **The eligibility set** ("who may vote") — integrity; must equal exactly one credential per living, enrolled human.
4. **Availability** of the casting and verification services.
5. **Long‑term ballot confidentiality** — the encrypted ballot record is public and permanent; its secrecy must survive future cryptanalysis.

### 2.2 Adversaries (assumed capabilities)

- **A1 — The Operator‑insider.** Posada staff, an infrastructure provider, or a compromised server. *Assume full control of any single server and its keys.* No single machine may be trusted with either the identity↔ballot link or the decryption key.
- **A2 — The Trustee minority.** Up to `t‑1` of `n` key‑holding trustees are corrupt/colluding.
- **A3 — The Coercer / vote‑buyer.** Can observe a voter before and after (but not necessarily *during* every possible re‑vote), demand proof, and pay or threaten.
- **A4 — The Sybil.** Tries to obtain more than one voting credential per human (fake IDs, deepfakes, credential resale, bots).
- **A5 — The Endpoint attacker.** Malware on the voter's phone/computer that tries to alter the vote before it is sealed.
- **A6 — The Nation‑state disruptor.** DDoS, BGP hijack, ISP‑level blocking, targeted deanonymization, and — for long‑term secrecy — a *harvest‑now‑decrypt‑later* posture recording all ciphertext for future quantum decryption.
- **A7 — The Network/Global passive observer.** Sees all traffic metadata (who connected, when).

### 2.3 Trust assumptions (what we *do* rely on)

- A **threshold** of trustees (`t` of `n`) is honest and their keys are not simultaneously stolen (§7).
- The **personhood issuance root** (government ID authenticity + liveness) is sound *at enrollment time*. This is the single largest real‑world trust anchor and is discussed candidly in §4.5.
- Standard cryptographic hardness (discrete log / lattice, hash collision resistance), with a stated migration path to post‑quantum primitives (§10).
- At least **one** honest party runs a public verifier and at least **one** honest bulletin‑board mirror exists (needed for universal verifiability to have teeth).

---

## 3. System overview

```
┌──────────────────────────────────────────────────────────────────────────────┐
│ LAYER 0 — IDENTITY (who is a unique human)                                     │
│   Posada DID stack  ·  Hyperledger Identus / Atala PRISM EdgeAgent (this repo) │
│   Gov‑ID scan + liveness  →  on‑device biometric match  →  ZK personhood proof │
│   Output: one anonymous, unlinkable *Voter Credential* (a leaf in a ZK set)    │
└───────────────┬────────────────────────────────────────────────────────────────┘
                │  proof of "I hold a valid, unused voter credential"
                ▼
┌──────────────────────────────────────────────────────────────────────────────┐
│ LAYER 1 — PRIVATE BALLOT (how you voted, hidden)                               │
│   Midnight (Cardano privacy sidechain, ZK / shielded)                          │
│   Encrypted ballot + ZK validity proof + nullifier                             │
│   Nobody sees the choice; everybody sees "a well‑formed vote from a unique     │
│   eligible human that has not voted before".                                   │
└───────────────┬────────────────────────────────────────────────────────────────┘
                │  encrypted ballots (homomorphically tallyable)
                ▼
┌──────────────────────────────────────────────────────────────────────────────┐
│ LAYER 2 — SCALE (500 M ballots)                                                │
│   Regional Hydra heads  →  recursive STARK aggregation  →  Merkle commitments  │
└───────────────┬────────────────────────────────────────────────────────────────┘
                │  Merkle roots + aggregate validity proof
                ▼
┌──────────────────────────────────────────────────────────────────────────────┐
│ LAYER 3 — ANCHOR & TALLY (the immutable outcome)                               │
│   Cardano L1: append‑only bulletin‑board roots  +  threshold homomorphic tally │
│   +  public tally‑correctness proof. Anyone can recompute the result.          │
└──────────────────────────────────────────────────────────────────────────────┘
```

Each layer is described in full below.

---

## 4. Layer 0 — Identity & one‑person‑one‑vote (the Posada DID stack)

### 4.1 Why this layer exists

1p1v is goal #1. It has two halves that *fight each other*:

- **Uniqueness:** exactly one credential per living human (defeat A4, the Sybil).
- **Unlinkability:** the credential, and the ballot cast with it, must be impossible to tie back to the human (protect asset #2).

Most "blockchain voting" projects solve the first by building a central voter roll — and in doing so destroy the second. Posada Voltaire refuses the central roll ("*not with DID*"). Uniqueness and unlinkability are reconciled with **anonymous credentials + nullifiers**.

### 4.2 Enrollment (done once, reusable across elections — the Lovelace pipeline)

The identity pipeline is the one already shipped in the Posada/Lovelace stack and built on the **Hyperledger Identus / Atala PRISM EdgeAgent SDK** (the very SDK in this repository, `EdgeAgentSDK/`):

1. **Government‑ID capture** + **liveness selfie**. Biometric match runs **entirely on‑device**; raw biometrics **never** leave the phone and are never stored server‑side.
2. A **Personhood Issuer** (a DID‑based verifiable‑credential issuer, `did:prism`) checks document authenticity + liveness and issues a **Proof‑of‑Personhood Verifiable Credential (PoP‑VC)** bound to a *biometric commitment*, not to the biometric itself.
3. The uniqueness check is a **de‑duplication over biometric commitments** (a privacy‑preserving fuzzy match / private set membership) so the same face cannot enroll twice — *without* a plaintext biometric database. This is the one place a probabilistic biometric dedup is unavoidable; it runs at *enrollment*, never at *voting*.

The PoP‑VC is a long‑lived, reusable identity asset — the same credential that gates Lovelace, Byron, and Shelley gates Voltaire.

### 4.3 From identity to an *anonymous* voter credential

For a specific election `E`, the voter derives — locally, on device — a **Voter Credential**:

- A fresh secret `s` (never leaves the device).
- A public **commitment** `C = Commit(s, PoP_id)` that is added to the election's **eligibility accumulator** (a Merkle tree / cryptographic accumulator of all eligible commitments). Enrollment into `E` proves "I hold a valid PoP‑VC and I am registering exactly one commitment for election E" in zero knowledge — so the commitment is *unlinkable* to the government identity, yet provably one‑per‑person.
- The set of all `C` is the **public eligibility set** for `E`. It contains no names, no IDs, no biometrics — only commitments.

### 4.4 Casting proves membership + uniqueness, reveals nothing

When voting (§5/§6), the voter produces a zero‑knowledge proof (Semaphore‑style anonymous signaling):

> "I know a secret `s` whose commitment `C` is in the eligibility set for election `E`, and here is the **nullifier** `N = Hash(s, E)`."

- **Membership** ⇒ eligible (defeats forged ballots).
- **Nullifier `N`** is deterministic per `(voter, election)`: casting twice yields the *same* `N`, so the second ballot is rejected. **This is how 1p1v is enforced at cast time without any identity being revealed.** Double‑voting is a cryptographic impossibility, not a database lookup.
- The proof leaks nothing linking `N` back to `C` or to the human.

### 4.5 Honest limitation — the issuance root

The hardest real‑world attack surface is **A4 at enrollment**: fake/borrowed IDs, deepfake liveness, and credential *resale* ("I enroll, then sell my `s`"). Mitigations, not cures:

- Liveness/anti‑deepfake is an arms race; use certified presentation‑attack detection (ISO/IEC 30107), and re‑attestation for high‑stakes elections.
- **Resale of `s`** is bounded by coercion‑resistance (§8): with re‑voting + fake credentials, a bought credential is worth less than it costs because the seller can silently override it. This is *why* coercion resistance is goal #4, not an afterthought.
- Biometric dedup has a nonzero false‑match/false‑non‑match rate; publish the chosen operating point and an appeals path (§9). At 500 M enrollments this is an operational program, not a line of code.

---

## 5. Layer 1 — The private ballot on Midnight

**Requirement (voter's words): "with the DID nobody should be able to see anything, just a vote."**

That is exactly the shielded‑data model of **Midnight**, Cardano's data‑protection sidechain (ZK‑based, smart contracts in the **Compact** language, with a shielded token/UTXO model). Posada Voltaire routes the ballot through Midnight so the *public* record of a vote is only:

```
{ election: E,
  nullifier: N,                    // unlinkable, one per voter
  ballot_ciphertext: ElGamal(vote), // threshold‑encrypted; unreadable by anyone alone
  validity_proof: π }              // ZK: "this ciphertext encodes ONE valid choice"
```

No name. No DID. No choice in the clear. An observer — including Posada itself — sees only *"a unique eligible human cast one well‑formed ballot."* The candidate they chose is inside `ballot_ciphertext`, which **no single party can decrypt** (§7).

Why Midnight rather than rolling our own mixnet:

- Native ZK + shielded state means the "hide the choice, prove it's valid" step is a first‑class primitive, audited and maintained by the Cardano privacy chain rather than bespoke.
- It settles to Cardano, so the anchoring story (§9) is native.
- **Trade‑off & honesty:** Midnight is comparatively young. The spec keeps the ballot representation *chain‑agnostic* (threshold ElGamal + Groth16/STARK proofs) so that if Midnight is unsuitable for a given deployment, the identical ballot can run on a self‑hosted mixnet + Cardano anchor without redesign. Midnight is the preferred private‑ballot substrate, not a hard dependency.

---

## 6. Ballot & tally cryptography

### 6.1 Encryption — threshold, homomorphic

- Ballots are encrypted under a **single election public key** `PK` whose secret is **split across `n` trustees** via distributed key generation (§7). No one holds the whole key.
- The scheme is **additively homomorphic** (exponential‑ElGamal, or lifted‑ElGamal): the product of ciphertexts decrypts to the *sum* of votes. **We never decrypt a single ballot — only the final totals.** This is the mathematical core of ballot secrecy surviving the count.

### 6.2 Large candidate lineups (thousands of candidates)

A naïve one‑ciphertext‑per‑candidate ballot is `O(#candidates)` per voter and does not scale to a large lineup. Options, selectable per election:

- **Vector ballot with a compact range proof:** encode the whole ballot as one packed vector; a single ZK proof asserts "exactly one 1, rest 0" (plurality) or a valid ranked/approval structure. Proof size stays ~constant in the number of candidates using Bulletproofs/PLONK‑style range arguments.
- **Ranked / approval / score voting** are supported by swapping the validity predicate `π` proves; the tally stays homomorphic for approval/score and moves to a verifiable **mixnet + decrypt** for methods (e.g. full STV) that aren't additively homomorphic.
- Candidate lists are themselves Merkle‑committed and published, so "the ballot the voter saw" is provably the canonical slate (defeats slate‑tampering / candidate‑hiding).

### 6.3 Tallying

1. Homomorphically combine all valid ciphertexts (per race) → one ciphertext of the totals.
2. Trustees run **threshold decryption** (§7) on *only* that combined ciphertext.
3. Publish totals **plus a ZK proof of correct decryption**. Anyone can verify the decryption matches the public combined ciphertext — the trustees cannot lie about the result even if `t` of them collude, because the proof is checked against public data.

---

## 7. Trustees & the key ceremony

**Voter's note: "true — find a way."** Here it is.

### 7.1 Distributed Key Generation (no dealer, no single key)

- `n` trustees run a **Pedersen/GJKR DKG**: the election secret key is *never assembled anywhere*. Each trustee ends with a share; `PK` is public; any `t` shares can jointly decrypt, `t‑1` learn nothing.
- Trustees are **diverse and adversarial to each other by construction**: e.g. Posada, an independent election authority, academic cryptographers, civil‑society observers, and an international auditor — chosen so collusion of `t` is politically and legally implausible, not merely discouraged.
- Shares live in **HSMs**, geographically and jurisdictionally separated. Ceremony is performed **in public, on camera, with a published transcript** and independently reproducible from the public commitments.

### 7.2 Threshold decryption ceremony (the count)

- Decryption of the *combined* tally ciphertext is a threshold ceremony: each participating trustee posts a partial decryption **with a ZK proof it used its real share**. Combining `t` valid partials yields the result. A trustee that lies is publicly identifiable and excluded.
- **Robustness:** with `t < n` (e.g. 5‑of‑9), the count completes even if some trustees are offline or malicious. **Secrecy:** `< t` trustees, even fully colluding with the operator, cannot decrypt a single ballot.

### 7.3 What this buys

No single insider (A1), and no minority of trustees (A2), can either read ballots or forge the result. The *only* way to learn the totals is the public, proof‑carrying ceremony — and the only totals it can produce are the true ones.

---

## 8. Coercion resistance & receipt‑freeness

**Voter's note: "we have it on Lovelace."** Voltaire reuses the Lovelace coercion‑resistance stack. The design target is the **JCJ / Civitas** family adapted to anonymous credentials:

- **Receipt‑freeness:** because the voter never holds a decryption of their own ballot and the randomness used for encryption can be *re‑randomized server‑blindly*, a voter **cannot produce a convincing proof** of how they voted. The tracking code (§9) proves *"my ballot is recorded"*, never *"my ballot is for X"*.
- **Coercion resistance via silent re‑voting / fake credentials:** the voter may cast multiple times; **only the last ballot per nullifier counts**, and — in the strong JCJ mode — a coerced voter can hand a coercer a *syntactically valid but fake* credential that produces a ballot which is silently discarded during tally, indistinguishable to the coercer from a real one. The coercer cannot tell whether they were given a real or a decoy credential, so buying/forcing a vote yields nothing reliable.
- This is what makes **credential resale (§4.5) economically irrational**: whatever you sell, you can silently override.

**Honest limit (stated in §1):** a coercer who physically watches the voter's *entire* voting window with no possibility of a later private re‑vote can still coerce. Remote voting cannot fully escape this; we reduce it to that worst case and make everything short of it fail. Physical **supervised‑voting kiosks** are offered for at‑risk populations as the fallback that closes even this gap.

---

## 9. Layer 2 & 3 — Scale, anchoring, immutability, verifiability

### 9.1 Why not "500 M votes on‑chain"

No L1 — Cardano included — settles 500 M discrete ballots inside an election window. Anyone claiming otherwise is hand‑waving. Posada Voltaire uses **verifiable off‑chain capture with L1 anchoring**:

1. **Capture** ballots off‑chain / on Midnight, sharded into **regional Hydra heads** (Cardano's L2 state channels) for locality and throughput.
2. **Aggregate** each batch with **recursive STARK proofs**: a succinct proof that "every ballot in this batch of `N` is valid and unique, and this Merkle root commits to all of them." Verifying one small proof replaces re‑checking millions of ballots.
3. **Anchor** on Cardano L1 only the **Merkle roots + the aggregate validity proof + the final tally + tally‑correctness proof**. Small, cheap, permanent.

### 9.2 Why the outcome cannot be changed

"Impossible to change the outcome" is earned by **four independent locks**, not by encryption alone:

1. **Append‑only public bulletin board.** Every accepted ballot (its ciphertext + nullifier + proof) is published. Its Merkle roots are **anchored on Cardano L1**, which is globally replicated and immutable. To alter or drop a recorded ballot you must break a hash chain *already committed to a public blockchain* — detectable by anyone with a mirror.
2. **Recorded‑as‑cast (individual verifiability).** Each voter gets a private **tracking code**; after casting they look it up on the bulletin board and confirm their ballot is present and unmodified.
3. **Counted‑as‑recorded (universal verifiability).** The homomorphic tally + decryption proof lets *anyone* recompute the result from the published ciphertexts. A wrong total cannot carry a valid proof.
4. **Cast‑as‑intended (Benaloh challenge).** Before finalizing, the voter may **challenge**: the app reveals the encryption randomness for a *spoiled* test ballot so the voter (or their chosen app) can verify the software encrypted the intended choice — then re‑encrypts a fresh real ballot. This catches a lying/compromised client (A5) *without* creating a receipt.

Changing the outcome therefore requires simultaneously: forging a STARK proof (cryptographically infeasible), rewriting Cardano L1 history (economically/globally infeasible), *and* defeating public re‑computation by independent verifiers. Integrity does not rest on trusting Posada.

### 9.3 Finality / rollback

Anchors are considered settled only after **k‑deep** confirmation on Cardano; the tally ceremony references anchors past the settlement horizon so a short chain reorg cannot revert counted ballots. The bulletin board retains pre‑anchor ballots so nothing is lost during the settlement wait.

### 9.4 Availability vs integrity (the voter's Q6, clarified)

"Impossible to change the outcome" (integrity, §9.2) is a *different* property from "impossible to *stop* people voting" (availability). A nation‑state (A6) that cannot alter a single ballot can still try to *suppress* voting via DDoS/blocking. Because **1p1v must be in the high seat**, suppression is treated as a first‑class attack:

- **Multi‑region, multi‑provider** ingest (see §11) with anycast + upstream DDoS scrubbing.
- **Multiple independent submission paths:** web, native app, third‑party relays, Tor/onion service, and **assisted/offline modes** (supervised kiosks; store‑and‑forward relays) so a blocked path does not disenfranchise.
- A ballot is a small self‑authenticating object; it can be **submitted by any relay** without the relay learning the vote, so censorship must block *all* paths, not one.

### 9.5 Audit, disputes, recounts (voter's Q9: yes)

- **Risk‑limiting audit posture:** because the count is a public proof over public ciphertexts, the "audit" is *everyone re‑running the verifier*. Independent parties publish their recomputation.
- **Dispute path:** a voter whose tracking code is missing/altered has cryptographic evidence of a discrepancy; a public challenge process and an independent election authority adjudicate. Enrollment false‑match appeals (§4.5) have a separate human process.
- **Everything public** (eligibility set, ballots, proofs, transcripts) is downloadable in bulk for independent tallies.

---

## 10. Post‑quantum strategy (voter's Q10: "how?")

Ballot ciphertext is **public and permanent**, so *harvest‑now‑decrypt‑later* (A6) is a real threat to secrecy decades out. Approach:

1. **Proofs → hash‑based today.** Prefer **STARKs** (hash‑based, no trusted setup, **post‑quantum secure**) for the aggregation/validity proofs. This removes the biggest PQ exposure and the trusted‑setup risk at once.
2. **Transport → hybrid PQ now.** TLS with **hybrid key exchange** (X25519 + **ML‑KEM/Kyber**) and PQ signatures (**ML‑DSA/Dilithium**) for service and credential signing. Hybrid means we're no weaker than today even if a PQ scheme is later broken.
3. **Long‑term ballot confidentiality → PQ envelope.** Wrap the (classically) homomorphic ElGamal ciphertext in a **post‑quantum KEM envelope** for at‑rest/archival storage so a future quantum adversary who harvested the public record still cannot open ballots; the homomorphic tally is performed inside the trustee ceremony where the classical layer is used transiently and then discarded. Track NIST/IETF **post‑quantum FHE / PQ‑homomorphic** advances and migrate the tally primitive as they mature.
4. **Crypto‑agility by design.** Every primitive is versioned and negotiated; nothing is hard‑coded, so a scheme can be rotated without a protocol fork.

Honest status: fully post‑quantum *homomorphic tallying* is not yet a mature, standardized primitive — that is the one component on a "migrate as the field matures" watch, with the PQ envelope protecting confidentiality in the interim.

---

## 11. Technology & language choices (the voter's Q2: agreed)

| Concern | Choice | Rationale |
|--------|--------|-----------|
| **On‑chain validators (Cardano L1 anchor)** | **Aiken** | Purpose‑built for Cardano, strongly typed, unit‑testable, the ecosystem standard. |
| **Formally‑verified tally core** | **Plutus / Plutarch (Haskell)** | The correctness‑critical tally/anchor logic gets machine‑checked proofs; Haskell is Cardano's formal‑methods heavyweight. |
| **Private ballot contracts** | **Compact (Midnight)** | Native shielded‑state / ZK contract language of the privacy chain. |
| **Off‑chain services: ingest, ZK verification, aggregation, relays** | **Rust** | Memory‑safe, highest‑performance systems language; the throughput bottleneck (proof verification) lives here. |
| **Identity / credential agent** | **Swift — Hyperledger Identus / Atala PRISM EdgeAgent SDK (this repo)** + Rust/Kotlin agents | Reuses the shipped Posada/Lovelace on‑device DID stack. |
| **Zero‑knowledge** | **STARK** (aggregation, PQ‑safe) + **Semaphore‑style** membership/nullifier proofs | PQ posture + anonymous 1p1v. |
| **Voter frontend** | Native iOS/Android (on‑device proving & biometrics) + a hardened web client for verification | On‑device keys never leave the phone. |

**"Strongest language" summary:** *Aiken* on‑chain, *Haskell* for the formally‑verified core, *Rust* for everything performance‑ and security‑critical off‑chain, *Compact* on Midnight. No single language is "strongest" across all layers; each layer uses the strongest tool for its guarantee.

---

## 12. Infrastructure & Hetzner sizing

The workload is **CPU‑bound on ZK‑proof verification**, bursty at close of polls, read‑heavy for verification afterwards. It is a **fleet**, not a server.

### 12.1 Napkin throughput

- 500 M voters; assume a multi‑day window with a regional peak of **~50 000 ballots/sec** globally.
- One **AX‑class node (AMD EPYC 9454P, 48c/96t)** verifies on the order of **~2 000–3 000 proofs/sec** (STARK verify + signature + nullifier check + write).
- ⇒ **~20–30 compute nodes** at peak, **×2–3** for redundancy + regional sharding ⇒ **~60–100 nodes** at global peak.

### 12.2 Tiered fleet (Hetzner)

| Tier | Voters | Compute (proof verify / ingest) | State / consensus / DB | Edge |
|------|--------|-------------------------------|------------------------|------|
| **Pilot** | ≤ 5 M | 3–5 × **CCX43/CCX53** (dedicated vCPU) | 1–2 × CCX33 (Postgres HA) | Cache + LB |
| **National** | ≤ 100 M | 20–40 × **AX162‑R** (EPYC 9454P, 48c/96t, 128–256 GB) | 3–5 × dedicated (Postgres/consensus, NVMe) | Multi‑region LB + CDN + object storage for bulletin board |
| **Global** | 500 M+ | 60–100 × **AX162‑class** across regional **Hydra heads** | 5–9 × dedicated per region | Anycast + DDoS scrubbing + CDN + multi‑region object storage |

- **Compute nodes:** `AX162-R` — 48c/96t EPYC 9454P, 256 GB ECC, NVMe. Stateless proof verifiers behind load balancers; scale horizontally.
- **State tier:** dedicated NVMe boxes for the bulletin board (append‑only) + eligibility accumulator; replicated, with object storage (bulk downloadable ballots).
- **Bulletin board is publicly mirrorable**, so read/verification load is offloaded to CDN + volunteer mirrors, not the core fleet.
- **Cost order of magnitude:** the global tier is dozens‑to‑~100 dedicated servers — a five‑figure/month infrastructure line, not a hyperscaler‑scale spend, precisely because heavy verification is *one* small proof per batch and reads are mirrorable.

*Sizing is a starting estimate to be replaced by load‑testing against the real proof system and per‑election parameters (window length, turnout curve, candidate count).*

---

## 13. Governance of the system itself (voter's Q11)

Stewardship sits with **posada.io**, but *capture‑resistantly*: the trustee set (§7) is deliberately not Posada‑only; the bulletin board is publicly mirrored; verifiers are independent; and protocol upgrades are versioned, published, and adopted through a transparent process. The design intent is that *even Posada cannot alter a result* — which is the entire point of building it this way, and the substantive contrast with stake‑weighted on‑chain governance.

---

## 14. Comparison to Cardano on‑chain governance voting

| Property | Cardano on‑chain gov (CIP‑1694 / DRep) | Posada Voltaire |
|----------|----------------------------------------|-----------------|
| Unit of power | **Stake‑weighted** (ada) | **One person, one vote** |
| Ballot secrecy | Public votes | Secret, threshold‑encrypted |
| Coercion / vote‑buying | Possible (visible, delegable stake) | Resisted (receipt‑free, silent re‑vote) |
| Sybil control | Economic (stake cost) | Proof‑of‑personhood DID |
| Verifiability | On‑chain, public | E2E‑verifiable, publicly recomputable |
| Who it empowers | Capital | Citizens |

This is the parallel the project is meant to make legible.

---

## 15. Honest open problems (nothing swept under the rug)

1. **Coercion in fully‑supervised physical settings** — mitigated, not solved; kiosks are the fallback (§8).
2. **Personhood issuance root** — deepfake liveness + ID forgery is an arms race (§4.5).
3. **Biometric dedup error rates at 500 M** — an operational program with a published operating point and appeals.
4. **PQ homomorphic tally** — not yet standardized; interim PQ envelope + migration watch (§10).
5. **Endpoint trust** — Benaloh challenge detects a cheating client but relies on some voters actually challenging (§9.2).
6. **Legal recognition & data‑protection law** — an immutable public ballot record vs. "right to erasure"; no jurisdiction yet treats a blockchain ballot as legally binding at national scale. This is a policy program, not a cryptographic one, and is the biggest non‑technical blocker.
7. **Digital divide / accessibility** — 500 M includes people without smartphones, connectivity, or literacy; assisted/kiosk modes are mandatory, not optional.

---

*Posada Voltaire — the ballot, made unforgeable. Built on the Posada DID stack; private on Midnight; anchored to Cardano.*
