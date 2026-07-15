# Posada Voltaire — Sovereign Voting Protocol

A coercion‑resistant, end‑to‑end‑verifiable voting protocol on **Cardano**, with
private ballots on **Midnight** and one‑person‑one‑vote enforced by the
**Posada DID stack** (built on the Hyperledger Identus / Atala PRISM EdgeAgent
SDK in this repository).

Designed as a parallel and benchmark to stake‑weighted on‑chain governance:
*secret ballot, one person one vote, coercion‑resistant, verifiable by anyone.*

## Contents

| File | What it is |
|------|-----------|
| [`SPEC.md`](./SPEC.md) | The deep technical spec — threat model, identity/DID layer, private ballot on Midnight, threshold homomorphic tally, key ceremony, coercion resistance, scaling to 500M, anchoring/immutability, post‑quantum strategy, language & Hetzner sizing, audits, governance, and honest open problems. |
| [`mockups.html`](./mockups.html) | Noble UI mockups — the five‑screen voter journey, architecture, and the four integrity locks. Open in a browser. |
| [`MANIFESTO.md`](./MANIFESTO.md) | The Posada / Lovelace manifesto (English + original Portuguese). |
| `assets/` | The Posada / Ada Lovelace logo. |

## The design in one paragraph

Identity is proven once by the Posada DID stack (gov‑ID + on‑device liveness →
a zero‑knowledge personhood credential) and reduced to an **anonymous, unlinkable
voter credential**. Casting a ballot publishes only a **nullifier** (which makes
double‑voting a cryptographic impossibility), a **threshold‑encrypted choice**
(readable by no single party), and a **validity proof** — routed through Midnight
so nobody sees anything but "a unique eligible human cast one well‑formed vote."
Ballots are captured off‑chain across regional **Hydra heads**, compressed with
**recursive STARK proofs**, and their roots plus the **threshold‑decrypted totals**
(with a proof) are anchored to **Cardano L1**. The result is recomputable by anyone
and rewritable by no one — not even Posada.

## Language choices

- **Aiken** — on‑chain validators (Cardano L1 anchor)
- **Plutus / Plutarch (Haskell)** — formally‑verified tally core
- **Compact** — private‑ballot contracts on Midnight
- **Rust** — high‑throughput off‑chain ingest, ZK verification, aggregation, relays
- **Swift / Identus EdgeAgent SDK** (this repo) — on‑device identity & credentials

See [`SPEC.md`](./SPEC.md) §11 for the rationale and §12 for Hetzner fleet sizing.
