//! Homomorphic tally, threshold decryption, and an INDEPENDENT transcript
//! verifier (property P3).
//!
//! The verifier recomputes the per-option combined ciphertexts from the public
//! ballots ALONE, then verifies the trustees' Chaum–Pedersen partial-decryption
//! proofs against those recomputed ciphertexts. Because each proof is bound
//! (via Fiat–Shamir) to the ciphertext's `c1`, tampering with any ballot
//! changes the combined `c1` and the proofs fail to verify → the verifier
//! returns FAIL. No secret material is needed to detect the tamper.

use crate::board::{Ballot, Board, Policy};
use crate::dkg::{public_share_from_commitments, Dkg};
use crate::elgamal::{Ciphertext, CiphertextHex, PublicKey};
use crate::group::{point_from_hex, point_to_hex, scalar_from_hex, scalar_to_hex};
use crate::threshold::{partial_decrypt, verify_partial, CpProof, PartialDecryption};
use crate::validity::{decode_ballot, encode_ballot, verify_ballot, BallotProofHex};
use curve25519_dalek::ristretto::RistrettoPoint;
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Header {
    pub election: String,
    pub options: Vec<String>,
    pub t: usize,
    pub n: usize,
    pub enrolled: u64,
    pub policy: String,
    pub public_key: String,
    /// n × t Feldman commitments (hex points).
    pub commitments: Vec<Vec<String>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PartialHex {
    pub index: u64,
    pub d: String,
    pub e: String,
    pub z: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TallySection {
    /// Per-option combined ciphertext (the ONLY ciphertexts ever decrypted).
    pub combined: Vec<CiphertextHex>,
    /// Per-option list of trustee partial decryptions.
    pub partials: Vec<Vec<PartialHex>>,
    /// Published per-option counts.
    pub results: Vec<u64>,
    pub max: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BallotEntry {
    pub nullifier: String,
    pub ballot: BallotProofHex,
    pub membership: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Transcript {
    pub header: Header,
    pub ballots: Vec<BallotEntry>,
    pub tally: Option<TallySection>,
}

fn encode_commitments(dkg: &Dkg) -> Vec<Vec<String>> {
    dkg.commitments
        .iter()
        .map(|row| row.iter().map(point_to_hex).collect())
        .collect()
}

pub fn decode_commitments(h: &Header) -> Option<Vec<Vec<RistrettoPoint>>> {
    h.commitments
        .iter()
        .map(|row| row.iter().map(|s| point_from_hex(s)).collect::<Option<Vec<_>>>())
        .collect()
}

/// Homomorphically sum the per-option ciphertexts across a set of ballots.
pub fn combine_ballots(ballots: &[&Ballot], k: usize) -> Vec<Ciphertext> {
    let mut acc = vec![Ciphertext::identity(); k];
    for b in ballots {
        for i in 0..k {
            acc[i] = acc[i].add(&b.cts[i]);
        }
    }
    acc
}

/// Build the tally section by decrypting ONLY the combined ciphertexts.
pub fn run_tally<R: RngCore + CryptoRng>(
    dkg: &Dkg,
    counted: &[&Ballot],
    k: usize,
    max: u64,
    rng: &mut R,
) -> TallySection {
    let combined = combine_ballots(counted, k);
    let mut partials_out = Vec::with_capacity(k);
    let mut results = Vec::with_capacity(k);
    for ct in &combined {
        // Use the first t trustees to decrypt this single combined ciphertext.
        let parts: Vec<PartialDecryption> = dkg.trustees[..dkg.t]
            .iter()
            .map(|tr| partial_decrypt(tr, ct, rng))
            .collect();
        let count = crate::threshold::decrypt(dkg, ct, &parts, max).expect("combined decrypt");
        results.push(count);
        partials_out.push(
            parts
                .iter()
                .map(|p| PartialHex {
                    index: p.index,
                    d: point_to_hex(&p.d),
                    e: scalar_to_hex(&p.proof.e),
                    z: scalar_to_hex(&p.proof.z),
                })
                .collect(),
        );
    }
    TallySection {
        combined: combined.iter().map(|c| c.to_hex()).collect(),
        partials: partials_out,
        results,
        max,
    }
}

/// Serialize a full transcript from a finished board.
pub fn build_transcript(
    header_election: &str,
    options: &[String],
    dkg: &Dkg,
    board: &Board,
    enrolled: u64,
    tally: Option<TallySection>,
) -> Transcript {
    let ballots = board
        .records
        .iter()
        .map(|b| BallotEntry {
            nullifier: hex::encode(b.nullifier),
            ballot: encode_ballot(&b.cts, &b.proof),
            membership: b.membership.clone(),
        })
        .collect();
    Transcript {
        header: Header {
            election: header_election.to_string(),
            options: options.to_vec(),
            t: dkg.t,
            n: dkg.n,
            enrolled,
            policy: board.policy.as_str().to_string(),
            public_key: point_to_hex(&dkg.public_key.0),
            commitments: encode_commitments(dkg),
        },
        ballots,
        tally,
    }
}

#[derive(Clone, Debug)]
pub struct VerifyOutcome {
    pub pass: bool,
    pub reason: String,
    pub counts: Vec<u64>,
}

/// INDEPENDENT verifier: recompute + check everything from the transcript alone.
pub fn verify_transcript(t: &Transcript) -> VerifyOutcome {
    let k = t.header.options.len();
    let pk = match point_from_hex(&t.header.public_key) {
        Some(p) => PublicKey(p),
        None => return fail("malformed public key"),
    };
    let commitments = match decode_commitments(&t.header) {
        Some(c) => c,
        None => return fail("malformed commitments"),
    };
    let policy = match t.header.policy.as_str() {
        "reject_duplicate" => Policy::RejectDuplicate,
        "last_write_wins" => Policy::LastWriteWins,
        other => return fail(&format!("unknown policy {other}")),
    };

    // 1. Decode + validity-check every ballot; enforce the policy to get the
    //    counted set (verifier trusts nothing but the transcript).
    let mut latest: std::collections::HashMap<[u8; 32], usize> = std::collections::HashMap::new();
    let mut order: Vec<[u8; 32]> = Vec::new();
    let mut decoded: Vec<Ballot> = Vec::with_capacity(t.ballots.len());
    for (i, be) in t.ballots.iter().enumerate() {
        let null = match hex::decode(&be.nullifier).ok().and_then(|v| <[u8; 32]>::try_from(v).ok()) {
            Some(n) => n,
            None => return fail(&format!("ballot {i}: bad nullifier")),
        };
        let (cts, proof) = match decode_ballot(&be.ballot) {
            Some(x) => x,
            None => return fail(&format!("ballot {i}: undecodable")),
        };
        if cts.len() != k {
            return fail(&format!("ballot {i}: wrong option count"));
        }
        if !verify_ballot(&pk, &cts, &proof) {
            return fail(&format!("ballot {i}: INVALID validity proof (exactly-one-choice broken)"));
        }
        match policy {
            Policy::RejectDuplicate => {
                if latest.contains_key(&null) {
                    return fail(&format!("ballot {i}: duplicate nullifier under reject policy"));
                }
                latest.insert(null, i);
                order.push(null);
            }
            Policy::LastWriteWins => {
                if !latest.contains_key(&null) {
                    order.push(null);
                }
                latest.insert(null, i);
            }
        }
        decoded.push(Ballot {
            nullifier: null,
            cts,
            proof,
            membership: be.membership.clone(),
        });
    }

    let counted: Vec<&Ballot> = order.iter().map(|nl| &decoded[latest[nl]]).collect();

    // 2. Recompute combined ciphertexts from the counted ballots ALONE.
    let combined = combine_ballots(&counted, k);

    let tally = match &t.tally {
        Some(ts) => ts,
        None => return fail("no tally section"),
    };
    if tally.partials.len() != k || tally.results.len() != k {
        return fail("tally shape mismatch");
    }

    // 3. Verify partial-decryption proofs against the RECOMPUTED combined ct,
    //    then decrypt. A tampered ballot changes `combined` and breaks these.
    let mut counts = Vec::with_capacity(k);
    for opt in 0..k {
        let ct = combined[opt];
        let mut parts = Vec::new();
        for ph in &tally.partials[opt] {
            let d = match point_from_hex(&ph.d) {
                Some(p) => p,
                None => return fail("bad partial point"),
            };
            let (e, z) = match (scalar_from_hex(&ph.e), scalar_from_hex(&ph.z)) {
                (Some(e), Some(z)) => (e, z),
                _ => return fail("bad partial scalar"),
            };
            let part = PartialDecryption {
                index: ph.index,
                d,
                proof: CpProof { e, z },
            };
            let pubshare = public_share_from_commitments(&commitments, ph.index);
            if !verify_partial(&part, &ct, pubshare) {
                return VerifyOutcome {
                    pass: false,
                    reason: format!(
                        "option {opt}: partial-decryption proof FAILED against recomputed tally \
                         → ballot tampering or forged tally detected"
                    ),
                    counts: vec![],
                };
            }
            parts.push(part);
        }
        match crate::threshold::decrypt(&Dkg {
            t: t.header.t,
            n: t.header.n,
            public_key: pk,
            trustees: vec![],
            commitments: commitments.clone(),
        }, &ct, &parts, tally.max) {
            Some(c) => counts.push(c),
            None => return fail(&format!("option {opt}: could not combine ≥ t partials")),
        }
    }

    // 4. Cross-check against the published results.
    if counts != tally.results {
        return VerifyOutcome {
            pass: false,
            reason: format!(
                "recomputed counts {counts:?} != published {:?} → transcript inconsistent",
                tally.results
            ),
            counts,
        };
    }

    VerifyOutcome {
        pass: true,
        reason: format!("verified {} ballots, counts {counts:?}", counted.len()),
        counts,
    }
}

fn fail(msg: &str) -> VerifyOutcome {
    VerifyOutcome {
        pass: false,
        reason: msg.to_string(),
        counts: vec![],
    }
}
