//! Variant B — JCJ / Civitas-style coercion resistance WITHOUT a per-voter
//! public nullifier. Eligibility and de-duplication are decided at tally time
//! by blind Plaintext-Equivalence Tests (PETs) on encrypted credentials.
//!
//! This is the design that *can* give unlinkable re-voting — but its tally is
//! superlinear. This module measures that cost with real threshold PETs so the
//! harness can report actual wall-clock and confirm/refute "superlinear".

use crate::dkg::Dkg;
use crate::elgamal::{Ciphertext, PublicKey};
use crate::group::g;
use crate::threshold::{combine, partial_decrypt};
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use rand_core::{CryptoRng, RngCore};
use std::time::Instant;

/// Encrypt a credential *point* under the threshold key.
pub fn encrypt_credential<R: RngCore + CryptoRng>(
    pk: &PublicKey,
    cred: RistrettoPoint,
    rng: &mut R,
) -> Ciphertext {
    let r = Scalar::random(rng);
    Ciphertext {
        c1: r * g(),
        c2: cred + r * pk.0,
    }
}

/// A real, blinded, threshold Plaintext-Equivalence Test.
///
/// Returns `true` iff the two ciphertexts encrypt the same credential. The
/// difference is blinded by a fresh random `z` shared across the trustees so
/// that an *inequality* leaks nothing (the decrypted point is uniformly random).
pub fn pet<R: RngCore + CryptoRng>(dkg: &Dkg, a: &Ciphertext, b: &Ciphertext, rng: &mut R) -> bool {
    // ratio = Enc(credA - credB)
    let ratio = Ciphertext {
        c1: a.c1 - b.c1,
        c2: a.c2 - b.c2,
    };
    // blind: z * ratio = Enc(z*(credA - credB)), z != 0
    let z = Scalar::random(rng);
    let blinded = Ciphertext {
        c1: z * ratio.c1,
        c2: z * ratio.c2,
    };
    // threshold-decrypt the blinded ratio to a POINT (message is a point).
    let parts: Vec<_> = dkg.trustees[..dkg.t]
        .iter()
        .map(|tr| partial_decrypt(tr, &blinded, rng))
        .collect();
    match combine(dkg, &blinded, &parts) {
        Some(m_point) => m_point == RistrettoPoint::default(),
        None => false,
    }
}

/// Precomputed material for fast repeated PETs: the first-`t` trustee shares and
/// their Lagrange-at-0 coefficients. Computing this ONCE (not per PET) is what
/// keeps the O(N^2) measurement tractable; it does not change the asymptotics.
pub struct PetCtx {
    shares: Vec<Scalar>,
    lambdas: Vec<Scalar>,
}

impl PetCtx {
    pub fn new(dkg: &Dkg) -> Self {
        let idx: Vec<u64> = dkg.trustees[..dkg.t].iter().map(|k| k.index).collect();
        let mut lambdas = Vec::with_capacity(dkg.t);
        for &i in &idx {
            let xi = Scalar::from(i);
            let mut num = Scalar::ONE;
            let mut den = Scalar::ONE;
            for &j in &idx {
                if j != i {
                    let xj = Scalar::from(j);
                    num *= xj;
                    den *= xj - xi;
                }
            }
            lambdas.push(num * den.invert());
        }
        PetCtx {
            shares: dkg.trustees[..dkg.t].iter().map(|k| k.share).collect(),
            lambdas,
        }
    }
}

/// A real threshold PET WITHOUT the per-partial Chaum–Pedersen proofs (the
/// trustees are assumed to follow the protocol for the purpose of measuring the
/// dedup loop's asymptotic cost). This is the intrinsic cryptographic PET work:
/// ratio, blind, t partial decryptions, Lagrange combine, identity check.
pub fn pet_fast<R: RngCore + CryptoRng>(ctx: &PetCtx, a: &Ciphertext, b: &Ciphertext, rng: &mut R) -> bool {
    let z = Scalar::random(rng);
    let c1 = z * (a.c1 - b.c1);
    let c2 = z * (a.c2 - b.c2);
    let mut xc1 = RistrettoPoint::default();
    for (share, lambda) in ctx.shares.iter().zip(ctx.lambdas.iter()) {
        xc1 += (*lambda * *share) * c1;
    }
    (c2 - xc1) == RistrettoPoint::default()
}

#[derive(Clone, Debug)]
pub struct DedupMeasurement {
    pub n: usize,
    pub pets_run: u64,
    pub duplicates_found: u64,
    pub seconds: f64,
    pub per_pet_us: f64,
}

/// Run the pairwise duplicate-elimination phase for `n` ballots (with a few
/// planted re-votes) using REAL threshold PETs, and measure it.
///
/// This is the O(n^2) phase of a JCJ tally. We run it at sizes small enough to
/// finish, then the harness projects to 10k/100k (which are infeasible on one
/// machine — itself the finding).
pub fn measure_dedup<R: RngCore + CryptoRng>(dkg: &Dkg, n: usize, revote_pairs: usize, rng: &mut R) -> DedupMeasurement {
    let pk = dkg.public_key;
    // Build n ballots; plant `revote_pairs` duplicate credentials.
    let mut creds: Vec<RistrettoPoint> = (0..n).map(|_| Scalar::random(rng) * g()).collect();
    for p in 0..revote_pairs.min(n / 2) {
        creds[n - 1 - p] = creds[p]; // a re-vote: same credential appears twice
    }
    let ballots: Vec<Ciphertext> = creds.iter().map(|c| encrypt_credential(&pk, *c, rng)).collect();

    let ctx = PetCtx::new(dkg);
    let start = Instant::now();
    let mut pets = 0u64;
    let mut dups = 0u64;
    for i in 0..n {
        for j in (i + 1)..n {
            pets += 1;
            if pet_fast(&ctx, &ballots[i], &ballots[j], rng) {
                dups += 1;
            }
        }
    }
    let secs = start.elapsed().as_secs_f64();
    DedupMeasurement {
        n,
        pets_run: pets,
        duplicates_found: dups,
        seconds: secs,
        per_pet_us: if pets > 0 { secs * 1e6 / pets as f64 } else { 0.0 },
    }
}

/// Project wall-clock for the O(n^2) dedup phase at a target `n`, given a
/// measured per-PET cost. Clearly a projection, not a run.
pub fn project_seconds(per_pet_us: f64, n: u64) -> f64 {
    let pets = (n as f64) * (n as f64 - 1.0) / 2.0;
    pets * per_pet_us / 1e6
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dkg;
    use rand::rngs::OsRng;

    #[test]
    fn pet_detects_equal_and_unequal() {
        let d = dkg::run(3, 5, &mut OsRng);
        let cred = Scalar::random(&mut OsRng) * g();
        let other = Scalar::random(&mut OsRng) * g();
        let a = encrypt_credential(&d.public_key, cred, &mut OsRng);
        let a2 = encrypt_credential(&d.public_key, cred, &mut OsRng); // re-encryption
        let b = encrypt_credential(&d.public_key, other, &mut OsRng);
        assert!(pet(&d, &a, &a2, &mut OsRng), "same credential must match");
        assert!(!pet(&d, &a, &b, &mut OsRng), "different credential must not match");
    }
}
