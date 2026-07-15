//! Threshold decryption of exponential-ElGamal ciphertexts, with a
//! Chaum–Pedersen proof of correct partial decryption per trustee.
//!
//! CRITICAL (property P2): the only function that ever recovers a plaintext is
//! [`decrypt`], and it requires at least `t` partial decryptions of a SINGLE
//! ciphertext — which in the tally path is always the homomorphic *product*
//! ciphertext. With `< t` partials it returns `None`. No API decrypts an
//! individual ballot.

use crate::dkg::{Dkg, TrusteeKey};
use crate::elgamal::Ciphertext;
use crate::group::{bounded_dlog, g, g_mul, hash_to_scalar};
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use rand_core::{CryptoRng, RngCore};

/// Chaum–Pedersen proof that log_G(public_share) == log_{c1}(d) == x_i.
#[derive(Clone, Copy, Debug)]
pub struct CpProof {
    pub e: Scalar,
    pub z: Scalar,
}

#[derive(Clone, Copy, Debug)]
pub struct PartialDecryption {
    pub index: u64,
    /// d_i = x_i * c1
    pub d: RistrettoPoint,
    pub proof: CpProof,
}

/// Produce a partial decryption d_i = x_i*c1 together with a proof that the
/// same x_i is the discrete log of the trustee's public share.
pub fn partial_decrypt<R: RngCore + CryptoRng>(
    trustee: &TrusteeKey,
    ct: &Ciphertext,
    rng: &mut R,
) -> PartialDecryption {
    let d = trustee.share * ct.c1;
    // Chaum–Pedersen (equality of discrete logs) over bases G and c1.
    let w = Scalar::random(rng);
    let t1 = g_mul(&w);
    let t2 = w * ct.c1;
    let e = hash_to_scalar(
        b"voltaire/cp/partial",
        &[g(), ct.c1, trustee.public_share, d, t1, t2],
        &[],
    );
    let z = w + e * trustee.share;
    PartialDecryption {
        index: trustee.index,
        d,
        proof: CpProof { e, z },
    }
}

/// Verify a partial decryption against the trustee's public share.
pub fn verify_partial(part: &PartialDecryption, ct: &Ciphertext, public_share: RistrettoPoint) -> bool {
    // Recompute commitments from the response: T1 = z*G - e*A, T2 = z*c1 - e*d.
    let t1 = g_mul(&part.proof.z) - part.proof.e * public_share;
    let t2 = part.proof.z * ct.c1 - part.proof.e * part.d;
    let e = hash_to_scalar(
        b"voltaire/cp/partial",
        &[g(), ct.c1, public_share, part.d, t1, t2],
        &[],
    );
    e == part.proof.e
}

/// Lagrange coefficient λ_i(0) for the given set of indices.
fn lagrange_at_zero(indices: &[u64], i: u64) -> Scalar {
    let xi = Scalar::from(i);
    let mut num = Scalar::ONE;
    let mut den = Scalar::ONE;
    for &j in indices {
        if j != i {
            let xj = Scalar::from(j);
            num *= xj; // (0 - x_j) = -x_j ; signs cancel across num/den, but keep explicit:
            den *= xj - xi;
        }
    }
    // λ = Π (-x_j)/(x_i - x_j) = Π x_j/(x_j - x_i)  (two sign flips cancel)
    num * den.invert()
}

/// Combine partials for a single ciphertext and recover `m*G`.
///
/// Returns `None` if fewer than `t` *distinct-index* valid partials are given.
/// This is the guard that makes P2 hold: `t-1` partials cannot decrypt.
pub fn combine(dkg: &Dkg, ct: &Ciphertext, partials: &[PartialDecryption]) -> Option<RistrettoPoint> {
    // Deduplicate by index and verify each proof.
    let mut seen = std::collections::HashSet::new();
    let mut valid: Vec<&PartialDecryption> = Vec::new();
    for p in partials {
        if !seen.insert(p.index) {
            continue;
        }
        let pubshare = crate::dkg::public_share_from_commitments(&dkg.commitments, p.index);
        if verify_partial(p, ct, pubshare) {
            valid.push(p);
        }
    }
    if valid.len() < dkg.t {
        return None;
    }
    let idx: Vec<u64> = valid.iter().map(|p| p.index).collect();
    // x*c1 = Σ λ_i * d_i
    let mut xc1 = RistrettoPoint::default();
    for p in &valid {
        let lambda = lagrange_at_zero(&idx, p.index);
        xc1 += lambda * p.d;
    }
    Some(ct.c2 - xc1)
}

/// Full threshold decryption of a *single* ciphertext to a bounded integer.
pub fn decrypt(dkg: &Dkg, ct: &Ciphertext, partials: &[PartialDecryption], max: u64) -> Option<u64> {
    let m_point = combine(dkg, ct, partials)?;
    bounded_dlog(m_point, max)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dkg;
    use crate::elgamal::{encrypt, Ciphertext};
    use rand::rngs::OsRng;

    #[test]
    fn threshold_decrypt_roundtrip() {
        let d = dkg::run(3, 5, &mut OsRng);
        let (ct, _) = encrypt(&d.public_key, 123, &mut OsRng);
        let partials: Vec<_> = d.trustees[..3]
            .iter()
            .map(|k| partial_decrypt(k, &ct, &mut OsRng))
            .collect();
        assert_eq!(decrypt(&d, &ct, &partials, 1000), Some(123));
    }

    #[test]
    fn t_minus_1_cannot_decrypt() {
        // P2 core: any t-1 subset returns None (cannot decrypt).
        let d = dkg::run(3, 5, &mut OsRng);
        let (ct, _) = encrypt(&d.public_key, 7, &mut OsRng);
        for combo in [[0usize, 1], [0, 2], [1, 3], [2, 4], [3, 4]] {
            let partials: Vec<_> = combo
                .iter()
                .map(|&i| partial_decrypt(&d.trustees[i], &ct, &mut OsRng))
                .collect();
            assert_eq!(decrypt(&d, &ct, &partials, 1000), None, "t-1 must not decrypt");
            assert!(combine(&d, &ct, &partials).is_none());
        }
    }

    #[test]
    fn homomorphic_then_threshold() {
        let d = dkg::run(3, 5, &mut OsRng);
        let mut acc = Ciphertext::identity();
        let mut sum = 0;
        for m in [10u64, 20, 30, 40] {
            let (ct, _) = encrypt(&d.public_key, m, &mut OsRng);
            acc = acc.add(&ct);
            sum += m;
        }
        let partials: Vec<_> = [0, 2, 4]
            .iter()
            .map(|&i| partial_decrypt(&d.trustees[i], &acc, &mut OsRng))
            .collect();
        assert_eq!(decrypt(&d, &acc, &partials, 1000), Some(sum));
    }
}
