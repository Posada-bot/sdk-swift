//! Joint-Feldman distributed key generation for a t-of-n threshold ElGamal key.
//!
//! No dealer ever holds the whole secret: each trustee contributes a random
//! polynomial, publishes Feldman commitments to its coefficients, and hands
//! every other trustee a share. Trustee i's secret share is the sum of the
//! shares it received; the group public key is the sum of the constant-term
//! commitments. The implicit secret `x = Σ_j a_{j,0}` is never assembled.
//!
//! This is the standard joint-Feldman DKG (secure against a passive/honest-but-
//! curious minority, which is exactly the P2 property under test: no `t-1`
//! subset can decrypt). Active-adversary robustness (GJKR complaint rounds) is
//! noted as out of scope in FINDINGS.

use crate::elgamal::PublicKey;
use crate::group::g;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use rand_core::{CryptoRng, RngCore};

/// One trustee's private key material after the DKG completes.
#[derive(Clone, Debug)]
pub struct TrusteeKey {
    /// Evaluation index (1..=n), never 0.
    pub index: u64,
    /// Secret share x_i = f(i) of the implicit secret x = f(0).
    pub share: Scalar,
    /// Public share x_i * G (publicly derivable from the commitments).
    pub public_share: RistrettoPoint,
}

/// Public + private output of the ceremony.
#[derive(Clone, Debug)]
pub struct Dkg {
    pub t: usize,
    pub n: usize,
    pub public_key: PublicKey,
    pub trustees: Vec<TrusteeKey>,
    /// Per-trustee Feldman commitments: commitments[j][k] = a_{j,k} * G.
    pub commitments: Vec<Vec<RistrettoPoint>>,
}

fn eval_poly(coeffs: &[Scalar], x: Scalar) -> Scalar {
    // Horner
    let mut acc = Scalar::ZERO;
    for c in coeffs.iter().rev() {
        acc = acc * x + c;
    }
    acc
}

/// Public share x_i*G reconstructed from all trustees' Feldman commitments:
/// Σ_j Σ_k commitments[j][k] * i^k.
pub fn public_share_from_commitments(commitments: &[Vec<RistrettoPoint>], index: u64) -> RistrettoPoint {
    let xi = Scalar::from(index);
    let mut total = RistrettoPoint::default();
    for comm in commitments {
        let mut xpow = Scalar::ONE;
        let mut sub = RistrettoPoint::default();
        for a_k in comm {
            sub += xpow * a_k;
            xpow *= xi;
        }
        total += sub;
    }
    total
}

/// Verify a received share against the dealer's Feldman commitments:
/// share*G ?= Σ_k commit[k] * i^k.
fn verify_share(share: Scalar, commit: &[RistrettoPoint], index: u64) -> bool {
    let xi = Scalar::from(index);
    let mut xpow = Scalar::ONE;
    let mut rhs = RistrettoPoint::default();
    for a_k in commit {
        rhs += xpow * a_k;
        xpow *= xi;
    }
    share * g() == rhs
}

/// Run the ceremony for `t`-of-`n`. Panics if parameters are nonsensical.
pub fn run<R: RngCore + CryptoRng>(t: usize, n: usize, rng: &mut R) -> Dkg {
    assert!(t >= 1 && t <= n, "need 1 <= t <= n");
    // Each trustee j samples a degree t-1 polynomial and commits to it.
    let mut all_coeffs: Vec<Vec<Scalar>> = Vec::with_capacity(n);
    let mut commitments: Vec<Vec<RistrettoPoint>> = Vec::with_capacity(n);
    for _ in 0..n {
        let coeffs: Vec<Scalar> = (0..t).map(|_| Scalar::random(rng)).collect();
        let comm: Vec<RistrettoPoint> = coeffs.iter().map(|c| c * g()).collect();
        all_coeffs.push(coeffs);
        commitments.push(comm);
    }

    // Every trustee i (index 1..=n) collects shares f_j(i) from every dealer j
    // and verifies each against that dealer's commitments (Feldman VSS).
    let mut trustees = Vec::with_capacity(n);
    for i in 1..=n as u64 {
        let mut share = Scalar::ZERO;
        for j in 0..n {
            let s_ji = eval_poly(&all_coeffs[j], Scalar::from(i));
            assert!(
                verify_share(s_ji, &commitments[j], i),
                "Feldman share verification failed (dealer {j} -> trustee {i})"
            );
            share += s_ji;
        }
        let public_share = public_share_from_commitments(&commitments, i);
        debug_assert_eq!(share * g(), public_share);
        trustees.push(TrusteeKey {
            index: i,
            share,
            public_share,
        });
    }

    // Group public key = Σ_j commitments[j][0] = (Σ_j a_{j,0}) * G = x*G.
    let pk = commitments
        .iter()
        .fold(RistrettoPoint::default(), |acc, c| acc + c[0]);

    Dkg {
        t,
        n,
        public_key: PublicKey(pk),
        trustees,
        commitments,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::group::bounded_dlog;
    use rand::rngs::OsRng;

    #[test]
    fn public_key_matches_reconstructed_secret() {
        let dkg = run(3, 5, &mut OsRng);
        // Reconstruct x from any 3 shares via Lagrange at 0 and check x*G == pk.
        let idx: Vec<u64> = dkg.trustees[..3].iter().map(|k| k.index).collect();
        let mut x = Scalar::ZERO;
        for k in &dkg.trustees[..3] {
            let mut num = Scalar::ONE;
            let mut den = Scalar::ONE;
            for &j in &idx {
                if j != k.index {
                    num *= Scalar::from(j);
                    den *= Scalar::from(j) - Scalar::from(k.index);
                }
            }
            let lambda = num * den.invert();
            x += lambda * k.share;
        }
        assert_eq!(x * g(), dkg.public_key.0);
        // sanity: encrypt small m and decrypt with reconstructed x
        let (ct, _) = crate::elgamal::encrypt(&dkg.public_key, 42, &mut OsRng);
        let mpt = ct.c2 - x * ct.c1;
        assert_eq!(bounded_dlog(mpt, 100), Some(42));
    }
}
