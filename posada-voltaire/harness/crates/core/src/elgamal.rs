//! Exponential (additively homomorphic) ElGamal over Ristretto.
//!
//! A message `m` is encoded as `m*G`, so the *product* of two ciphertexts
//! decrypts to the *sum* of the plaintexts — this is what makes the tally
//! computable without ever decrypting an individual ballot.

use crate::group::{encode_u64, g_mul, point_from_hex, point_to_hex};
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublicKey(pub RistrettoPoint);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ciphertext {
    pub c1: RistrettoPoint,
    pub c2: RistrettoPoint,
}

impl Ciphertext {
    /// The encryption of 0 with randomness 0 — the identity for homomorphic add.
    pub fn identity() -> Self {
        Ciphertext {
            c1: RistrettoPoint::default(),
            c2: RistrettoPoint::default(),
        }
    }

    /// Homomorphic addition: Enc(a) + Enc(b) = Enc(a+b).
    pub fn add(&self, other: &Ciphertext) -> Ciphertext {
        Ciphertext {
            c1: self.c1 + other.c1,
            c2: self.c2 + other.c2,
        }
    }

    pub fn to_hex(&self) -> CiphertextHex {
        CiphertextHex {
            c1: point_to_hex(&self.c1),
            c2: point_to_hex(&self.c2),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CiphertextHex {
    pub c1: String,
    pub c2: String,
}

impl CiphertextHex {
    pub fn decode(&self) -> Option<Ciphertext> {
        Some(Ciphertext {
            c1: point_from_hex(&self.c1)?,
            c2: point_from_hex(&self.c2)?,
        })
    }
}

/// Encrypt `m` (encoded as `m*G`). Returns the ciphertext and the randomness
/// `r` (needed by the prover to build validity proofs).
pub fn encrypt<R: RngCore + CryptoRng>(
    pk: &PublicKey,
    m: u64,
    rng: &mut R,
) -> (Ciphertext, Scalar) {
    let r = Scalar::random(rng);
    encrypt_with_randomness(pk, m, r)
}

pub fn encrypt_with_randomness(pk: &PublicKey, m: u64, r: Scalar) -> (Ciphertext, Scalar) {
    let c1 = g_mul(&r);
    let c2 = encode_u64(m) + r * pk.0;
    (Ciphertext { c1, c2 }, r)
}

/// Encrypt a full scalar message point `m*G` given as a group element.
pub fn encrypt_point<R: RngCore + CryptoRng>(
    pk: &PublicKey,
    m_point: RistrettoPoint,
    rng: &mut R,
) -> (Ciphertext, Scalar) {
    let r = Scalar::random(rng);
    (
        Ciphertext {
            c1: g_mul(&r),
            c2: m_point + r * pk.0,
        },
        r,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::group::bounded_dlog;
    use rand::rngs::OsRng;

    #[test]
    fn homomorphic_sum_decrypts_to_sum() {
        // trivial single-key sanity check (full threshold decrypt tested elsewhere)
        let x = Scalar::random(&mut OsRng);
        let pk = PublicKey(g_mul(&x));
        let mut acc = Ciphertext::identity();
        let mut total = 0u64;
        for m in [3u64, 5, 7, 11] {
            let (ct, _) = encrypt(&pk, m, &mut OsRng);
            acc = acc.add(&ct);
            total += m;
        }
        let m_point = acc.c2 - x * acc.c1;
        assert_eq!(bounded_dlog(m_point, 1000), Some(total));
    }
}
