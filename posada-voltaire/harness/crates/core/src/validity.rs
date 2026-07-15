//! Ballot validity proofs (Helios-style), proving "exactly one valid choice"
//! without revealing which. Real sigma protocols over the ElGamal group:
//!   * each option ciphertext encrypts a bit (disjunctive Chaum–Pedersen: 0 or 1)
//!   * the homomorphic sum of the option ciphertexts encrypts exactly 1
//!
//! No SNARK is needed for validity; the Semaphore-style *membership* proof
//! (separate `voltaire-zk` crate) is where the real SNARK lives.

use crate::elgamal::{encrypt, Ciphertext, CiphertextHex, PublicKey};
use crate::group::{g, g_mul, hash_to_scalar, scalar_from_hex, scalar_to_hex};
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

/// Disjunctive proof that one ciphertext encrypts 0 or 1.
#[derive(Clone, Copy, Debug)]
pub struct BitProof {
    pub e0: Scalar,
    pub z0: Scalar,
    pub e1: Scalar,
    pub z1: Scalar,
}

/// Chaum–Pedersen equality-of-DL proof (used for the "sum == 1" clause).
#[derive(Clone, Copy, Debug)]
pub struct CpEq {
    pub e: Scalar,
    pub z: Scalar,
}

#[derive(Clone, Debug)]
pub struct BallotProof {
    pub bits: Vec<BitProof>,
    pub sum_one: CpEq,
}

fn bit_challenge(pk: &PublicKey, ct: &Ciphertext, t: &[RistrettoPoint; 4]) -> Scalar {
    hash_to_scalar(
        b"voltaire/bit",
        &[pk.0, ct.c1, ct.c2, t[0], t[1], t[2], t[3]],
        &[],
    )
}

fn prove_bit<R: RngCore + CryptoRng>(pk: &PublicKey, ct: &Ciphertext, r: Scalar, b: u64, rng: &mut R) -> BitProof {
    // Targets for the two CP statements (bases are G and pk):
    //   branch 0: (A0,B0) = (c1, c2)         [encrypts 0]
    //   branch 1: (A1,B1) = (c1, c2 - G)     [encrypts 1]
    let a = [ct.c1, ct.c1];
    let bpt = [ct.c2, ct.c2 - g()];
    let real = b as usize;
    let fake = 1 - real;

    // Simulate the fake branch.
    let e_fake = Scalar::random(rng);
    let z_fake = Scalar::random(rng);
    let tf1 = g_mul(&z_fake) - e_fake * a[fake];
    let tf2 = z_fake * pk.0 - e_fake * bpt[fake];

    // Commit the real branch.
    let w = Scalar::random(rng);
    let tr1 = g_mul(&w);
    let tr2 = w * pk.0;

    // Order commitments by branch index for the hash.
    let mut t = [RistrettoPoint::default(); 4];
    t[real * 2] = tr1;
    t[real * 2 + 1] = tr2;
    t[fake * 2] = tf1;
    t[fake * 2 + 1] = tf2;

    let e = bit_challenge(pk, ct, &t);
    let e_real = e - e_fake;
    let z_real = w + e_real * r;

    let mut es = [Scalar::ZERO; 2];
    let mut zs = [Scalar::ZERO; 2];
    es[real] = e_real;
    zs[real] = z_real;
    es[fake] = e_fake;
    zs[fake] = z_fake;

    BitProof {
        e0: es[0],
        z0: zs[0],
        e1: es[1],
        z1: zs[1],
    }
}

fn verify_bit(pk: &PublicKey, ct: &Ciphertext, proof: &BitProof) -> bool {
    let a = [ct.c1, ct.c1];
    let bpt = [ct.c2, ct.c2 - g()];
    let es = [proof.e0, proof.e1];
    let zs = [proof.z0, proof.z1];
    let mut t = [RistrettoPoint::default(); 4];
    for i in 0..2 {
        t[i * 2] = g_mul(&zs[i]) - es[i] * a[i];
        t[i * 2 + 1] = zs[i] * pk.0 - es[i] * bpt[i];
    }
    let e = bit_challenge(pk, ct, &t);
    e == proof.e0 + proof.e1
}

fn sum_one_challenge(pk: &PublicKey, csum: &Ciphertext, t1: RistrettoPoint, t2: RistrettoPoint) -> Scalar {
    let b = csum.c2 - g();
    hash_to_scalar(b"voltaire/sumone", &[pk.0, csum.c1, b, t1, t2], &[])
}

fn prove_sum_one<R: RngCore + CryptoRng>(pk: &PublicKey, csum: &Ciphertext, rsum: Scalar, rng: &mut R) -> CpEq {
    // Prove (csum.c1, csum.c2 - G) is a DH pair under (G, pk): witness rsum.
    let w = Scalar::random(rng);
    let t1 = g_mul(&w);
    let t2 = w * pk.0;
    let e = sum_one_challenge(pk, csum, t1, t2);
    let z = w + e * rsum;
    CpEq { e, z }
}

fn verify_sum_one(pk: &PublicKey, csum: &Ciphertext, proof: &CpEq) -> bool {
    let a = csum.c1;
    let b = csum.c2 - g();
    let t1 = g_mul(&proof.z) - proof.e * a;
    let t2 = proof.z * pk.0 - proof.e * b;
    let e = sum_one_challenge(pk, csum, t1, t2);
    e == proof.e
}

/// Construct a valid ballot for `choice` among `k` options and its proof.
pub fn prove_ballot<R: RngCore + CryptoRng>(
    pk: &PublicKey,
    choice: usize,
    k: usize,
    rng: &mut R,
) -> (Vec<Ciphertext>, BallotProof) {
    assert!(choice < k);
    let mut cts = Vec::with_capacity(k);
    let mut rs = Vec::with_capacity(k);
    for i in 0..k {
        let m = (i == choice) as u64;
        let (ct, r) = encrypt(pk, m, rng);
        cts.push(ct);
        rs.push(r);
    }
    let bits: Vec<BitProof> = (0..k)
        .map(|i| prove_bit(pk, &cts[i], rs[i], (i == choice) as u64, rng))
        .collect();
    let csum = cts.iter().fold(Ciphertext::identity(), |acc, c| acc.add(c));
    let rsum = rs.iter().fold(Scalar::ZERO, |acc, r| acc + r);
    let sum_one = prove_sum_one(pk, &csum, rsum, rng);
    (cts, BallotProof { bits, sum_one })
}

/// Verify a ballot: k bit proofs + the sum==1 proof. This is the "exactly one
/// valid choice" guarantee.
pub fn verify_ballot(pk: &PublicKey, cts: &[Ciphertext], proof: &BallotProof) -> bool {
    if cts.len() != proof.bits.len() || cts.is_empty() {
        return false;
    }
    for (ct, bp) in cts.iter().zip(proof.bits.iter()) {
        if !verify_bit(pk, ct, bp) {
            return false;
        }
    }
    let csum = cts.iter().fold(Ciphertext::identity(), |acc, c| acc.add(c));
    verify_sum_one(pk, &csum, &proof.sum_one)
}

// ---- serde encodings for the on-disk transcript ----

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BallotProofHex {
    pub cts: Vec<CiphertextHex>,
    pub bits: Vec<[String; 4]>,
    pub sum_one: [String; 2],
}

pub fn encode_ballot(cts: &[Ciphertext], proof: &BallotProof) -> BallotProofHex {
    BallotProofHex {
        cts: cts.iter().map(|c| c.to_hex()).collect(),
        bits: proof
            .bits
            .iter()
            .map(|b| {
                [
                    scalar_to_hex(&b.e0),
                    scalar_to_hex(&b.z0),
                    scalar_to_hex(&b.e1),
                    scalar_to_hex(&b.z1),
                ]
            })
            .collect(),
        sum_one: [scalar_to_hex(&proof.sum_one.e), scalar_to_hex(&proof.sum_one.z)],
    }
}

pub fn decode_ballot(enc: &BallotProofHex) -> Option<(Vec<Ciphertext>, BallotProof)> {
    let cts: Option<Vec<Ciphertext>> = enc.cts.iter().map(|c| c.decode()).collect();
    let cts = cts?;
    let mut bits = Vec::with_capacity(enc.bits.len());
    for b in &enc.bits {
        bits.push(BitProof {
            e0: scalar_from_hex(&b[0])?,
            z0: scalar_from_hex(&b[1])?,
            e1: scalar_from_hex(&b[2])?,
            z1: scalar_from_hex(&b[3])?,
        });
    }
    let sum_one = CpEq {
        e: scalar_from_hex(&enc.sum_one[0])?,
        z: scalar_from_hex(&enc.sum_one[1])?,
    };
    Some((cts, BallotProof { bits, sum_one }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dkg;
    use rand::rngs::OsRng;

    #[test]
    fn valid_ballot_verifies() {
        let d = dkg::run(3, 5, &mut OsRng);
        for choice in 0..3 {
            let (cts, proof) = prove_ballot(&d.public_key, choice, 3, &mut OsRng);
            assert!(verify_ballot(&d.public_key, &cts, &proof), "choice {choice}");
        }
    }

    #[test]
    fn cheating_ballot_two_ones_is_rejected() {
        // Encrypt [1,1,0] and try to pass it off — the sum==1 proof must fail,
        // and honest bit proofs can't be forged for the tampered structure.
        let d = dkg::run(3, 5, &mut OsRng);
        let (c0, r0) = encrypt(&d.public_key, 1, &mut OsRng);
        let (c1, r1) = encrypt(&d.public_key, 1, &mut OsRng);
        let (c2, r2) = encrypt(&d.public_key, 0, &mut OsRng);
        let cts = vec![c0, c1, c2];
        // Attacker builds honest-looking bit proofs (they *are* bits) ...
        let bits = vec![
            prove_bit(&d.public_key, &cts[0], r0, 1, &mut OsRng),
            prove_bit(&d.public_key, &cts[1], r1, 1, &mut OsRng),
            prove_bit(&d.public_key, &cts[2], r2, 0, &mut OsRng),
        ];
        // ... but the sum is 2, so no valid sum==1 proof exists. Attacker tries
        // with the true rsum; verification must reject because sum != 1.
        let csum = cts.iter().fold(Ciphertext::identity(), |a, c| a.add(c));
        let rsum = r0 + r1 + r2;
        let sum_one = prove_sum_one(&d.public_key, &csum, rsum, &mut OsRng);
        let proof = BallotProof { bits, sum_one };
        assert!(!verify_ballot(&d.public_key, &cts, &proof), "double vote must be rejected");
    }
}
