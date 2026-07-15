//! Ristretto group helpers, Fiat–Shamir hashing, and a bounded discrete-log
//! decoder for exponential-ElGamal tally decoding.
//!
//! The group and scalar arithmetic are provided by `curve25519-dalek` (a real,
//! audited library). Nothing here re-implements a primitive under test.

use curve25519_dalek::constants::{RISTRETTO_BASEPOINT_POINT, RISTRETTO_BASEPOINT_TABLE};
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use sha2::{Digest, Sha512};
use std::collections::HashMap;

/// The fixed generator G for the whole system.
#[inline]
pub fn g() -> RistrettoPoint {
    RISTRETTO_BASEPOINT_POINT
}

/// Fast multiplication of the fixed generator, `s * G`, using dalek's
/// precomputed basepoint table. Same result as `s * g()`, just faster — used on
/// the hot path so the harness runs at N = 10k / 1M in reasonable time.
#[inline]
pub fn g_mul(s: &Scalar) -> RistrettoPoint {
    RISTRETTO_BASEPOINT_TABLE * s
}

/// Fiat–Shamir: hash an arbitrary transcript of points/scalars into a scalar.
pub fn hash_to_scalar(label: &[u8], points: &[RistrettoPoint], scalars: &[Scalar]) -> Scalar {
    let mut h = Sha512::new();
    h.update(label);
    for p in points {
        h.update(p.compress().to_bytes());
    }
    for s in scalars {
        h.update(s.to_bytes());
    }
    let digest = h.finalize();
    let mut wide = [0u8; 64];
    wide.copy_from_slice(&digest);
    Scalar::from_bytes_mod_order_wide(&wide)
}

/// Encode/decode helpers for serde transcripts.
pub fn point_to_hex(p: &RistrettoPoint) -> String {
    hex::encode(p.compress().to_bytes())
}

pub fn point_from_hex(s: &str) -> Option<RistrettoPoint> {
    let bytes = hex::decode(s).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    CompressedRistretto(arr).decompress()
}

pub fn scalar_to_hex(s: &Scalar) -> String {
    hex::encode(s.to_bytes())
}

pub fn scalar_from_hex(s: &str) -> Option<Scalar> {
    let bytes = hex::decode(s).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Option::from(Scalar::from_canonical_bytes(arr))
}

/// Baby-step / giant-step discrete log for a *bounded* exponent.
///
/// Solves `target = m * G` for `0 <= m <= max`. Used only to decode the final
/// homomorphic tally, whose value is bounded by the number of ballots. Returns
/// `None` if no such `m <= max` exists (e.g. a tampered/incorrectly-combined
/// ciphertext) — that `None` is itself a falsification signal.
pub fn bounded_dlog(target: RistrettoPoint, max: u64) -> Option<u64> {
    if target == RistrettoPoint::default() {
        return Some(0);
    }
    let n = (max as f64).sqrt().ceil() as u64 + 1;
    // Baby steps: table[j*G] = j for j in 0..n
    let mut table: HashMap<[u8; 32], u64> = HashMap::with_capacity(n as usize);
    let mut acc = RistrettoPoint::default();
    for j in 0..=n {
        table.insert(acc.compress().to_bytes(), j);
        acc += g();
    }
    // Giant steps: target - i*(n*G)
    let ng = Scalar::from(n) * g();
    let mut gamma = target;
    for i in 0..=n {
        if let Some(&j) = table.get(&gamma.compress().to_bytes()) {
            let m = i * n + j;
            if m <= max {
                return Some(m);
            }
        }
        gamma -= ng;
    }
    None
}

/// Map a small integer to a group element m*G (exponential encoding).
#[inline]
pub fn encode_u64(m: u64) -> RistrettoPoint {
    g_mul(&Scalar::from(m))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dlog_roundtrip() {
        for &m in &[0u64, 1, 2, 999, 12345, 100_000] {
            let p = encode_u64(m);
            assert_eq!(bounded_dlog(p, 200_000), Some(m), "m={m}");
        }
    }

    #[test]
    fn dlog_rejects_out_of_range() {
        let p = encode_u64(500);
        assert_eq!(bounded_dlog(p, 100), None);
    }
}
