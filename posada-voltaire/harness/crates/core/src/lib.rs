//! Posada Voltaire — falsification harness core library.
//!
//! This crate implements, with real curve/scalar arithmetic from
//! `curve25519-dalek`, the cryptographic machinery whose *correctness claims*
//! the harness tries to break: exponential-ElGamal, joint-Feldman t-of-n DKG,
//! threshold decryption with Chaum–Pedersen proofs, Helios-style ballot
//! validity proofs, an append-only bulletin board, the homomorphic tally, and
//! the JCJ (Variant B) plaintext-equivalence machinery.
//!
//! It deliberately does NOT try to look like a product. Where a property fails,
//! the relevant function returns an error/`None`/`false` rather than papering
//! over it.

pub mod board;
pub mod dkg;
pub mod elgamal;
pub mod govbench;
pub mod group;
pub mod jcj;
pub mod tally;
pub mod threshold;
pub mod validity;
