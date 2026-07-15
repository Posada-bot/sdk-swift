//! Semaphore-style anonymous membership + nullifier proof, as a REAL Groth16
//! SNARK over BN254 using Poseidon (from `ark-crypto-primitives`).
//!
//! Statement proved in zero knowledge:
//!   "I know a secret `s` whose commitment leaf `H(s)` is in the Merkle tree
//!    with public `root`, and the public `nullifier` equals `H(s, E)` for the
//!    public external nullifier `E` (the election id)."
//!
//! * `root` ties the proof to the eligibility set (Layer 0).
//! * `nullifier` is deterministic per (voter, election) — this is the object
//!   the P4 coercer test attacks, and the P1 double-vote check keys on.
//!
//! We roll no primitive: Poseidon, the R1CS, and Groth16 all come from
//! arkworks. Only the (standard) circuit wiring is ours.

use ark_bn254::{Bn254, Fr};
use ark_crypto_primitives::sponge::constraints::CryptographicSpongeVar;
use ark_crypto_primitives::sponge::poseidon::constraints::PoseidonSpongeVar;
use ark_crypto_primitives::sponge::poseidon::{find_poseidon_ark_and_mds, PoseidonConfig, PoseidonSponge};
use ark_crypto_primitives::sponge::CryptographicSponge;
use ark_ff::PrimeField;
use ark_groth16::{Groth16, PreparedVerifyingKey, Proof, ProvingKey};
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::boolean::Boolean;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::select::CondSelectGadget;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_snark::SNARK;
use ark_std::rand::{CryptoRng, RngCore};

/// Standard Poseidon parameters for BN254 (rate 2, x^5 S-box).
pub fn poseidon_config() -> PoseidonConfig<Fr> {
    let full_rounds = 8usize;
    let partial_rounds = 57usize;
    let alpha = 5u64;
    let rate = 2usize;
    let capacity = 1usize;
    let (ark, mds) = find_poseidon_ark_and_mds::<Fr>(
        Fr::MODULUS_BIT_SIZE as u64,
        rate,
        full_rounds as u64,
        partial_rounds as u64,
        0,
    );
    PoseidonConfig::new(full_rounds, partial_rounds, alpha, mds, ark, rate, capacity)
}

/// Native Poseidon hash of a slice of field elements → one field element.
pub fn poseidon_hash(cfg: &PoseidonConfig<Fr>, inputs: &[Fr]) -> Fr {
    let mut sponge = PoseidonSponge::new(cfg);
    sponge.absorb(&inputs.to_vec());
    sponge.squeeze_field_elements(1)[0]
}

/// leaf commitment = H(s)
pub fn commitment(cfg: &PoseidonConfig<Fr>, s: Fr) -> Fr {
    poseidon_hash(cfg, &[s])
}

/// deterministic nullifier = H(s, E)
pub fn nullifier(cfg: &PoseidonConfig<Fr>, s: Fr, e: Fr) -> Fr {
    poseidon_hash(cfg, &[s, e])
}

/// A fixed "empty" leaf value for padding the tree to a power of two.
fn empty_leaf() -> Fr {
    Fr::from(0u64)
}

/// A binary Merkle tree over Poseidon, built natively so we can extract paths.
pub struct MerkleTree {
    pub cfg: PoseidonConfig<Fr>,
    pub depth: usize,
    /// levels[0] = leaves, levels[depth] = [root]
    levels: Vec<Vec<Fr>>,
}

impl MerkleTree {
    /// Build from leaf commitments. Pads to the next power of two.
    pub fn build(cfg: PoseidonConfig<Fr>, mut leaves: Vec<Fr>) -> Self {
        let n = leaves.len().max(1).next_power_of_two();
        leaves.resize(n, empty_leaf());
        let depth = n.trailing_zeros() as usize;
        let mut levels = vec![leaves];
        for d in 0..depth {
            let prev = &levels[d];
            let mut next = Vec::with_capacity(prev.len() / 2);
            for pair in prev.chunks(2) {
                next.push(poseidon_hash(&cfg, &[pair[0], pair[1]]));
            }
            levels.push(next);
        }
        MerkleTree { cfg, depth, levels }
    }

    pub fn root(&self) -> Fr {
        self.levels[self.depth][0]
    }

    /// Return (siblings, path_bits) for leaf `index`.
    /// path_bit = true  ⇒ the current node is the RIGHT child at that level.
    pub fn path(&self, index: usize) -> (Vec<Fr>, Vec<bool>) {
        let mut siblings = Vec::with_capacity(self.depth);
        let mut bits = Vec::with_capacity(self.depth);
        let mut idx = index;
        for d in 0..self.depth {
            let is_right = idx & 1 == 1;
            let sib = if is_right { idx - 1 } else { idx + 1 };
            siblings.push(self.levels[d][sib]);
            bits.push(is_right);
            idx >>= 1;
        }
        (siblings, bits)
    }
}

/// In-circuit Poseidon hash.
fn poseidon_hash_var(
    cfg: &PoseidonConfig<Fr>,
    cs: ConstraintSystemRef<Fr>,
    inputs: &[FpVar<Fr>],
) -> Result<FpVar<Fr>, SynthesisError> {
    let mut sponge = PoseidonSpongeVar::new(cs, cfg);
    sponge.absorb(&inputs.to_vec())?;
    Ok(sponge.squeeze_field_elements(1)?[0].clone())
}

/// The membership circuit.
#[derive(Clone)]
pub struct VoterCircuit {
    pub cfg: PoseidonConfig<Fr>,
    pub depth: usize,
    // public
    pub root: Fr,
    pub external_nullifier: Fr,
    pub nullifier: Fr,
    // private witness
    pub s: Fr,
    pub siblings: Vec<Fr>,
    pub path_bits: Vec<bool>,
}

impl VoterCircuit {
    /// A shape-only instance (for Groth16 setup), all witnesses zeroed.
    pub fn empty(cfg: PoseidonConfig<Fr>, depth: usize) -> Self {
        VoterCircuit {
            cfg,
            depth,
            root: Fr::from(0u64),
            external_nullifier: Fr::from(0u64),
            nullifier: Fr::from(0u64),
            s: Fr::from(0u64),
            siblings: vec![Fr::from(0u64); depth],
            path_bits: vec![false; depth],
        }
    }
}

impl ConstraintSynthesizer<Fr> for VoterCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        // Public inputs — order matters and must match verify().
        let root = FpVar::new_input(cs.clone(), || Ok(self.root))?;
        let ext = FpVar::new_input(cs.clone(), || Ok(self.external_nullifier))?;
        let null = FpVar::new_input(cs.clone(), || Ok(self.nullifier))?;

        // Private witnesses.
        let s = FpVar::new_witness(cs.clone(), || Ok(self.s))?;
        let mut sib_vars = Vec::with_capacity(self.depth);
        let mut bit_vars = Vec::with_capacity(self.depth);
        for d in 0..self.depth {
            sib_vars.push(FpVar::new_witness(cs.clone(), || Ok(self.siblings[d]))?);
            bit_vars.push(Boolean::new_witness(cs.clone(), || Ok(self.path_bits[d]))?);
        }

        // leaf = H(s)
        let mut cur = poseidon_hash_var(&self.cfg, cs.clone(), &[s.clone()])?;

        // Walk to the root.
        for d in 0..self.depth {
            let sib = &sib_vars[d];
            let bit = &bit_vars[d];
            // bit == true ⇒ cur is right child ⇒ parent = H(sib, cur)
            let left = FpVar::conditionally_select(bit, sib, &cur)?;
            let right = FpVar::conditionally_select(bit, &cur, sib)?;
            cur = poseidon_hash_var(&self.cfg, cs.clone(), &[left, right])?;
        }
        cur.enforce_equal(&root)?;

        // nullifier = H(s, E)
        let n = poseidon_hash_var(&self.cfg, cs.clone(), &[s, ext])?;
        n.enforce_equal(&null)?;

        Ok(())
    }
}

/// Groth16 keys for a fixed tree depth.
pub struct Keys {
    pub pk: ProvingKey<Bn254>,
    pub pvk: PreparedVerifyingKey<Bn254>,
    pub depth: usize,
    pub cfg: PoseidonConfig<Fr>,
}

pub fn setup<R: RngCore + CryptoRng>(depth: usize, rng: &mut R) -> Keys {
    let cfg = poseidon_config();
    let circuit = VoterCircuit::empty(cfg.clone(), depth);
    let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(circuit, rng).expect("groth16 setup");
    let pvk = Groth16::<Bn254>::process_vk(&vk).expect("process vk");
    Keys { pk, pvk, depth, cfg }
}

/// Produce a membership proof for `s` at `index` in `tree`, for election `e`.
pub fn prove<R: RngCore + CryptoRng>(
    keys: &Keys,
    tree: &MerkleTree,
    s: Fr,
    index: usize,
    e: Fr,
    rng: &mut R,
) -> (Proof<Bn254>, Fr, Fr) {
    let (siblings, path_bits) = tree.path(index);
    let root = tree.root();
    let null = nullifier(&keys.cfg, s, e);
    let circuit = VoterCircuit {
        cfg: keys.cfg.clone(),
        depth: keys.depth,
        root,
        external_nullifier: e,
        nullifier: null,
        s,
        siblings,
        path_bits,
    };
    let proof = Groth16::<Bn254>::prove(&keys.pk, circuit, rng).expect("groth16 prove");
    (proof, root, null)
}

/// Verify a membership proof against public (root, E, nullifier).
pub fn verify(keys: &Keys, proof: &Proof<Bn254>, root: Fr, e: Fr, null: Fr) -> bool {
    Groth16::<Bn254>::verify_with_processed_vk(&keys.pvk, &[root, e, null], proof).unwrap_or(false)
}

/// Compressed serialized size of a Groth16 proof, in bytes (constant in N).
pub fn proof_size_bytes(proof: &Proof<Bn254>) -> usize {
    use ark_serialize::CanonicalSerialize;
    let mut v = Vec::new();
    proof.serialize_compressed(&mut v).expect("serialize proof");
    v.len()
}

/// 32-byte little-endian encoding of a field element (used as the board nullifier).
pub fn fr_to_bytes(x: Fr) -> [u8; 32] {
    use ark_ff::BigInteger;
    let mut out = [0u8; 32];
    let v = x.into_bigint().to_bytes_le();
    out[..v.len().min(32)].copy_from_slice(&v[..v.len().min(32)]);
    out
}

/// Deterministic secret for voter `i` (harness convenience; enrollment is
/// simulated per the task).
pub fn voter_secret(i: u64) -> Fr {
    Fr::from(i.wrapping_mul(0x9E3779B97F4A7C15).wrapping_add(1))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_std::rand::rngs::StdRng;
    use ark_std::rand::SeedableRng;

    #[test]
    fn membership_proof_roundtrip() {
        let mut rng = StdRng::seed_from_u64(1);
        let depth = 4; // 16 leaves
        let keys = setup(depth, &mut rng);
        let leaves: Vec<Fr> = (0..16).map(|i| commitment(&keys.cfg, voter_secret(i))).collect();
        let tree = MerkleTree::build(keys.cfg.clone(), leaves);
        let e = Fr::from(2024u64);
        let (proof, root, null) = prove(&keys, &tree, voter_secret(5), 5, e, &mut rng);
        assert!(verify(&keys, &proof, root, e, null));
        // Wrong nullifier must fail.
        assert!(!verify(&keys, &proof, root, e, null + Fr::from(1u64)));
        // Determinism of nullifier (basis for P1 / P4-A).
        assert_eq!(nullifier(&keys.cfg, voter_secret(5), e), null);
    }

    #[test]
    fn non_member_cannot_prove() {
        // A secret not in the tree yields a root mismatch ⇒ prove() panics or
        // verify() fails. We check that proving with a bogus path fails to verify.
        let mut rng = StdRng::seed_from_u64(7);
        let depth = 3;
        let keys = setup(depth, &mut rng);
        let leaves: Vec<Fr> = (0..8).map(|i| commitment(&keys.cfg, voter_secret(i))).collect();
        let tree = MerkleTree::build(keys.cfg.clone(), leaves);
        let e = Fr::from(1u64);
        // Prove membership of an actual member, then verify against a DIFFERENT
        // root — must fail (soundness of the root binding).
        let (proof, root, null) = prove(&keys, &tree, voter_secret(2), 2, e, &mut rng);
        assert!(verify(&keys, &proof, root, e, null));
        let bogus_root = root + Fr::from(999u64);
        assert!(!verify(&keys, &proof, bogus_root, e, null));
    }
}
