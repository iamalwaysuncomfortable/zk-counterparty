use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
use curve25519_dalek_ng::ristretto::CompressedRistretto;
use curve25519_dalek_ng::scalar::Scalar;
use lazy_static::lazy_static;
use merlin::Transcript;

lazy_static!(
    /// Generators (base points) for Bulletproofs.
    /// The `party_capacity` is the maximum number of values in one proof. It should
    /// be at least 2 * MAX_INPUTS + MAX_OUTPUTS, which allows for inputs, pseudo outputs, and outputs.
    pub static ref BP_GENERATORS: BulletproofGens =
        BulletproofGens::new(64, 64);
);

pub fn create_range_proof(values: &[u64], n: usize, transcript: &mut Transcript) -> (RangeProof, Vec<CompressedRistretto>)  {
    let v = values.len();
    let blindings = vec![Scalar::random(&mut rand::thread_rng()); v];
    let pedersen_generators = PedersenGens::default();
    RangeProof::prove_multiple(
        &BP_GENERATORS,
        &pedersen_generators,
        transcript,
        values,
        &blindings,
        n
    )
    .unwrap()
}

pub fn verify_range_proof(proof: &RangeProof, commitments: &[CompressedRistretto], n: usize, transcript: &mut Transcript) -> bool {
    let pedersen_generators = PedersenGens::default();
    proof
        .verify_multiple(
            &BP_GENERATORS,
            &pedersen_generators,
            transcript,
            commitments,
            n
        )
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_range_proof() {
        let values = vec![0, 1, 2, 3, 4, 5, 6, 7];
        let mut transcript = Transcript::new(b"RangeProof");
        let mut transcript2 = Transcript::new(b"RangeProof");
        let (proof, commitments) = create_range_proof(&values, 16, &mut transcript);
        assert!(verify_range_proof(&proof, &commitments,16, &mut transcript2));
    }
}