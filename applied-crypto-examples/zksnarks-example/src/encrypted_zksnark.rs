//! An example of ZkSnarks math for demonstration purposes, not intended for production use

use crate::polynomial::Polynomial;
use bls12_381::{G1Affine, G1Projective, G2Affine, G2Projective, Scalar};
use ff::Field;

/// Provers calculated curve points created by multiplying the polynomial coefficient
/// scalars by the challenge curve points
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProverTranscript {
    // Object containing vector of Ristretto curve points created by multiplying
    // the secret scalar, and the shift of the secret scalar by the Ristretto
    // basepoint
    px_eval: G1Affine,
    // Prover's evaluation of their secret polynomial against the challenge values
    // provided by the verifier
    px_powers_eval: G1Affine,
    // provers' evaluation of h(x)
    hx_eval: G1Affine,
}

impl ProverTranscript {
    /// Create a new proof transcript
    pub(crate) fn new(
        px_eval: G1Affine,
        px_powers_eval: G1Affine,
        hx_eval: G1Affine,
    ) -> Self {
        Self { px_eval, px_powers_eval, hx_eval }
    }

    pub fn get_proof_values(&self) -> (G1Affine, G1Affine, G1Affine) {
        (self.px_eval, self.px_powers_eval, self.hx_eval)
    }
}

/// Verifier challenge
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifierTranscript {
    /// List of Ristretto curve points created by multiplying the secret scalar by the
    /// Ristretto basepoint
    encrypted_powers: Vec<G1Projective>,
    /// List of Ristretto curve points created by shifting the encrypted powers by a
    /// secret scalar
    shifted_powers: Vec<G1Projective>,
    /// Scalar proving key
    scalar_verification_key: G2Affine,
    /// Powers proving key
    power_verification_key: G2Affine,
}

impl VerifierTranscript {
    /// Create a list of encrypted powers from a secret scalar. This

    pub fn new(target_polynomial: &Polynomial) -> Self {
        let mut rng = rand::thread_rng();
        let shift = Scalar::random( &mut rng);
        let scalar = Scalar::random( &mut rng);
        let G2 = G2Projective::generator();
        let (encrypted_powers, shifted_powers) = Self::calculate_encrypted_powers(&scalar, &shift, target_polynomial.degree());
        let scalar_verification_key = G2Affine::from(G2 * target_polynomial.eval_public_polynomial(&scalar));
        let power_verification_key = G2Affine::from(G2 * shift);

        Self {
            encrypted_powers,
            shifted_powers,
            scalar_verification_key,
            power_verification_key
        }
    }

    pub(crate) fn calculate_encrypted_powers(scalar: &Scalar, shift: &Scalar, degree: usize) -> (Vec<G1Projective>, Vec<G1Projective>) {
        let G1 = G1Projective::generator();
        let mut power = *scalar;
        let mut encrypted_powers = vec![G1, G1 * scalar];
        let mut shifted_powers = vec![ G1 * shift, G1 * shift * scalar];
        for _ in 1..degree {
            power *= scalar;
            encrypted_powers.push(G1 * power);
            shifted_powers.push(  G1 * (shift * power));
        }
        println!("encrypted_powers: {:?}", encrypted_powers);
        (encrypted_powers, shifted_powers)
    }

    /// Get encrypted powers
    pub fn get_encrypted_powers(&self) -> (&Vec<G1Projective>, &Vec<G1Projective>) {
        (&self.encrypted_powers, &self.shifted_powers)
    }

    /// Get verification keys
    pub fn get_verification_keys(&self) -> (&G2Affine, &G2Affine) {
        (&self.scalar_verification_key, &self.power_verification_key)
    }

    pub fn verify_proof(&self, proof: &ProverTranscript) -> bool {
        let (px_eval, px_powers_eval, hx_eval) = proof.get_proof_values();
        let G1 = G1Affine::generator();
        let G2 = G2Affine::generator();
        let power_projection = bls12_381::pairing(&px_powers_eval, &G2);
        let secret_scalar_projection = bls12_381::pairing(&px_eval, &G2);
        let scalar_mult = bls12_381::pairing(&hx_eval, &self.scalar_verification_key);
        let power_mult = bls12_381::pairing(&px_eval, &self.power_verification_key);
        (power_projection == power_mult) && (secret_scalar_projection == scalar_mult)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Root;

    #[test]
    fn test_encrypted_powers_calculate_correctly() {
        let scalar = Scalar::from(5u64);
        let shift = Scalar::from(2u64);
        let (encrypted_powers, shifted_powers) = VerifierTranscript::calculate_encrypted_powers(&scalar, &shift, 6);
        let G1 = G1Affine::generator();

        // Check encrypted powers match expected curve points
        assert_eq!(encrypted_powers.len(), 7);
        assert_eq!(encrypted_powers[0], G1.into());
        assert_eq!(encrypted_powers[1], G1 * Scalar::from(5u64));
        assert_eq!(encrypted_powers[2], G1 * Scalar::from(25u64));
        assert_eq!(encrypted_powers[3], G1 * Scalar::from(125u64));
        assert_eq!(encrypted_powers[4], G1 * Scalar::from(625u64));
        assert_eq!(encrypted_powers[5], G1 * Scalar::from(3125u64));
        assert_eq!(encrypted_powers[6], G1 * Scalar::from(15625u64));

        // Check shifted powers match expected curve points
        assert_eq!(shifted_powers.len(), 7);
        assert_eq!(shifted_powers[0], G1 * shift);
        assert_eq!(shifted_powers[1], G1 * Scalar::from(2 * 5u64));
        assert_eq!(shifted_powers[2], G1 * Scalar::from(2 * 25u64));
        assert_eq!(shifted_powers[3], G1 * Scalar::from(2 * 125u64));
        assert_eq!(shifted_powers[4], G1 * Scalar::from(2 * 625u64));
        assert_eq!(shifted_powers[5], G1 * Scalar::from(2 * 3125u64));
        assert_eq!(shifted_powers[6], G1 * Scalar::from(2 * 15625u64));
    }

    #[test]
    fn test_encrypted_coefficients_arent_exposed() {
        let roots = vec![
            Root::try_from((1, 2)).unwrap(),
            Root::try_from((3, 6)).unwrap(),
            Root::try_from((2, 4)).unwrap(),
        ];

        let G1 = G1Projective::generator();
        let polynomial = Polynomial::new(roots, 2).unwrap();
        let scalar = Scalar::from(5u64);
        let shift = Scalar::from(2u64);
        let verifier_transcript = VerifierTranscript::new(&polynomial);
        let prover_transcript = polynomial.generate_response(&verifier_transcript);
        let (px, px_shift, hx) = prover_transcript.get_proof_values();

        // Check polynomial is properly shifted and does NOT evaluate to unencrypted coefficients
        assert_eq!(polynomial.degree(), 3);
        assert_ne!(G1Projective::from(px), G1 * Scalar::from(2058u64));
        assert_ne!(G1Projective::from(px_shift), G1 * Scalar::from(4116u64));
    }

    #[test]
    fn test_encrypted_proof_is_correct_and_fails_for_alternate_polynomials() {
        let roots = vec![
            Root::try_from((1, 2)).unwrap(),
            Root::try_from((3, 6)).unwrap(),
            Root::try_from((2, 4)).unwrap(),
            Root::try_from((1, 8)).unwrap(),
            Root::try_from((1, 7)).unwrap(),
        ];

        let roots_alt = vec![
            Root::try_from((1, 2)).unwrap(),
            Root::try_from((4, 12)).unwrap(),
            Root::try_from((1, 5)).unwrap(),
            Root::try_from((1, 3)).unwrap(),
            Root::try_from((1, 4)).unwrap(),
        ];


        let polynomial = Polynomial::new(roots, 2).unwrap();
        let polynomial_alt = Polynomial::new(roots_alt, 2).unwrap();
        let verifier_transcript = VerifierTranscript::new(&polynomial);
        let prover_response = polynomial.generate_response(&verifier_transcript);
        let prover_response_alt = polynomial_alt.generate_response(&verifier_transcript);

        assert!(verifier_transcript.verify_proof(&prover_response));
        assert!(!verifier_transcript.verify_proof(&prover_response_alt));
    }
}
