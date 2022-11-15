//! An example of ZkSnarks math for demonstration purposes, not intended for production use

use crate::polynomial::Polynomial;
use bls12_381::{G1Affine, G1Projective, G2Affine, G2Projective, Scalar};
use ff::Field;

/// Collection of the prover's calculated curve points. These curve points
/// are calculated by multiplying the polynomial coefficients by the verifier's
/// challenge points (which equate to repeated additions of the provided points)
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProverTranscript {
    // Evaluation of the prover's polynomial at the verifier's challenge point
    px_eval: G1Affine,
    // Evaluation of the prover's polynomial at the verifier's power shifted
    // challenge points
    px_powers_eval: G1Affine,
    // Evaluation of the non-public roots of the prover's polynomial at the
    // verifier's challenge points
    hx_eval: G1Affine,
}

impl ProverTranscript {
    // Create a new proof transcript
    pub(crate) fn new(px_eval: G1Affine, px_powers_eval: G1Affine, hx_eval: G1Affine) -> Self {
        Self {
            px_eval,
            px_powers_eval,
            hx_eval,
        }
    }

    /// Get prover's evaluation of the polynomial at the challenge points and shifted
    /// challenge points. All points returned are in the BLS12-381 prime subgroup over
    /// a 381-bit prime field represented by the [`G1Affine`]
    ///
    /// # Returns
    /// A tuple of the form ([`p(s)`](G1Affine), [`p(s_shifted)`](G1Affine), [`h(s)`](G1Affine)) where
    /// p(s) = evaluation of the prover's polynomial at the verifier's challenge points
    /// p(s_shifted) = evaluation of the prover's polynomial at the verifier's shifted challenge points
    /// h(s) = evaluation of the hidden roots of the prover's polynomial at the verifier's challenge points
    pub fn get_proof_values(&self) -> (G1Affine, G1Affine, G1Affine) {
        (self.px_eval, self.px_powers_eval, self.hx_eval)
    }
}

/// Verifier's transcript providing a secret scalar raised to powers equal to the degree of the
/// polynomial the prover claims to have for the prover to evaluate in order to prove knowledge
/// of their polynomial
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifierTranscript {
    // List of BLS12-381 prime subgroup points created by multiplying the secret scalar
    // by the subgroup generator
    encrypted_powers: Vec<G1Projective>,
    // List of BLS12-381 prime subgroup points curve points created by shifting the
    // encrypted powers by a secret scalar and multiplying them by the subgroup generator
    shifted_powers: Vec<G1Projective>,
    // A BLS12-381 (prime subgroup) point multiplied by the scalar resulting from the
    // evaluation of the public roots of the prover's polynomial. This point is used
    // to verify the prover's evaluation of the polynomial at the verifier's challenge
    // points non-interactively through the use of the pairing operation. This point
    // is calculated using the extension field of the BLS12-381 curve.
    public_root_verification_key: G2Affine,
    // A BLS12-381 (prime subgroup) point multiplied by the secret shift scalar. This
    // point is used to verify the prover's evaluation of the polynomial at the shifted
    // challenge points through the pairing operation. This point is calculated using the
    // extension field of the BLS12-381 curve.
    power_verification_key: G2Affine,
}

impl VerifierTranscript {
    /// Create a verifier transcript from the prover's polynomial degree and public roots
    pub fn new(target_polynomial: &Polynomial) -> Self {
        let mut rng = rand::thread_rng();
        let shift = Scalar::random(&mut rng);
        let scalar = Scalar::random(&mut rng);
        let G2 = G2Projective::generator();
        let (encrypted_powers, shifted_powers) =
            Self::calculate_encrypted_powers(&scalar, &shift, target_polynomial.degree());
        let public_root_verification_key =
            G2Affine::from(G2 * target_polynomial.eval_public_polynomial(&scalar));
        let power_verification_key = G2Affine::from(G2 * shift);

        Self {
            encrypted_powers,
            shifted_powers,
            public_root_verification_key,
            power_verification_key,
        }
    }

    // Calculate the encrypted powers using randomly generated scalars
    pub(crate) fn calculate_encrypted_powers(
        scalar: &Scalar,
        shift: &Scalar,
        degree: usize,
    ) -> (Vec<G1Projective>, Vec<G1Projective>) {
        let G1 = G1Projective::generator();
        let mut power = *scalar;
        let mut encrypted_powers = vec![G1, G1 * scalar];
        let mut shifted_powers = vec![G1 * shift, G1 * shift * scalar];
        for _ in 1..degree {
            power *= scalar;
            encrypted_powers.push(G1 * power);
            shifted_powers.push(G1 * (shift * power));
        }
        println!("encrypted_powers: {:?}", encrypted_powers);
        (encrypted_powers, shifted_powers)
    }

    /// Get encrypted powers calculated from the prover's polynomial
    ///
    /// # Returns
    /// A tuple of the form (encrypted_powers, shifted_powers)
    /// `encrypted_powers` is a vector of `G1Projective` curve points created by multiplying
    /// exponents of a secret scalar up to the degree of the prover's claimed polynomial by
    /// the generator of the BLS12-381 prime subgroup over a 381-bit prime field
    /// `shifted_powers` is calculated in the same manner, but includes a multiplication of
    /// secret shift scalar to enforce usage of the
    pub fn get_encrypted_powers(&self) -> (&Vec<G1Projective>, &Vec<G1Projective>) {
        (&self.encrypted_powers, &self.shifted_powers)
    }

    /// Get verification keys used in the pairing operation used to complete non-interactive
    /// verification of the proof
    ///
    /// # Returns
    /// A tuple of the form ([`public_root_verification_key`](G2Affine), [`power_verification_key`](G2Affine))
    /// `public_root_verification_key` is a curve point multiplied by the scalar resulting from
    /// the evaluation of the public roots of the prover's polynomial
    /// `power_verification_key` is a curve point multiplied by the secret shift scalar
    ///
    /// Both verification keys are calculated using the prime subgroup of the BLS12-381 curve
    /// over an extension field of the prime field represented by the `G2Affine` struct
    pub fn get_verification_keys(&self) -> (&G2Affine, &G2Affine) {
        (
            &self.public_root_verification_key,
            &self.power_verification_key,
        )
    }

    /// Verify the prover's reported values against the verifier's challenge points
    /// using the pairing operation.
    ///
    /// This operation is roughly equivalent to the following:
    /// pair(G1*p(s), G2) == pair(G1*h(s), G2*t(s))
    /// pair(G1*p(s_shifted), G2) == pair(G1*p(s), G2*shift)
    ///
    /// The underlying mechanics of the pairing operation are complicated but their
    /// main useful feature is that they allow for already encrypted values to be
    /// compared directly (and homomorphically) allowing for non-interactive verification
    /// to happen without leaking sensitive secrets.
    pub fn verify_proof(&self, proof: &ProverTranscript) -> bool {
        // Get the prover's reported values
        let (px_eval, px_powers_eval, hx_eval) = proof.get_proof_values();

        // Perform the pairing operations to verify the prover's reported evaluations
        // against the verifier's challenge values
        let G2 = G2Affine::generator();
        let pairing_px = bls12_381::pairing(&px_eval, &G2);
        let pairing_px_shifted = bls12_381::pairing(&px_powers_eval, &G2);
        let pairing_hx_tx = bls12_381::pairing(&hx_eval, &self.public_root_verification_key);
        let pairing_px_shift = bls12_381::pairing(&px_eval, &self.power_verification_key);
        (pairing_px == pairing_hx_tx) && (pairing_px_shifted == pairing_px_shift)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Root;

    #[test]
    fn test_encrypted_powers_calculate_correctly() {
        // Create known scalars for the hidden scalar and shift scalar
        let scalar = Scalar::from(5u64);
        let shift = Scalar::from(2u64);
        let (encrypted_powers, shifted_powers) =
            VerifierTranscript::calculate_encrypted_powers(&scalar, &shift, 6);
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

        // Create two polynomials with different roots
        let polynomial = Polynomial::new(roots, 2).unwrap();
        let polynomial_alt = Polynomial::new(roots_alt, 2).unwrap();
        let verifier_transcript = VerifierTranscript::new(&polynomial);

        // Evaluate the polynomials against the verifier's challenge values
        let prover_response = polynomial.generate_response(&verifier_transcript);
        let prover_response_alt = polynomial_alt.generate_response(&verifier_transcript);

        // Ensure only the correct polynomial verifies correctly
        assert!(verifier_transcript.verify_proof(&prover_response));
        assert!(!verifier_transcript.verify_proof(&prover_response_alt));
    }
}
