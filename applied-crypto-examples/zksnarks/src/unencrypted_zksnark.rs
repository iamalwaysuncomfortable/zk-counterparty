//! Simple demonstration of the basic polynomial math behind ZkSnarks

use crate::polynomial::UnencryptedPolynomial;

/// Unencrypted challenge response pair
#[derive(Clone, Debug, Ord, PartialOrd, Eq, PartialEq)]
pub struct UnencryptedChallengeResponse {
    // p(x) = h(x)*t(x)
    px: i64,
    // h(x)
    hx: i64,
}

impl UnencryptedChallengeResponse {
    /// Create new challenge response
    pub fn new(px: i64, hx: i64) -> Self {
        Self { px, hx }
    }

    /// Verify the challenge values provided by the prover match!
    pub fn verify(&self, x: i64, polynomial: &UnencryptedPolynomial) -> bool {
        self.px == self.hx * polynomial.eval(x)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SimpleRoot;

    #[test]
    fn test_unencrypted_proof() {
        let roots = vec![
            SimpleRoot::new(1, 2).unwrap(),
            SimpleRoot::new(3, 6).unwrap(),
            SimpleRoot::new(2, 4).unwrap(),
        ];
        let polynomial = UnencryptedPolynomial::new(roots).set_public_roots(2);
        let challenge_polynomial = polynomial.get_public_polynomial().unwrap();

        let challenge_one = 40;
        let challenge_two = 100;
        let challenge_three = 200;

        let polynomial_response_one = polynomial.answer_challenge(challenge_one);
        let polynomial_response_two = polynomial.answer_challenge(challenge_two);
        let polynomial_response_three = polynomial.answer_challenge(challenge_three);

        assert!(polynomial_response_one.verify(challenge_one, &challenge_polynomial));
        assert!(polynomial_response_two.verify(challenge_two, &challenge_polynomial));
        assert!(polynomial_response_three.verify(challenge_three, &challenge_polynomial));
    }
}
