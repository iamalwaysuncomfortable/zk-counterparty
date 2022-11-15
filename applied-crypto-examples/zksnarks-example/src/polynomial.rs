//! Implementation of Polynomials used for zksnarks

use crate::{
    error::Error,
    encrypted_zksnark::{ProverTranscript, VerifierTranscript},
    unencrypted_zksnark::UnencryptedChallengeResponse,
};
use bls12_381::{G1Projective, Scalar};
use ff::Field;

#[derive(Clone)]
pub struct Root {
    pub a: Scalar,
    pub b: Scalar,
}

impl Root {
    /// Evaluate the root at a given scalar
    pub fn eval(&self, x: &Scalar) -> Scalar {
        x * self.a + self.b
    }
}

impl TryFrom<(i64, i64)> for Root {
    type Error = Error;

    fn try_from((a, b): (i64, i64)) -> Result<Self, Self::Error> {
        if b % a == 0 {
            let mut a_prime = Scalar::from(a.unsigned_abs());
            let mut b_prime = Scalar::from(b.unsigned_abs());
            if a < 0 {
                a_prime = -a_prime;
            }
            if b < 0 {
                b_prime = -b_prime;
            }
            return Ok(Self {
                a: a_prime,
                b: b_prime,
            });
        }
        Err(Error::OutsideIntegerField(a, b))
    }
}

/// Single root of a polynomial
#[derive(Clone)]
pub struct SimpleRoot {
    // a in ax+b
    a: i64,
    // b in ax+b
    b: i64,
}

impl SimpleRoot {
    /// Create new root
    pub fn new(a: i64, b: i64) -> Result<Self, Error> {
        if b % a == 0 {
            return Ok(Self { a, b });
        }
        Err(Error::OutsideIntegerField(a, b))
    }

    /// Evaluate a polynomial root
    pub fn eval(&self, x: i64) -> i64 {
        self.a * x + self.b
    }
}

/// Polynomial with coefficients (in the finite field of integers order 2^255-19)
/// the prover must prove knowledge of
#[derive(Clone)]
pub struct Polynomial {
    // Polynomial roots (a, b) such that a*x + b is a factor of the polynomial
    roots: Vec<Root>,
    // Polynomial coefficients
    coefficients: Vec<Scalar>,
    // Hidden polynomial coefficients (defined by h(x) = p(x)/t(x))
    hidden_coefficients: Vec<Scalar>,
    // Number of public roots
    num_public_roots: usize,
}

impl Polynomial {
    /// Create a new polynomial from a list of roots
    pub fn new(roots: Vec<Root>, num_public_roots: usize) -> Result<Self, Error> {
        if num_public_roots == 0 || num_public_roots == roots.len() {
            return Err(Error::InvalidPublicRoots(num_public_roots));
        }
        let coefficients = Self::combine_roots(&roots[..]);
        let hidden_coefficients = Self::combine_roots(&roots[num_public_roots..]);
        Ok(Self {
            roots,
            coefficients,
            hidden_coefficients,
            num_public_roots,
        })
    }

    // Combine polynomial roots into coefficients
    fn combine_roots(roots: &[Root]) -> Vec<Scalar> {
        let mut coefficients = Vec::new();
        for root in roots.iter() {
            if coefficients.is_empty() {
                coefficients.push(root.a);
                coefficients.push(root.b);
            } else {
                let mut new_coefficients = Vec::new();
                new_coefficients.push(coefficients[0] * root.a);
                for i in 1..coefficients.len() {
                    new_coefficients.push(coefficients[i - 1] * root.b + coefficients[i] * root.a);
                }
                new_coefficients.push(coefficients[coefficients.len() - 1] * root.b);
                coefficients = new_coefficients;
            }
        }
        coefficients.reverse();
        coefficients
    }

    /// Degree of the polynomial
    pub fn degree(&self) -> usize {
        self.roots.len()
    }

    /// Take a verifier challenge and evaluate the polynomial at the encrypted and shifted
    /// powers (in form of <s, s^2, .., s^n> and <shift*s, shift*s^2, .., shift*s^n>
    /// respectively)
    pub fn generate_response(&self, challenge: &VerifierTranscript) -> ProverTranscript {
        // Generate random scalar in order to encrypt the evaluation of the polynomial
        let b = Scalar::random(&mut rand::thread_rng());
        let (encrypted_powers, shifted_powers) = challenge.get_encrypted_powers();

        // Evaluate p(s) = t(s) * h(s) at the encrypted scalars sent by the verifier
        let px_eval = self.eval(encrypted_powers, &self.coefficients, &b).into();

        // Evaluate p(s) = t(s) * h(s) at the encrypted scalars sent by the verifier
        let hx_eval = self.eval(encrypted_powers, &self.hidden_coefficients, &b).into();

        // Evaluate p(s*shift) = t(s*shift) * h(s*shift) at the encrypted & shifted scalars sent by the verifier
        let px_shift_eval = self.eval(shifted_powers, &self.coefficients, &b).into();
        ProverTranscript::new(px_eval, px_shift_eval, hx_eval)
    }

    // Evaluate polynomial at given encrypted powers. The powers provided to this function
    // are in the form of s*G, s^2*G, .., s^n*G where s is a scalar raised to powers and then
    // encrypted by multiplication of the curve generator point G. The result is curve points
    // e1, e2, .., en. To evaluate the polynomial, the scalar polynomial coefficients
    // a1, a2, .., an are multiplied by a blinding scalar `b` and then multiplied by the powers
    // represented by the resulting curve points. The multiplication takes the form of
    // (a1*b)*e1 + (a2*b)*e2 + .. + (an*b)*en and constitutes the proof response which proves
    // knowledge of the polynomial coefficients.
    fn eval(
        &self,
        powers: &[G1Projective],
        coefficients: &[Scalar],
        blinding_scalar: &Scalar,
    ) -> G1Projective {
        powers
            .iter()
            .zip(coefficients.iter())
            .map(|(p, c)| p * (c * blinding_scalar))
            .sum()
    }

    /// Evaluate public polynomial t(s) at given scalar s
    pub fn eval_public_polynomial(&self, scalar: &Scalar) -> Scalar {
        self.roots[0..self.num_public_roots]
            .to_vec()
            .iter()
            .fold(Scalar::one(), |acc, root| acc * root.eval(scalar))
    }
}

/// Polynomial with coefficients restricted to integers within the field of 8-bit signed integers
#[derive(Clone)]
pub struct UnencryptedPolynomial {
    // Polynomial roots (a, b) such that a*x + b is a factor of the polynomial
    roots: Vec<SimpleRoot>,
    // public roots
    public_roots: Vec<SimpleRoot>,
}

impl UnencryptedPolynomial {
    /// Create a new polynomial from a list of roots
    pub fn new(roots: Vec<SimpleRoot>) -> Self {
        Self {
            roots,
            public_roots: Vec::new(),
        }
    }

    /// Set public roots for the polynomial
    pub fn set_public_roots(mut self, num_public: usize) -> Self {
        self.public_roots = self.roots[0..num_public].to_vec();
        self
    }

    /// Get degree of polynomial
    pub fn degree(&self) -> usize {
        self.roots.len()
    }

    /// Create public polynomial from private polynomial
    pub fn get_public_polynomial(&self) -> Result<UnencryptedPolynomial, Error> {
        if self.public_roots.is_empty() {
            return Err(Error::NoPublicRoots);
        }
        Ok(UnencryptedPolynomial::new(self.public_roots.clone()))
    }

    /// Evaluate polynomial at a given point
    pub fn eval(&self, x: i64) -> i64 {
        self.roots.iter().fold(1, |acc, root| acc * root.eval(x))
    }

    /// Given a challenge point, evaluate polynomials h(x) and p(x) at the challenge point
    pub fn answer_challenge(&self, x: i64) -> UnencryptedChallengeResponse {
        let px = self.eval(x);
        let tx = self
            .public_roots
            .iter()
            .fold(1, |acc, root| acc * root.eval(x));
        let hx = px / tx;
        UnencryptedChallengeResponse::new(px, hx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_polynomial_simple_roots_must_divide() {
        assert_eq!(SimpleRoot::new(2, 1).err().unwrap(), Error::OutsideIntegerField(2, 1));
    }

    #[test]
    fn test_polynomial_roots_must_divide() {
        assert_eq!(Root::try_from((2i64, 1i64)).err().unwrap(), Error::OutsideIntegerField(2, 1));
    }

    #[test]
    fn test_polynomial_evaluates_correctly_unencrypted() {
        let roots = vec![
            SimpleRoot::new(1, 2).unwrap(),
            SimpleRoot::new(3, 6).unwrap(),
            SimpleRoot::new(2, 4).unwrap(),
        ];
        let polynomial = UnencryptedPolynomial::new(roots);
        assert_eq!(polynomial.eval(0), 48);
        assert_eq!(polynomial.eval(1), 162);
        assert_eq!(polynomial.eval(2), 384);
        assert_eq!(polynomial.eval(3), 750);
    }
}
