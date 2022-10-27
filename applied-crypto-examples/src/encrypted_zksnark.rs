//! An example of naive implementations of zksnarks for tutorial purposes
use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT, ristretto::RistrettoPoint, scalar::Scalar,
};
const G: RistrettoPoint = RISTRETTO_BASEPOINT_POINT;

/// Single root of a polynomial
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Root {
    // a in ax+b
    a: Scalar,
    // b in ax+b
    b: Scalar,
}

impl Root {
    /// Create a new root from i64 values
    pub fn new(a: i64, b: i64) -> Result<Self, Error> {
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

    /// Evaluate the root at a given scalar
    pub fn eval(&self, x: &Scalar) -> Scalar {
        self.a * x + self.b
    }
}

/// Object providing an encrypted list of scalars encrypted by multiplying them by an
/// elliptic curve (making them discrete log hard to calculate) and an evaluation of
/// the public roots of the target polynomial that is able to verify prover responses.
pub struct EncryptedChallenge {
    /// List of Ristretto curve points created by multiplying the secret scalar by the
    /// Ristretto basepoint
    pub encrypted_powers: Vec<RistrettoPoint>,
    // Public roots of the target polynomial evaluate at the secret scalar
    ts: Scalar,
}

impl EncryptedChallenge {
    /// Create a new encrypted challenge object
    pub fn new(scalar: &Scalar, target_polynomial: &Polynomial) -> Self {
        let mut power = *scalar;
        let mut encrypted_powers = vec![G, scalar * G];
        let ts = target_polynomial.eval_public_polynomial(scalar);
        for _ in 1..target_polynomial.degree() {
            power *= scalar;
            encrypted_powers.push(power * G); // it1: x^2, it2: x^3, it3: x^4, it4: x^5
        }
        Self {
            encrypted_powers,
            ts,
        }
    }

    /// Verify a prover response by multiplying t(s) the provers calculated curve points
    pub fn verify_response(&self, response: &EncryptedResponse) -> bool {
        self.ts * response.hx == response.px
    }
}

/// Provers calculated curve points created by multiplying the polynomial coefficient
/// scalars by the challenge curve points
pub struct EncryptedResponse {
    /// Evaluation of all polynomial coefficients at the challenge curve points
    pub px: RistrettoPoint,
    /// Evaluation of h(s) = p(s)/t(s) at the challenge curve points
    pub hx: RistrettoPoint,
}

impl EncryptedResponse {
    /// New encrypted response object
    pub fn new(px: RistrettoPoint, hx: RistrettoPoint) -> Self {
        Self { px, hx }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error {
    /// Proposed roots would result in a polynomial with coefficients in the rational field
    OutsideIntegerField(i64, i64),
    /// Either no public roots were set, or all roots were set to public
    InvalidPublicRoots(usize),
}

/// Polynomial with coefficients in the field of 2^255-19 which prover can prove knowledge of
#[derive(Clone, Debug)]
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

    /// Get degree of polynomial
    pub fn degree(&self) -> usize {
        self.roots.len()
    }

    /// calculate encrypted polynomial
    pub fn generate_response(&self, powers: &EncryptedChallenge) -> EncryptedResponse {
        let px = self.eval(powers, &self.coefficients);
        let hx = self.eval(powers, &self.hidden_coefficients);
        EncryptedResponse::new(px, hx)
    }

    /// Evaluate polynomial at given encrypted powers
    fn eval(&self, powers: &EncryptedChallenge, coefficients: &Vec<Scalar>) -> RistrettoPoint {
        powers
            .encrypted_powers
            .iter()
            .zip(coefficients.iter())
            .map(|(p, c)| p * c)
            .sum()
    }

    /// Evaluate public polynomial at given scalar
    pub fn eval_public_polynomial(&self, scalar: &Scalar) -> Scalar {
        self.roots[0..self.num_public_roots]
            .to_vec()
            .iter()
            .fold(Scalar::one(), |acc, root| acc * root.eval(scalar))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypted_polynomial_roots_must_divide() {
        assert_eq!(Root::new(2, 1), Err(Error::OutsideIntegerField(2, 1)));
    }

    #[test]
    fn test_encrypted_powers_calculate_correctly() {
        let roots = vec![
            Root::new(1, 2).unwrap(),
            Root::new(3, 6).unwrap(),
            Root::new(2, 4).unwrap(),
            Root::new(1, 6).unwrap(),
            Root::new(2, 6).unwrap(),
        ];

        let polynomial = Polynomial::new(roots, 2).unwrap();
        let scalar = Scalar::from(5u64);
        let powers = EncryptedChallenge::new(&scalar, &polynomial);

        // Check encrypted powers match expected curve points
        assert_eq!(powers.encrypted_powers.len(), 6);
        assert_eq!(powers.encrypted_powers[0], G);
        assert_eq!(powers.encrypted_powers[1], Scalar::from(5u64) * G);
        assert_eq!(powers.encrypted_powers[2], Scalar::from(25u64) * G);
        assert_eq!(powers.encrypted_powers[3], Scalar::from(125u64) * G);
        assert_eq!(powers.encrypted_powers[4], Scalar::from(625u64) * G);
        assert_eq!(powers.encrypted_powers[5], Scalar::from(3125u64) * G);
    }

    #[test]
    fn test_encrypted_polynomial_evaluates_correctly() {
        let roots = vec![
            Root::new(1, 2).unwrap(),
            Root::new(3, 6).unwrap(),
            Root::new(2, 4).unwrap(),
        ];

        let polynomial = Polynomial::new(roots, 2).unwrap();
        let scalar = Scalar::from(5u64);
        let challenge = EncryptedChallenge::new(&scalar, &polynomial);
        let response = polynomial.generate_response(&challenge);

        // Check encrypted polynomial evaluates to expected curve point
        assert_eq!(polynomial.degree(), 3);
        assert_eq!(response.px, Scalar::from(2058u64) * G);
    }

    #[test]
    fn test_encrypted_polynomial_challenge_response() {
        let roots = vec![
            Root::new(1, 2).unwrap(),
            Root::new(3, 6).unwrap(),
            Root::new(2, 4).unwrap(),
        ];

        let roots2 = vec![
            Root::new(1, 2).unwrap(),
            Root::new(3, -6).unwrap(),
            Root::new(2, 4).unwrap(),
        ];

        let scalar = Scalar::from(5u64);
        let scalar2 = Scalar::from(10u64);
        let scalar3 = Scalar::from(15u64);

        let polynomial = Polynomial::new(roots, 2).unwrap();
        let polynomial2 = Polynomial::new(roots2, 2).unwrap();
        let challenge = EncryptedChallenge::new(&scalar, &polynomial);
        let challenge2 = EncryptedChallenge::new(&scalar2, &polynomial);
        let challenge3 = EncryptedChallenge::new(&scalar3, &polynomial);
        let challenge4 = EncryptedChallenge::new(&scalar3, &polynomial2);

        let response = polynomial.generate_response(&challenge);
        let response2 = polynomial.generate_response(&challenge2);
        let response3 = polynomial.generate_response(&challenge3);
        let response4 = polynomial2.generate_response(&challenge4);

        // Check that response from prover matches
        assert!(challenge.verify_response(&response));
        assert!(challenge2.verify_response(&response2));
        assert!(challenge3.verify_response(&response3));
        assert!(challenge4.verify_response(&response4));
    }
}
