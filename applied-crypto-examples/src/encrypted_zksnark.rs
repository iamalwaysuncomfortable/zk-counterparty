//! An example of naive implementations of zksnarks for tutorial purposes
use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT, ristretto::RistrettoPoint, scalar::Scalar,
};
const G: RistrettoPoint = RISTRETTO_BASEPOINT_POINT;

/// Single root of a polynomial
#[derive(Clone, Debug, Ord, PartialOrd, Eq, PartialEq)]
pub struct Root {
    // a in ax+b
    a: i64,
    // b in ax+b
    b: i64,
}

impl Root {
    pub fn new(a: i64, b: i64) -> Result<Self, Error> {
        if b % a == 0 {
            return Ok(Self { a, b });
        }
        Err(Error::OutsideIntegerField(a, b))
    }

    pub fn eval(&self, x: i64) -> i64 {
        self.a * x + self.b
    }
}

pub struct EncryptedPowers {
    pub encrypted_powers: Vec<RistrettoPoint>,
}

impl EncryptedPowers {
    pub fn new(degree: usize, scalar: Scalar) -> Self {
        let mut power = scalar;
        let mut encrypted_powers = vec![G, scalar * G];
        for _ in 1..degree {
            power *= scalar;
            encrypted_powers.push(power * G); // it1: x^2, it2: x^3, it3: x^4, it4: x^5
        }
        Self { encrypted_powers }
    }
}

pub struct EncryptedResponse {
    px: RistrettoPoint,
    hx: RistrettoPoint,
}

impl EncryptedResponse {
    pub fn new(px: RistrettoPoint, hx: RistrettoPoint) -> Self {
        Self { px, hx }
    }
    pub fn verify(&self, tx: &Scalar) -> bool {
        tx * self.hx == self.px
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error {
    /// Proposed roots would result in a polynomial with coefficients in the rational field
    OutsideIntegerField(i64, i64),
    /// No public roots set
    NoPublicRoots,
}

/// Polynomial with coefficients restricted to integers within the field of 8-bit signed integers
#[derive(Clone, Debug)]
pub struct Polynomial {
    // Polynomial roots (a, b) such that a*x + b is a factor of the polynomial
    roots: Vec<Root>,
    // Polynomial coefficients
    coefficients: Vec<i64>,
    // Number of public roots
    num_public_roots: usize,
}

impl Polynomial {
    /// Create a new polynomial from a list of roots
    pub fn new(roots: Vec<Root>, num_public_roots: usize) -> Self {
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
        Self {
            roots,
            coefficients,
            num_public_roots,
        }
    }

    /// Get degree of polynomial
    pub fn degree(&self) -> usize {
        self.roots.len()
    }

    /// calculate encrypted polynomial
    pub fn generate_response(&self, powers: &EncryptedPowers) -> EncryptedResponse {
        let px = self.eval(powers);
        let h = Polynomial::new(self.roots[self.num_public_roots..].to_vec(), 0);
        let hx = h.eval(powers);
        EncryptedResponse::new(px, hx)
    }

    pub fn eval(&self, powers: &EncryptedPowers) -> RistrettoPoint {
        powers
            .encrypted_powers
            .iter()
            .zip(self.coefficients.iter())
            .map(|(p, c)| {
                let term = p * Scalar::from(c.unsigned_abs());
                if *c < 0 {
                    return -term;
                }
                term
            })
            .sum()
    }

    /// Create public polynomial from private polynomial
    pub fn eval_public_polynomial(&self, scalar: i64) -> Result<Scalar, Error> {
        if self.num_public_roots == 0 {
            return Err(Error::NoPublicRoots);
        }
        let result = self.roots[0..self.num_public_roots]
            .to_vec()
            .iter()
            .fold(1, |acc, root| acc * root.eval(scalar));
        if result < 0 {
            return Ok(-Scalar::from(result.unsigned_abs()));
        }
        Ok(Scalar::from(result.unsigned_abs()))
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
        let scalar = Scalar::from(5u64);
        let powers = EncryptedPowers::new(5, scalar);
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

        let polynomial = Polynomial::new(roots, 0);
        let scalar = Scalar::from(5u64);
        let powers = EncryptedPowers::new(polynomial.degree() + 1, scalar);

        assert_eq!(polynomial.degree(), 3);
        assert_eq!(polynomial.eval(&powers), Scalar::from(2058u64) * G);
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

        let powers = EncryptedPowers::new(roots.len() + 1, scalar);
        let powers2 = EncryptedPowers::new(roots.len() + 1, scalar2);
        let powers3 = EncryptedPowers::new(roots.len() + 1, scalar3);

        let polynomial = Polynomial::new(roots, 2);
        let polynomial2 = Polynomial::new(roots2, 2);
        let tx = polynomial.eval_public_polynomial(5i64).unwrap();
        let tx2 = polynomial.eval_public_polynomial(10i64).unwrap();
        let tx3 = polynomial.eval_public_polynomial(15i64).unwrap();
        let tx4 = polynomial2.eval_public_polynomial(5i64).unwrap();

        let response = polynomial.generate_response(&powers);
        let response2 = polynomial.generate_response(&powers2);
        let response3 = polynomial.generate_response(&powers3);
        let response4 = polynomial2.generate_response(&powers);

        assert!(response.verify(&tx));
        assert!(response2.verify(&tx2));
        assert!(response3.verify(&tx3));
        assert!(response4.verify(&tx4));
    }
}
