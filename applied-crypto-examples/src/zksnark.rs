//! An example of naive implementations of zksnarks for tutorial purposes

/// Single root of a polynomial
#[derive(Clone, Debug, Ord, PartialOrd, Eq, PartialEq)]
pub struct Root {
    // a in ax+b
    a: i64,
    // b in ax+b
    b: i64,
}

/// Unencrypted challenge response pair
#[derive(Clone, Debug, Ord, PartialOrd, Eq, PartialEq)]
pub struct UnencryptedChallengeResponse {
    // p(x) = h(x)*t(x)
    px: i64,
    // h(x)
    hx: i64,
}

impl UnencryptedChallengeResponse {
    pub fn new(px: i64, hx: i64) -> Self {
        Self { px, hx }
    }

    pub fn verify(&self, x: i64, polynomial: &Polynomial) -> bool {
        self.px == self.hx * polynomial.eval(x)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error {
    /// Proposed roots would result in a polynomial with coefficients in the rational field
    OutsideIntegerField(i64, i64),
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

/// Polynomial with coefficients restricted to integers within the field of 8-bit signed integers
#[derive(Clone, Debug)]
pub struct Polynomial {
    // Polynomial roots (a, b) such that a*x + b is a factor of the polynomial
    roots: Vec<Root>,
    // public roots
    public_roots: Vec<Root>,
}

impl Polynomial {
    /// Create a new polynomial from a list of roots
    pub fn new(roots: Vec<Root>) -> Self {
        Self {
            roots,
            public_roots: Vec::new(),
        }
    }

    pub fn set_public_roots(mut self, num_public: usize) -> Self {
        self.public_roots = self.roots[0..num_public].to_vec();
        self
    }

    /// Get degree of polynomial
    pub fn degree(&self) -> usize {
        self.roots.len()
    }

    /// Create public polynomial from private polynomial
    pub fn get_public_polynomial(&self) -> Polynomial {
        Polynomial::new(self.public_roots.clone())
    }

    /// Evaluate polynomial at a given point
    pub fn eval(&self, x: i64) -> i64 {
        self.roots.iter().fold(1, |acc, root| acc * root.eval(x))
    }

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
    fn test_polynomial_roots_must_divide() {
        assert_eq!(Root::new(2, 1), Err(Error::OutsideIntegerField(2, 1)));
    }

    #[test]
    fn test_polynomial_evaluates_correctly() {
        let roots = vec![
            Root::new(1, 2).unwrap(),
            Root::new(3, 6).unwrap(),
            Root::new(2, 4).unwrap(),
        ];
        let polynomial = Polynomial::new(roots);
        assert_eq!(polynomial.eval(0), 48);
        assert_eq!(polynomial.eval(1), 162);
        assert_eq!(polynomial.eval(2), 384);
        assert_eq!(polynomial.eval(3), 750);
    }

    #[test]
    fn test_polynomial_naive_challenge_response() {
        let roots = vec![
            Root::new(1, 2).unwrap(),
            Root::new(3, 6).unwrap(),
            Root::new(2, 4).unwrap(),
        ];
        let polynomial = Polynomial::new(roots).set_public_roots(2);
        let challenge_polynomial = polynomial.get_public_polynomial();

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
