//! Collection of atomic curve operations for use in benchmarking

use bls12_381::{G1Projective, Scalar as BLS_Scalar};
use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT as G, ristretto::RistrettoPoint,
    scalar::Scalar as Ristretto_Scalar,
};
use lazy_static::lazy_static;

lazy_static! {
    static ref G_BLS: G1Projective = G1Projective::generator();
}

/// Curve test objects containing pre-computed scalars and curve points
/// within the Ristretto and BLS12-381 libraries
pub struct CurveTests {
    ristretto_scalar: Ristretto_Scalar,
    inverse_ristretto_scalar: Ristretto_Scalar,
    bls_scalar: BLS_Scalar,
    inverse_bls_scalar: BLS_Scalar,
    ristretto_point: RistrettoPoint,
    bls_point: G1Projective,
    inverse_ristretto_point: RistrettoPoint,
    inverse_bls_point: G1Projective,
}

impl CurveTests {
    /// Create a new curve object with pre-computed scalars and curve points from a u64 number
    pub fn new(p1: u64) -> CurveTests {
        let base_ristretto = Ristretto_Scalar::from(p1);
        let inverse_ristretto = base_ristretto.invert();
        let base_bls = BLS_Scalar::from(p1);
        let inverse_bls = base_bls.invert().unwrap();
        let ristretto_point = G * base_ristretto;
        let bls_point = *G_BLS * base_bls;
        let inverse_ristretto_point = G * inverse_ristretto;
        let inverse_bls_point = *G_BLS * inverse_bls;
        CurveTests {
            ristretto_scalar: base_ristretto,
            inverse_ristretto_scalar: inverse_ristretto,
            bls_scalar: base_bls,
            inverse_bls_scalar: inverse_bls,
            ristretto_point,
            bls_point,
            inverse_ristretto_point,
            inverse_bls_point,
        }
    }

    /// Find the inverse of a Ristretto scalar
    pub fn ristretto_scalar_inversion(&self) -> Ristretto_Scalar {
        self.ristretto_scalar.invert()
    }

    /// Find the inverse of a BLS scalar
    pub fn bls_scalar_inversion(&self) -> BLS_Scalar {
        self.bls_scalar.invert().unwrap()
    }

    /// Add two small Ristretto scalars
    pub fn small_ristretto_scalar_addition(&self) -> Ristretto_Scalar {
        self.ristretto_scalar + self.ristretto_scalar
    }

    /// Add two large Ristretto scalars
    pub fn large_ristretto_scalar_addition(&self) -> Ristretto_Scalar {
        self.inverse_ristretto_scalar + self.inverse_ristretto_scalar
    }

    /// Add two small BLS scalars
    pub fn small_bls_scalar_addition(&self) -> BLS_Scalar {
        self.bls_scalar + self.bls_scalar
    }

    /// Add two large BLS scalars
    pub fn large_bls_scalar_addition(&self) -> BLS_Scalar {
        self.inverse_bls_scalar + self.inverse_bls_scalar
    }

    /// Multiply small Ristretto scalar by Ristretto Generator point
    pub fn small_ristretto_scalar_multiplication_with_generator(&self) -> RistrettoPoint {
        G * self.ristretto_scalar
    }

    /// Multiply large Ristretto scalar by Ristretto Generator point
    pub fn large_ristretto_scalar_multiplication_with_generator(&self) -> RistrettoPoint {
        G * self.inverse_ristretto_scalar
    }

    /// Multiply small BLS scalar by BLS prime field Generator point
    pub fn small_bls_scalar_multiplication_with_prime_generator(&self) -> G1Projective {
        G1Projective::generator() * self.bls_scalar
    }

    /// Multiply large BLS scalar by BLS prime field Generator point
    pub fn large_bls_scalar_multiplication_with_prime_generator(&self) -> G1Projective {
        G1Projective::generator() * self.inverse_bls_scalar
    }

    /// Add two Ristretto points found by multiplying small Ristretto scalars by the Generator
    pub fn small_ristretto_point_addition(&self) -> RistrettoPoint {
        self.ristretto_point + self.ristretto_point
    }

    /// Add two Ristretto points found by multiplying large Ristretto scalars by the Generator
    pub fn large_ristretto_point_addition(&self) -> RistrettoPoint {
        self.inverse_ristretto_point + self.inverse_ristretto_point
    }

    /// Add two BLS points found by multiplying small BLS scalars by the prime field Generator
    pub fn small_bls_point_addition(&self) -> G1Projective {
        self.bls_point + self.bls_point
    }

    /// Add two BLS points found by multiplying large BLS scalars by the prime field Generator
    pub fn large_bls_point_addition(&self) -> G1Projective {
        self.inverse_bls_point + self.inverse_bls_point
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_atomic_curve_operations_give_expected_outputs() {
        let base = 4000u64;
        let double = 8000u64;
        let curve_tests = CurveTests::new(base);
        assert_eq!(
            curve_tests.ristretto_scalar_inversion(),
            curve_tests.inverse_ristretto_scalar
        );
        assert_eq!(
            curve_tests.bls_scalar_inversion(),
            curve_tests.inverse_bls_scalar
        );
        assert_eq!(
            curve_tests.large_ristretto_scalar_addition(),
            Ristretto_Scalar::from(base).invert() + Ristretto_Scalar::from(base).invert()
        );
        assert_eq!(
            curve_tests.small_ristretto_scalar_addition(),
            Ristretto_Scalar::from(double)
        );
        assert_eq!(
            curve_tests.large_bls_scalar_addition(),
            BLS_Scalar::from(base).invert().unwrap() + BLS_Scalar::from(base).invert().unwrap()
        );
        assert_eq!(
            curve_tests.small_bls_scalar_addition(),
            BLS_Scalar::from(double)
        );
        assert_eq!(
            curve_tests.large_ristretto_scalar_multiplication_with_generator(),
            Ristretto_Scalar::from(base).invert() * G
        );
        assert_eq!(
            curve_tests.small_ristretto_scalar_multiplication_with_generator(),
            G * Ristretto_Scalar::from(base)
        );
        assert_eq!(
            curve_tests.small_bls_scalar_multiplication_with_prime_generator(),
            *G_BLS * BLS_Scalar::from(base)
        );
        assert_eq!(
            curve_tests.large_bls_scalar_multiplication_with_prime_generator(),
            *G_BLS * BLS_Scalar::from(base).invert().unwrap()
        );
        assert_eq!(
            curve_tests.small_ristretto_point_addition(),
            G * Ristretto_Scalar::from(base) + G * Ristretto_Scalar::from(base)
        );
        assert_eq!(
            curve_tests.small_bls_point_addition(),
            *G_BLS * BLS_Scalar::from(base) + *G_BLS * BLS_Scalar::from(base)
        );
        assert_eq!(
            curve_tests.large_ristretto_point_addition(),
            G * Ristretto_Scalar::from(base).invert() + G * Ristretto_Scalar::from(base).invert()
        );
        assert_eq!(
            curve_tests.large_bls_point_addition(),
            *G_BLS * BLS_Scalar::from(base).invert().unwrap()
                + *G_BLS * BLS_Scalar::from(base).invert().unwrap()
        );
    }
}
