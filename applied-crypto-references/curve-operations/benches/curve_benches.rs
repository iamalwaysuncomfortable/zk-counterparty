#![feature(test)]

extern crate test;
use curve_operations::CurveTests;
use lazy_static::lazy_static;
use test::Bencher;

lazy_static! {
    static ref CURVE_TESTS: CurveTests = CurveTests::new(4000);
}

#[bench]
fn bench_ristretto_scalar_inversion(b: &mut Bencher) {
    b.iter(|| CURVE_TESTS.ristretto_scalar_inversion());
}

#[bench]
fn bench_bls_scalar_inversion(b: &mut Bencher) {
    b.iter(|| CURVE_TESTS.bls_scalar_inversion());
}

#[bench]
fn bench_small_ristretto_scalar_addition(b: &mut Bencher) {
    b.iter(|| CURVE_TESTS.small_ristretto_scalar_addition());
}

#[bench]
fn bench_large_ristretto_scalar_addition(b: &mut Bencher) {
    b.iter(|| CURVE_TESTS.large_ristretto_scalar_addition());
}

#[bench]
fn bench_small_bls_scalar_addition(b: &mut Bencher) {
    b.iter(|| CURVE_TESTS.small_bls_scalar_addition());
}

#[bench]
fn bench_large_bls_scalar_addition(b: &mut Bencher) {
    b.iter(|| CURVE_TESTS.large_bls_scalar_addition());
}

#[bench]
fn bench_small_ristretto_scalar_multiplication_with_generator(b: &mut Bencher) {
    b.iter(|| CURVE_TESTS.small_ristretto_scalar_multiplication_with_generator());
}

#[bench]
fn bench_large_ristretto_scalar_multiplication_with_generator(b: &mut Bencher) {
    b.iter(|| CURVE_TESTS.large_ristretto_scalar_multiplication_with_generator());
}

#[bench]
fn bench_small_bls_scalar_multiplication_with_prime_generator(b: &mut Bencher) {
    b.iter(|| CURVE_TESTS.small_bls_scalar_multiplication_with_prime_generator());
}

#[bench]
fn bench_large_bls_scalar_multiplication_with_prime_generator(b: &mut Bencher) {
    b.iter(|| CURVE_TESTS.large_bls_scalar_multiplication_with_prime_generator());
}

#[bench]
fn bench_small_ristretto_point_addition(b: &mut Bencher) {
    b.iter(|| CURVE_TESTS.small_ristretto_point_addition());
}

#[bench]
fn bench_large_ristretto_point_addition(b: &mut Bencher) {
    b.iter(|| CURVE_TESTS.large_ristretto_point_addition());
}

#[bench]
fn bench_small_bls_point_addition(b: &mut Bencher) {
    b.iter(|| CURVE_TESTS.small_bls_point_addition());
}

#[bench]
fn bench_large_bls_point_addition(b: &mut Bencher) {
    b.iter(|| CURVE_TESTS.large_bls_point_addition());
}
