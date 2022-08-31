use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_COMPRESSED,
    ristretto::CompressedRistretto,
    scalar::Scalar
};
use curve25519_dalek::ristretto::RistrettoPoint;
use merlin::Transcript;

// Domain separators for the proof
const PROOF_DOMAIN_SEP: &'static [u8] = b"SIMPLE_PROOF";
const PUBLIC_SCALAR_DOMAIN_SEP: &'static [u8] = b"PUBLIC_SCALAR";
const CHALLENGE_SCALAR_DOMAIN_SEP: &'static [u8] = b"CHALLENGE_SCALAR";

// Proof constants
const G: CompressedRistretto = RISTRETTO_BASEPOINT_COMPRESSED;

pub trait SimpleSchnorProofProtocol {
    fn proof_domain_separator(&mut self);
    fn append_public_scalar(&mut self, point: &CompressedRistretto);
    fn get_challenge_scalar(&mut self, point: &CompressedRistretto) -> Scalar;
}

impl SimpleSchnorProofProtocol for Transcript {
    fn proof_domain_separator(&mut self) {
        self.append_message(b"DOMAIN_SEP", PROOF_DOMAIN_SEP);
    }

    fn append_public_scalar(&mut self, point: &CompressedRistretto) {
        self.append_message(PUBLIC_SCALAR_DOMAIN_SEP, point.as_bytes());
    }

    fn get_challenge_scalar(&mut self, point: &CompressedRistretto) -> Scalar {
        let mut buf = [0; 64];
        self.challenge_bytes(CHALLENGE_SCALAR_DOMAIN_SEP, &mut buf);
        Scalar::from_bytes_mod_order_wide(&buf)
    }

}

pub fn prove_key_ownership(private_key: RistrettoPoint, proof_transcript: Transcript) {
    let k = private_key.compress();
}

pub fn verify_key_ownership(public_key: RistrettoPoint, proof_transcript: Transcript) {

}