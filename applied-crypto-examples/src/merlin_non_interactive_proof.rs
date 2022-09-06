use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT, ristretto::RistrettoPoint, scalar::Scalar,
};
use merlin::{Transcript, TranscriptRng};

// Domain separators for the proof
const PROOF_DOMAIN_SEP: &[u8] = b"SIMPLE_PROOF";
const WITNESS_DOMAIN_SEP: &[u8] = b"WITNESS_BYTES";
const CHALLENGE_SCALAR_DOMAIN_SEP: &[u8] = b"CHALLENGE_SCALAR";

// Proof constants
const G: RistrettoPoint = RISTRETTO_BASEPOINT_POINT;

/// Object implementing basic Schnorr Proof.
#[derive(Clone, Copy, Debug)]
pub struct SimpleSchnorrProof {
    response: Scalar,
    public_scalar: RistrettoPoint,
}

/// Proof errors
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// Proof doesn't match
    ProofMismatch(String, String),
}

impl SimpleSchnorrProof {
    /// Create a non-interactive proof pair to prove ownership of a private key
    pub fn generate_proof(private_key: &Scalar, proof_transcript: &mut Transcript) -> Self {
        let public_key = private_key * G;
        let mut rng = proof_transcript.get_rng(&public_key);
        let random_scalar = Scalar::random(&mut rng);
        let public_scalar = random_scalar * G;
        proof_transcript.append_ristretto_point(&public_scalar);
        let challenge_scalar = proof_transcript.get_challenge_scalar();
        let response = random_scalar + private_key * challenge_scalar;

        Self {
            response,
            public_scalar,
        }
    }

    /// Verify that proof matches
    pub fn verify_proof(
        &mut self,
        public_key: &RistrettoPoint,
        proof_transcript: &mut Transcript,
    ) -> Result<RistrettoPoint, Error> {
        proof_transcript.append_ristretto_point(&self.public_scalar);
        let challenge_scalar: Scalar = proof_transcript.get_challenge_scalar();
        let response_point = self.response * G;
        let verification_point = self.public_scalar + challenge_scalar * public_key;
        if response_point.eq(&verification_point) {
            return Ok(response_point);
        }
        Err(Error::ProofMismatch(
            hex::encode(response_point.compress().as_bytes()),
            hex::encode(response_point.compress().as_bytes()),
        ))
    }

    /// Get proof pair data
    pub fn get_proof_pair(&self) -> (Scalar, RistrettoPoint) {
        (self.response, self.public_scalar)
    }
}

/// An example of an interactive proof protocol implemented for Merlin Transcripts
pub trait SimpleSchnorProofProtocol {
    fn proof_domain_separator(&mut self);
    fn append_ristretto_point(&mut self, curve_point: &RistrettoPoint);
    fn get_challenge_scalar(&mut self) -> Scalar;
    fn get_rng(&mut self, public_key: &RistrettoPoint) -> TranscriptRng;
}

impl SimpleSchnorProofProtocol for Transcript {
    fn proof_domain_separator(&mut self) {
        self.append_message(b"DOMAIN_SEP", PROOF_DOMAIN_SEP);
    }

    fn append_ristretto_point(&mut self, curve_point: &RistrettoPoint) {
        self.append_message(PROOF_DOMAIN_SEP, curve_point.compress().as_bytes());
    }

    fn get_challenge_scalar(&mut self) -> Scalar {
        let mut buf = [0; 64];
        self.challenge_bytes(CHALLENGE_SCALAR_DOMAIN_SEP, &mut buf);
        Scalar::from_bytes_mod_order_wide(&buf)
    }

    fn get_rng(&mut self, public_key: &RistrettoPoint) -> TranscriptRng {
        self.build_rng()
            .rekey_with_witness_bytes(WITNESS_DOMAIN_SEP, public_key.compress().as_bytes())
            .finalize(&mut rand::rngs::OsRng)
    }
}
