//! Example of a non-interactive zero knowledge proof implementation using Merlin Transcripts.

use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT, ristretto::RistrettoPoint, scalar::Scalar,
};
use merlin::{Transcript, TranscriptRng};

/// This example uses a very simple Schnorr Signature scheme to prove knowledge of a private key.
/// The proof demonstrated would not be suitable for production use as it is susceptible to well
/// known attacks, but it demonstrates how to define a transcript protocol and subsequently use it
/// to carry out a non-interactive proof.

/// In the proof, there are 2 parties the "prover" who owns the private key `k` and the "verifier"
/// who verifies the "prover" owns the key. In the interactive case, the proof is as follows:
/// 1. A generator point `G` is defined in the group the proof takes place in. This is often either
/// an integer acting as a generator of a cyclic group or a point in an elliptic curve group. The
/// public key `K` is defined as `K = kG`.
/// 2. Prover chooses a random scalar `a` and computes `A = aG` and sends it to the verifier.
/// 3. Verifier defines a challenge scalar `c` and sends it to the prover
/// 4. Prover computes the response `r` as `r = a + c*k` and sends it to the verifier
/// 5. Verifier computes `R = rG` and `R' = A + c*K` and if `R = R'`, the proof is valid
///
/// Merlin Transcripts allow us to define a non-interactive version of this proof by allowing
/// both parties to compute a deterministic challenge scalar `c`. To do this a transcript protocol
/// that the verifier both agree on is defined including domain separators, an `append_proof_value()`
/// function that serializes proof values into bytes in a canonical way and a `get_challenge()`
/// which transforms the bytes into a scalar in a canonical way. After this is defined the proof
/// works as follows:
/// 1. Prover chooses a random scalar `a` and computes `A = aG` and absorbs `A` into a Merlin
/// transcript `T` using `T.append_proof_value(A)`
/// 2. Prover defines a scalar `c` using `T.get_challenge()` and computes the response `r`
/// as `r = a + c*k` and publishes the proof pair (`A`, `r`)
/// 3. Verifier gets the random scalar `c` defining a transcript `T'` and deriving `c` by falling
/// `T'.append_proof_value(A)` and `c = T'.get_challenge()`
/// 4. Verifier computes `R = rG` and `R' = A + c*K` and if `R = R'`, the proof is valid
///
/// The main difference with the latter version of this proof is that the prover can compute the
/// proof values `A` and `r` without any interaction with the verifier. Likewise any verifier who
/// uses the same transcript protocol can verify the verifier's published proof values without any
/// interaction with the prover.

// Below we define the transcript protocol for the Schnorr Signature proof system. In this
// particular proof system, we will use elliptic curve points as the proof values.

// TRANSCRIPT PROTOCOL DEFINITION
// Transcript protocols are defined in 2 steps:
// 1. Defining a list of domain separators for the proof that provers and verifiers agree on
// 2. Defining a set of functions that serialize proof values into bytes in a canonical way
//
// Below we define these steps in order

// PROOF CONSTANTS
const G: RistrettoPoint = RISTRETTO_BASEPOINT_POINT;

// DOMAIN SEPARATORS
// Domain separator for initializing a transcript
const PROOF_DOMAIN_SEP: &[u8] = b"SIMPLE_PROOF";

// Domain separator for sinking challenge values into the transcript
const PROOF_VALUE_DOMAIN_SEP: &[u8] = b"PROOF_VALUE";

// Domain separator for getting a challenge scalar from the transcript
const CHALLENGE_SCALAR_DOMAIN_SEP: &[u8] = b"CHALLENGE_SCALAR";

// Domain separator for keying a transcript based RNG for generating random scalars
const WITNESS_DOMAIN_SEP: &[u8] = b"WITNESS_BYTES";

// DEFINING ENCODINGS

// To help in defining a canonical encoding of proof values, we define a trait which defines several
// functions which encapsulate encoding our proof values into bytes in a canonical way.

/// An example of an interactive proof protocol implemented for Merlin Transcripts
pub trait SimpleSchnorProofProtocol {
    /// Add a domain separator to the transcript for the entire proof, meant to be called at the
    /// beginning of a proof
    fn proof_domain_separator(&mut self);

    /// Encode a Ristretto curve point used in the proof into bytes in a canonical way and append it
    /// to the transcript
    fn append_proof_value(&mut self, curve_point: &RistrettoPoint);

    /// Get a reproducible challenge scalar from the transcript
    fn get_challenge(&mut self) -> Scalar;

    /// Get an rng based on the Merlin Transcript using the public key as the witness bytes
    fn get_rng(&mut self, public_key: &RistrettoPoint) -> TranscriptRng;
}

impl SimpleSchnorProofProtocol for Transcript {
    fn proof_domain_separator(&mut self) {
        self.append_message(b"DOMAIN_SEP", PROOF_DOMAIN_SEP);
    }

    fn append_proof_value(&mut self, curve_point: &RistrettoPoint) {
        self.append_message(PROOF_VALUE_DOMAIN_SEP, curve_point.compress().as_bytes());
    }

    fn get_challenge(&mut self) -> Scalar {
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

/// Object implementing basic Schnorr Proof. This object holds the public proof values `A` and `r`
/// and provides public functions generate and verify the proof values.
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
    /// Create a non-interactive proof pair to prove ownership of a private key. This function takes
    /// a transcript, and the private_key as inputs and returns a proof object that can be sent to
    /// verifiers.
    pub fn generate_proof(private_key: &Scalar, proof_transcript: &mut Transcript) -> Self {
        // Generate the public key value
        let public_key = private_key * G;

        // Get a keyed rng to generate the random scalar `a` and public scalar `aG` and append
        // `aG` to the transcript
        let mut rng = proof_transcript.get_rng(&public_key);
        let random_scalar = Scalar::random(&mut rng);
        let public_scalar = random_scalar * G;
        proof_transcript.append_proof_value(&public_scalar);

        // Generate the challenge scalar using the merlin transcript which the prover can later
        // reproduce and define the reesponse
        let challenge_scalar = proof_transcript.get_challenge();
        let response = random_scalar + private_key * challenge_scalar;

        Self {
            response,
            public_scalar,
        }
    }

    /// Verify that the proof of ownership of the private key can be verified from a published
    /// public key.
    pub fn verify_proof(
        &mut self,
        public_key: &RistrettoPoint,
        proof_transcript: &mut Transcript,
    ) -> Result<RistrettoPoint, Error> {
        // As the verifier, append the public scalar `aG` to the transcript
        proof_transcript.append_proof_value(&self.public_scalar);

        // Get the same challenge scalar that prover used to generate the proof
        let challenge_scalar: Scalar = proof_transcript.get_challenge();

        // Use the proof values the prover published to verify the proof
        let response_point = self.response * G;
        let verification_point = self.public_scalar + challenge_scalar * public_key;

        // If the points match, it's been proven the prover knows the private key
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

/// Create a proof object from published prover values
impl From<(Scalar, RistrettoPoint)> for SimpleSchnorrProof {
    fn from(proof_pair: (Scalar, RistrettoPoint)) -> Self {
        Self {
            response: proof_pair.0,
            public_scalar: proof_pair.1,
        }
    }
}
