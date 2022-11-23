mod merlin_non_interactive_proof;
mod tutorials;

pub use crate::{
    merlin_non_interactive_proof::{Error, SimpleProofProtocol, SimpleSchnorrProof},
    tutorials::{merlin_basics_tutorial, merlin_non_interactive_proof_tutorial},
};

pub(crate) use crate::merlin_non_interactive_proof::generate_keypair;
