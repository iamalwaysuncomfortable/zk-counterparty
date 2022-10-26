mod config;
mod merlin_non_interactive_proof;
mod tutorials;

pub mod zksnark;
pub mod encrypted_zksnark;

pub use crate::{
    config::{ConfigArgs, Tutorials},
    merlin_non_interactive_proof::{Error, SimpleProofProtocol, SimpleSchnorrProof},
    tutorials::{merlin_basics_tutorial, merlin_non_interactive_proof_tutorial},
};

pub(crate) use crate::merlin_non_interactive_proof::generate_keypair;
