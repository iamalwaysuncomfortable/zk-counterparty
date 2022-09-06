mod config;
mod merlin_basics;
mod merlin_non_interactive_proof;

pub use crate::{
    config::{ConfigArgs, Tutorials},
    merlin_basics::merlin_basics_tutorial,
    merlin_non_interactive_proof::{Error, SimpleSchnorrProof},
};
