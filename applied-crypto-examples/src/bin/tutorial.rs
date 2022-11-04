//! Demonstrating the usage of Merlin STROBE based transcripts for creating non-interative
//! public coin arguments and consistent hashing schemes.

use applied_crypto_examples::{ConfigArgs, Tutorials};
use clap::Parser;
use merlin_example::{merlin_basics_tutorial, merlin_non_interactive_proof_tutorial};

fn main() {
    let config = ConfigArgs::parse();
    match config.tutorial {
        Tutorials::Merlin => merlin_basics_tutorial(),
        Tutorials::MerlinNonInteractiveProof => {
            merlin_non_interactive_proof_tutorial();
        }
    }
}
