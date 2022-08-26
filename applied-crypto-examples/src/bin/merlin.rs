//! Demonstrating the usage of Merlin STROBE based transcripts for creating non-interative
//! public coin arguments and consistent hashing schemes.

use merlin::Transcript;

fn main() {
    // Merlin transcripts are based on the STROBE protocol and use a concept called "Sponge Constructions"
    // in order to build non-interactive proofs in a way that is dependent on prior state. We will show
    // how these proofs are constructed as well as demonstrate the use of consistent hashing to construct
    // other interesting applications.
    let mut transcript = Transcript::new(b"test");
    let mut transcript2 = Transcript::new(b"test");
}
