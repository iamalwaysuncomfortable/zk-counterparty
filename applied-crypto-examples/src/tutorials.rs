use crate::{generate_keypair, SimpleSchnorrProof};
use merlin::Transcript;

pub fn merlin_basics_tutorial() {
    // Merlin transcripts are used to create created fixed length, deterministic outputs based on
    // a set of prior inputs (possibly of varying lengths). Their main purpose is to build non-
    // interactive proofs in a way that both the prover and verifier can independently compute.
    // They also include built-in functionality for creating random number generators (rng) which
    // create an rng whose output is bound to the current transcript.
    //
    // They can further be used to develop other useful cryptographic tools like hashing schemes
    // which can produce deterministic outputs for a wide class of objects.
    //
    // This example will demonstrate the basics of Merlin transcripts and their application to
    // the aforementioned cryptographic tools.

    // Let's start by creating two transcripts.
    let mut transcript_one = Transcript::new(b"test");
    let mut transcript_two = Transcript::new(b"test");

    // Merlin Transcripts under the hood are based on "Sponge Functions" (also called "Sponge
    // Constructions"). Sponge functions take in variable length input in fixed length blocks in
    // a series of "absorption" phases and then output fixed length blocks of bits in a "squeezing"
    // phase until the desired number of bits are output. This is an oversimplification of the
    // underlying implementation of Merlin Transcripts, but it helps illustrate why the Merlin API
    // is structured like it is.

    // Transcripts have two functions which fall under the "absorption" category. The first function
    // is called "append_message" which takes a domain separator to indicate the purpose of the
    // message, and a canonical byte representation of an object. The second is "append_u64" which
    // takes a rust u64 and a domain separator. Both of these function absorb data into the transcript
    // which will lead to unique outputs during the output or "squeeze" phase.

    let number_32: u32 = 12345678;
    transcript_one.append_message(b"byte-string-messages", b"here's a note");
    transcript_one.append_message(b"byte-string-messages", b"here's another note");
    transcript_one.append_message(b"number-messages", &number_32.to_le_bytes());

    transcript_two.append_message(b"byte-string-messages", b"here's a note");
    transcript_two.append_message(b"byte-string-messages", b"here's another note");
    transcript_two.append_message(b"number-messages", &number_32.to_le_bytes());

    transcript_one.append_u64(b"number-messages", 800000u64);
    transcript_two.append_u64(b"number-messages", 800000u64);

    // The "squeeze" portion of the Merlin API will output bytes that are based on all inputs
    // created above. Given that two transcripts were given the inputs, the output will be
    // identical.

    let mut buf = [0; 8];
    let mut buf_2 = [0; 8];
    transcript_one.challenge_bytes(b"extraction", &mut buf);
    transcript_two.challenge_bytes(b"extraction", &mut buf_2);

    // This "squeeze" action can be continued to generate further deterministic byte sequence
    // outputs. Anyone who runs this code file will get exactly the same output.
    let mut buf_3 = [0; 16];
    let mut buf_4 = [0; 16];
    transcript_one.challenge_bytes(b"extraction", &mut buf_3);
    transcript_two.challenge_bytes(b"extraction", &mut buf_4);

    // However, if we give the merlin transcripts different outputs to absorb, the outputs
    // of the two transcriptions will diverge.
    let mut buf_5 = [0; 8];
    let mut buf_6 = [0; 8];
    transcript_one.append_message(b"byte-string-messages", b"a note");
    transcript_two.append_message(b"byte-string-messages", b"a different note");
    transcript_one.challenge_bytes(b"extraction", &mut buf_5);
    transcript_two.challenge_bytes(b"extraction", &mut buf_6);

    // Executable part of the tutorial
    println!();
    println!("This tutorial demonstrates the basic usage of merlin transcripts.");
    println!("We create two Merlin Transcripts 'absorb' the following data into both transcripts");
    println!("using the 'append_message' and 'append_u64' methods");
    println!();
    println!("Data Ingested:");
    println!("Domain Separator: 'byte-string-messages' - Message: 'here's a note'",);
    println!("Domain Separator: 'byte-string-messages' - Message: 'here's another note'",);
    println!("Domain Separator 'number-messages' - Message {}", 12345678);
    println!("Domain Separator 'number-messages' - Message {}", 800000);
    println!();
    println!("We now 'squeeze' out bytes of each transcript using the 'challenge_bytes' method which allows us");
    println!("to do useful things with them like creating random numerical challenge numbers as shown below");
    println!("which are tied to the history of the transcript");
    println!(
        "8-byte output from transcript 1: {:?} - encoded as u64: {}",
        hex::encode(&buf),
        u64::from_le_bytes(buf)
    );
    println!(
        "8-byte output from transcript 2: {:?} - encoded as u64: {}",
        hex::encode(&buf_2),
        u64::from_le_bytes(buf_2)
    );
    println!();
    println!("We see that both transcripts output equal 8 byte sequences and corresponding u64s");
    println!();
    println!("If desired, we can continue to extract equal outputs from each transcript like so:");
    println!(
        "16-byte output from transcript 1: {:?}, - encoded as u128: {}",
        hex::encode(&buf_3),
        u128::from_le_bytes(buf_3)
    );
    println!(
        "16-byte output from transcript 1: {:?}, - encoded as u128: {}",
        hex::encode(&buf_4),
        u128::from_le_bytes(buf_3)
    );
    println!();
    println!("If we add any further input that is NOT the same, the outputs will be different as we demonstrate below.");
    println!();
    println!("Data Ingested:");
    println!("Transcript 1 - Domain Separator: 'byte-string-messages' - Message: 'a note'");
    println!("Transcript 2 - Domain Separator: 'a note' - Message: 'a different note'",);
    println!();
    println!("Output:");
    println!(
        "8-byte output from transcript 1: {:?} - encoded as u64: {}",
        hex::encode(&buf_5),
        u64::from_le_bytes(buf_5)
    );
    println!(
        "8-byte output from transcript 2: {:?} - encoded as u64: {}",
        hex::encode(&buf_6),
        u64::from_le_bytes(buf_6)
    );
    println!();
    println!("The deterministic property of Merlin Transcripts allows us to create 'transcript protocols'");
    println!("in which we design a canonical byte encodings and domain separators for proof objects such that");
    println!("provers and verifiers can do zero knowledge proofs in non-interactive ways.");
    println!();
    println!("Alternatively, by defining the same domain labels and byte encodings for objects we're concerned about");
    println!("we can define a consistent hashing scheme for all objects we find interesting.");
}

pub fn merlin_non_interactive_proof_tutorial() {
    // This tutorial demonstrates the use of Merlin transcripts to create a non-interactive
    // proof of knowledge of a private key.

    // We create a Merlin Transcript to use as a sponge for our proof.
    let mut transcript = SimpleSchnorrProof::create_new_transcript();
    let (private_key, public_key) = generate_keypair();
    let proof = SimpleSchnorrProof::generate_proof(&private_key, &mut transcript);
    let proof_pair = proof.get_proof_pair();

    let mut verifier_transcript = SimpleSchnorrProof::create_new_transcript();
    let mut verifier_proof = SimpleSchnorrProof::from(proof_pair);
    let result = verifier_proof.verify_proof(&public_key, &mut verifier_transcript);

    if result.is_ok() {
        println!("Proof verified!");
    } else {
        println!("Proof failed to verify!");
    }
}