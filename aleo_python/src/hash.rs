use super::*;
use snarkvm::console::algorithms::Poseidon2;
use snarkvm::prelude::{Hash, Testnet3, Field};
use ToString;

// Takes a poseiden hash of an integer and returns the hash as a string
#[pyfunction]
pub fn hash_int(a: u64) -> PyResult<String> {
    let field = Field::from_u64(a);
    let hasher = Poseidon2::setup("Poseidon2").unwrap();
    let hash: Field<Testnet3> = hasher.hash(&[field]).unwrap();
    Ok(hash.to_string())
}
