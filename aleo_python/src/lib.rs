use pyo3::prelude::*;

pub mod hash;
pub use hash::*;

/// A Python module implemented in Rust.
#[pymodule]
fn aleo_python(_py: Python<'_>, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(hash_int, m)?)?;

    Ok(())
}
