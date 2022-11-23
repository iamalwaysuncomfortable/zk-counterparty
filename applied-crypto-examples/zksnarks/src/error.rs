//! Errors in zksnarks

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error {
    /// Proposed roots would result in a polynomial with coefficients in the rational field
    OutsideIntegerField(i64, i64),
    /// Either no public roots were set, or all roots were set to public
    InvalidPublicRoots(usize),
    /// No public roots set
    NoPublicRoots,
}
