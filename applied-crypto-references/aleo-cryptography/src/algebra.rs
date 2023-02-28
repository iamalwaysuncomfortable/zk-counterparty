///! This module explores Aleo's basic algebraic structures and their properties

//Field and Ring elements
use snarkvm::utilities::{
    BigInteger384, BigInteger
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn additions_overflow() {
        let mut a = BigInteger384::new([u64::MAX, u64::MAX, u64::MAX, u64::MAX, u64::MAX, u64::MAX]);
        let mut b = BigInteger384::from(7);
        a.add_nocarry(&b);
        let d = BigInteger384::from(6);
        assert_eq!(a, d);
    }

    #[test]
    fn subs_overflow() {
        let mut a = BigInteger384::from(0);
        let mut b = BigInteger384::from(1);
        a.sub_noborrow(&b);
        let d = BigInteger384::new([u64::MAX, u64::MAX, u64::MAX, u64::MAX, u64::MAX, u64::MAX]);
        assert_eq!(a, d);
    }
}