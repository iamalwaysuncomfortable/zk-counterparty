///! This module explores Aleo's basic algebraic structures and their properties

#[cfg(test)]
mod tests {
    //Field and Ring elements
    use snarkvm::utilities::{
        BigInteger384, BigInteger
    };

    #[test]
    fn additions_overflow() {
        let mut a = BigInteger384::new([u64::MAX, u64::MAX, u64::MAX, u64::MAX, u64::MAX, u64::MAX]);
        let b = BigInteger384::from(7);
        let add_overflowed = a.add_nocarry(&b);
        let d = BigInteger384::from(6);
        assert_eq!(a, d);
        assert!(add_overflowed);

    }

    #[test]
    fn subs_overflow() {
        let mut a = BigInteger384::from(0);
        let b = BigInteger384::from(1);
        let sub_overflowed = a.sub_noborrow(&b);
        let d = BigInteger384::new([u64::MAX, u64::MAX, u64::MAX, u64::MAX, u64::MAX, u64::MAX]);
        assert_eq!(a, d);
        assert!(sub_overflowed);
    }

    #[test]
    fn mul_test() {
        let mut a = BigInteger384::from(2000000);
        a.muln(1);
        let mut b = BigInteger384::from(2000000);
        b.muln(2);
        let mut c = BigInteger384::from(2000000);
        c.muln(4);
        assert_eq!(a, BigInteger384::from(4000000));
        assert_eq!(b, BigInteger384::from(8000000));
        assert_eq!(c, BigInteger384::from(32000000));

        let mut c = BigInteger384::from(2000000);
        c.mul2();
        assert_eq!(c, BigInteger384::from(4000000));

    }

    #[test]
    fn mul_saturation() {
        // Create a number that is within 1 multiplication of overflowing
        let mut a = BigInteger384::new([u64::MAX, u64::MAX, u64::MAX, u64::MAX, u64::MAX, u64::MAX - 4]);
        let u384_max = BigInteger384::new([u64::MAX, u64::MAX, u64::MAX, u64::MAX, u64::MAX, u64::MAX]);
        a.mul2();
        println!("a: {}", a);
        println!("u384_max: {}", u384_max);
    }
}